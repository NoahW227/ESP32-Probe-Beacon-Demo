//! Passive 802.11 management-frame sniffer for ESP32-S3.
//!
//! Listens in promiscuous mode, hops 2.4 GHz channels, parses beacons and
//! probe requests/responses, and emits one JSON object per line on stdout.
//!
//! Design notes that matter:
//!
//! * We come up in STA mode but never call `connect()`. Being *associated*
//!   would pin the radio to the AP's channel and kill channel hopping, which
//!   is also why the host link is USB serial rather than WiFi.
//! * The promiscuous RX callback runs on the WiFi driver task. It must not
//!   block or allocate, so it parses each frame into a fixed-size POD record
//!   and drops it into a FreeRTOS queue. All formatting, aggregation and I/O
//!   happens on the main task.
//! * Beacons are aggregated on-device (one update per BSSID per second)
//!   because every AP beacons ~10x/second and forwarding all of that would
//!   swamp the serial link with redundant rows.

use core::ffi::c_void;
use core::mem::size_of;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::collections::HashMap;
use std::io::Write;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::*;
use esp_idf_svc::wifi::{ClientConfiguration, Configuration, WifiDriver};

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Depth of the callback -> main-task handoff queue.
const QUEUE_DEPTH: u32 = 384;

/// How often aggregated beacon rows are flushed to the host.
const BEACON_FLUSH_MS: u64 = 1000;

/// Forget an AP we haven't heard from in this long.
const AP_STALE_MS: u64 = 300_000;

/// Safety valve: max *wildcard* probe requests emitted per second. Named
/// probes (the ones carrying a real SSID) always bypass this - they are the
/// rare, interesting ones and must never be dropped.
const WILDCARD_PROBE_BUDGET: u32 = 150;

/// How long the main loop blocks waiting on the frame queue.
///
/// `portTICK_PERIOD_MS` is a C macro, so bindgen never emits it; derive the
/// tick count from the real `configTICK_RATE_HZ` binding instead so this stays
/// correct if the tick rate in sdkconfig.defaults ever changes.
const QUEUE_WAIT_TICKS: u32 = 50 * configTICK_RATE_HZ / 1000;

/// Channel dwell schedule. 1/6/11 are the non-overlapping channels where most
/// APs actually live, so they get a longer dwell; the rest get a quick look so
/// we still catch probe requests sprayed across the band.
/// Full sweep = 3*400 + 10*150 = 2700 ms.
const HOP_PLAN: [(u8, u64); 13] = [
    (1, 400),
    (2, 150),
    (3, 150),
    (4, 150),
    (5, 150),
    (6, 400),
    (7, 150),
    (8, 150),
    (9, 150),
    (10, 150),
    (11, 400),
    (12, 150),
    (13, 150),
];

// ---------------------------------------------------------------------------
// 802.11 layout constants
// ---------------------------------------------------------------------------

const MGMT_HDR_LEN: usize = 24;
/// Timestamp(8) + beacon interval(2) + capability(2) after the header.
const FIXED_PARAMS_LEN: usize = 12;
const FCS_LEN: usize = 4;

const SUBTYPE_PROBE_REQ: u8 = 4;
const SUBTYPE_PROBE_RESP: u8 = 5;
const SUBTYPE_BEACON: u8 = 8;

const TAG_SSID: u8 = 0;
const TAG_DS_PARAMS: u8 = 3;
const TAG_RSN: u8 = 48;
const TAG_VENDOR: u8 = 221;

const CAP_PRIVACY: u16 = 0x0010;

// Record kinds, mirrored on the host.
const KIND_BEACON: u8 = 0;
const KIND_PROBE_REQ: u8 = 1;
const KIND_PROBE_RESP: u8 = 2;

// Security classes.
const SEC_OPEN: u8 = 0;
const SEC_WEP: u8 = 1;
const SEC_WPA: u8 = 2;
const SEC_WPA2: u8 = 3;
const SEC_WPA3: u8 = 4;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

static QUEUE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
/// Frames the callback accepted.
static FRAMES: AtomicU32 = AtomicU32::new(0);
/// Frames the callback had to throw away because the queue was full. Non-zero
/// here means the main task isn't draining fast enough.
static DROPS: AtomicU32 = AtomicU32::new(0);

/// Fixed-size, `Copy` record passed through the FreeRTOS queue. No pointers,
/// no heap - it is memcpy'd by value into and out of the queue.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawRec {
    kind: u8,
    rssi: i8,
    channel: u8,
    sec: u8,
    ssid_len: u8,
    /// addr2 - the transmitter. For a probe request this is the client.
    src: [u8; 6],
    /// addr3 - the BSSID.
    bssid: [u8; 6],
    ssid: [u8; 32],
}

impl RawRec {
    const fn zeroed() -> Self {
        Self {
            kind: 0,
            rssi: 0,
            channel: 0,
            sec: 0,
            ssid_len: 0,
            src: [0; 6],
            bssid: [0; 6],
            ssid: [0; 32],
        }
    }

    fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len as usize]
    }
}

// ---------------------------------------------------------------------------
// Promiscuous RX callback  (runs on the WiFi task - keep it cheap)
// ---------------------------------------------------------------------------

unsafe extern "C" fn rx_cb(buf: *mut c_void, pkt_type: wifi_promiscuous_pkt_type_t) {
    if pkt_type != wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT || buf.is_null() {
        return;
    }

    let pkt = &*(buf as *const wifi_promiscuous_pkt_t);

    // sig_len includes the 4-byte FCS, which is not part of the MPDU we parse.
    let sig_len = pkt.rx_ctrl.sig_len() as usize;
    if sig_len < MGMT_HDR_LEN + FCS_LEN {
        return;
    }
    let len = sig_len - FCS_LEN;
    let body = core::slice::from_raw_parts(pkt.payload.as_ptr(), len);

    let fc0 = body[0];
    // Type 0 == management. Anything else shouldn't reach us given the filter.
    if (fc0 >> 2) & 0x03 != 0 {
        return;
    }
    let subtype = (fc0 >> 4) & 0x0F;

    let (kind, tag_start) = match subtype {
        SUBTYPE_BEACON => (KIND_BEACON, MGMT_HDR_LEN + FIXED_PARAMS_LEN),
        SUBTYPE_PROBE_RESP => (KIND_PROBE_RESP, MGMT_HDR_LEN + FIXED_PARAMS_LEN),
        // A probe request has no fixed parameters; tags start right after the
        // header.
        SUBTYPE_PROBE_REQ => (KIND_PROBE_REQ, MGMT_HDR_LEN),
        _ => return,
    };
    if len < tag_start {
        return;
    }

    let mut rec = RawRec::zeroed();
    rec.kind = kind;
    rec.rssi = pkt.rx_ctrl.rssi() as i8;
    rec.channel = pkt.rx_ctrl.channel() as u8;
    rec.src.copy_from_slice(&body[10..16]);
    rec.bssid.copy_from_slice(&body[16..22]);

    // Capability bits only exist on beacons and probe responses.
    let privacy = if kind == KIND_PROBE_REQ {
        false
    } else {
        let cap = u16::from_le_bytes([body[34], body[35]]);
        cap & CAP_PRIVACY != 0
    };

    let mut has_rsn = false;
    let mut has_sae = false;
    let mut has_wpa = false;

    // Walk the tagged parameters.
    let mut i = tag_start;
    while i + 2 <= len {
        let id = body[i];
        let tlen = body[i + 1] as usize;
        let start = i + 2;
        let end = start + tlen;
        if end > len {
            break; // truncated / malformed - stop rather than read past the end
        }
        let data = &body[start..end];

        match id {
            TAG_SSID => {
                let n = tlen.min(32);
                rec.ssid[..n].copy_from_slice(&data[..n]);
                rec.ssid_len = n as u8;
            }
            TAG_DS_PARAMS => {
                // The AP's declared channel is more trustworthy than the
                // channel we happened to receive on (adjacent-channel bleed).
                if tlen >= 1 && data[0] >= 1 && data[0] <= 14 {
                    rec.channel = data[0];
                }
            }
            TAG_RSN => {
                has_rsn = true;
                if rsn_has_sae(data) {
                    has_sae = true;
                }
            }
            TAG_VENDOR => {
                // Old-style WPA1 IE: OUI 00:50:F2, type 1.
                if tlen >= 4 && data[..4] == [0x00, 0x50, 0xf2, 0x01] {
                    has_wpa = true;
                }
            }
            _ => {}
        }
        i = end;
    }

    rec.sec = if has_sae {
        SEC_WPA3
    } else if has_rsn {
        SEC_WPA2
    } else if has_wpa {
        SEC_WPA
    } else if privacy {
        SEC_WEP
    } else {
        SEC_OPEN
    };

    // An SSID that is all NUL bytes is a hidden network advertising a
    // zero-filled placeholder; treat it as hidden (empty).
    if rec.ssid_len > 0 && rec.ssid[..rec.ssid_len as usize].iter().all(|&b| b == 0) {
        rec.ssid_len = 0;
    }

    let q = QUEUE.load(Ordering::Relaxed);
    if q.is_null() {
        return;
    }
    // Non-blocking send; on a full queue we drop and count rather than stall
    // the WiFi task.
    let ok = xQueueGenericSend(
        q as QueueHandle_t,
        &rec as *const RawRec as *const c_void,
        0,
        0, // queueSEND_TO_BACK
    );
    if ok == 1 {
        FRAMES.fetch_add(1, Ordering::Relaxed);
    } else {
        DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Look for the SAE AKM suite (00-0F-AC:8) inside an RSN information element,
/// which is what distinguishes WPA3 from WPA2.
fn rsn_has_sae(data: &[u8]) -> bool {
    // version(2) group cipher(4) pairwise_count(2) pairwise[4*n]
    //   akm_count(2) akm[4*n]
    if data.len() < 8 {
        return false;
    }
    let pair_count = u16::from_le_bytes([data[6], data[7]]) as usize;
    let akm_count_off = 8 + pair_count * 4;
    if akm_count_off + 2 > data.len() {
        return false;
    }
    let akm_count =
        u16::from_le_bytes([data[akm_count_off], data[akm_count_off + 1]]) as usize;
    let akm_off = akm_count_off + 2;
    for k in 0..akm_count {
        let o = akm_off + k * 4;
        if o + 4 > data.len() {
            break;
        }
        // 00-0F-AC:8 = SAE, :9 = FT-SAE
        if data[o..o + 3] == [0x00, 0x0f, 0xac] && (data[o + 3] == 8 || data[o + 3] == 9) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Host-facing JSON
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    (unsafe { esp_timer_get_time() } as u64) / 1000
}

fn push_mac(out: &mut String, mac: &[u8; 6]) {
    out.push('"');
    for (i, b) in mac.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{:02x}", b));
    }
    out.push('"');
}

/// SSIDs are arbitrary attacker-controlled bytes: not necessarily UTF-8, and
/// free to contain quotes, backslashes and control characters. Escape
/// rigorously or one hostile beacon breaks the host's line parser.
fn push_str_escaped(out: &mut String, raw: &[u8]) {
    out.push('"');
    for c in String::from_utf8_lossy(raw).chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn sec_name(sec: u8) -> &'static str {
    match sec {
        SEC_WEP => "WEP",
        SEC_WPA => "WPA",
        SEC_WPA2 => "WPA2",
        SEC_WPA3 => "WPA3",
        _ => "OPEN",
    }
}

/// A locally-administered unicast address (bit 1 of the first octet) is the
/// signature of MAC randomization - i.e. a phone deliberately hiding its real
/// hardware address. This is worth surfacing: it is the visible evidence that
/// the device is trying not to be tracked.
fn is_randomized(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

// ---------------------------------------------------------------------------
// Beacon aggregation
// ---------------------------------------------------------------------------

struct Ap {
    ssid: [u8; 32],
    ssid_len: u8,
    sec: u8,
    channel: u8,
    /// Strongest RSSI seen since the last flush.
    rssi_best: i8,
    /// Total beacons heard from this BSSID since boot.
    count: u32,
    last_seen_ms: u64,
    dirty: bool,
}

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    // Our JSON shares stdout with the IDF log; keep the log quiet.
    unsafe {
        esp_log_level_set(b"*\0".as_ptr() as *const _, esp_log_level_t_ESP_LOG_WARN);
    }

    let peripherals = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    // Create the handoff queue before the callback can ever fire.
    let q = unsafe { xQueueGenericCreate(QUEUE_DEPTH, size_of::<RawRec>() as u32, 0) };
    if q.is_null() {
        anyhow::bail!("failed to allocate frame queue");
    }
    QUEUE.store(q as *mut c_void, Ordering::SeqCst);

    // Bring the radio up in STA mode but never connect: association would lock
    // us to one channel.
    let mut wifi = WifiDriver::new(peripherals.modem, sysloop, Some(nvs))?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;

    unsafe {
        // Manual country policy covering channels 1-13 so the hopper can reach
        // 12 and 13. We only ever receive, never transmit.
        let mut country = wifi_country_t {
            cc: [0; 3],
            schan: 1,
            nchan: 13,
            max_tx_power: 20,
            policy: wifi_country_policy_t_WIFI_COUNTRY_POLICY_MANUAL,
        };
        let cc = *b"JP\0";
        country.cc = cc.map(|b| b as _);
        esp!(esp_wifi_set_country(&country))?;
    }

    wifi.start()?;

    unsafe {
        // Power save would have the radio nap through frames we want.
        esp!(esp_wifi_set_ps(wifi_ps_type_t_WIFI_PS_NONE))?;

        let filter = wifi_promiscuous_filter_t {
            filter_mask: WIFI_PROMIS_FILTER_MASK_MGMT,
        };
        esp!(esp_wifi_set_promiscuous_filter(&filter))?;
        esp!(esp_wifi_set_promiscuous_rx_cb(Some(rx_cb)))?;
        esp!(esp_wifi_set_promiscuous(true))?;
    }

    // Channel hopper.
    std::thread::Builder::new()
        .stack_size(4096)
        .name("hopper".into())
        .spawn(|| loop {
            for (ch, dwell) in HOP_PLAN {
                unsafe {
                    // Ignore failures: some channels may be rejected depending
                    // on the regulatory state, and that shouldn't stop the sweep.
                    esp_wifi_set_channel(ch, wifi_second_chan_t_WIFI_SECOND_CHAN_NONE);
                }
                std::thread::sleep(std::time::Duration::from_millis(dwell));
            }
        })?;

    let mut out = String::with_capacity(8192);
    let mut stdout = std::io::stdout();

    // Announce ourselves so the host can confirm the link is live and knows
    // what schema to expect.
    out.push_str("{\"t\":\"meta\",\"fw\":\"wardrive-fw 0.1\",\"band\":\"2.4GHz\",\"schema\":1}\n");

    let mut aps: HashMap<[u8; 6], Ap> = HashMap::new();
    let mut rec = RawRec::zeroed();

    let mut last_flush = now_ms();
    let mut last_stat = now_ms();
    let mut probe_window_start = now_ms();
    let mut wildcards_this_window: u32 = 0;
    let mut wildcards_suppressed: u32 = 0;

    loop {
        // Drain whatever the callback has queued. 50 ms block keeps us
        // responsive without spinning.
        let got = unsafe {
            xQueueReceive(
                q,
                &mut rec as *mut RawRec as *mut c_void,
                QUEUE_WAIT_TICKS,
            )
        };

        if got == 1 {
            loop {
                handle(
                    &rec,
                    &mut aps,
                    &mut out,
                    &mut wildcards_this_window,
                    &mut wildcards_suppressed,
                );
                let more = unsafe {
                    xQueueReceive(q, &mut rec as *mut RawRec as *mut c_void, 0)
                };
                if more != 1 {
                    break;
                }
            }
        }

        let now = now_ms();

        // Reset the wildcard-probe budget once per second.
        if now.saturating_sub(probe_window_start) >= 1000 {
            probe_window_start = now;
            wildcards_this_window = 0;
        }

        // Flush aggregated beacon rows.
        if now.saturating_sub(last_flush) >= BEACON_FLUSH_MS {
            last_flush = now;
            for (bssid, ap) in aps.iter_mut() {
                if !ap.dirty {
                    continue;
                }
                emit_beacon(&mut out, bssid, ap, now);
                ap.dirty = false;
                ap.rssi_best = i8::MIN;
            }
            aps.retain(|_, ap| now.saturating_sub(ap.last_seen_ms) < AP_STALE_MS);
        }

        // Heartbeat / health line.
        if now.saturating_sub(last_stat) >= 2000 {
            last_stat = now;
            out.push_str("{\"t\":\"stat\",\"ts\":");
            out.push_str(&now.to_string());
            out.push_str(",\"frames\":");
            out.push_str(&FRAMES.load(Ordering::Relaxed).to_string());
            out.push_str(",\"queue_drops\":");
            out.push_str(&DROPS.load(Ordering::Relaxed).to_string());
            out.push_str(",\"probe_suppressed\":");
            out.push_str(&wildcards_suppressed.to_string());
            out.push_str(",\"aps\":");
            out.push_str(&aps.len().to_string());
            out.push_str(",\"heap\":");
            out.push_str(&unsafe { esp_get_free_heap_size() }.to_string());
            out.push_str("}\n");
        }

        if !out.is_empty() {
            let _ = stdout.write_all(out.as_bytes());
            let _ = stdout.flush();
            out.clear();
        }
    }
}

fn handle(
    rec: &RawRec,
    aps: &mut HashMap<[u8; 6], Ap>,
    out: &mut String,
    wildcards_this_window: &mut u32,
    wildcards_suppressed: &mut u32,
) {
    let now = now_ms();

    match rec.kind {
        KIND_BEACON => {
            let entry = aps.entry(rec.bssid).or_insert_with(|| {
                Ap {
                    ssid: rec.ssid,
                    ssid_len: rec.ssid_len,
                    sec: rec.sec,
                    channel: rec.channel,
                    rssi_best: i8::MIN,
                    count: 0,
                    last_seen_ms: now,
                    // Emit a brand-new AP on the next flush rather than
                    // waiting a full cycle.
                    dirty: true,
                }
            });

            entry.count = entry.count.saturating_add(1);
            entry.last_seen_ms = now;
            entry.channel = rec.channel;
            entry.sec = rec.sec;
            entry.dirty = true;
            if rec.rssi > entry.rssi_best {
                entry.rssi_best = rec.rssi;
            }
            // A hidden AP's beacon carries no SSID, but its probe response
            // might - so never overwrite a known name with an empty one.
            if rec.ssid_len > 0 {
                entry.ssid = rec.ssid;
                entry.ssid_len = rec.ssid_len;
            }
        }

        KIND_PROBE_REQ => {
            let named = rec.ssid_len > 0;
            if !named {
                // Wildcard probes are the bulk of the traffic and each one is
                // individually uninteresting; budget them.
                if *wildcards_this_window >= WILDCARD_PROBE_BUDGET {
                    *wildcards_suppressed = wildcards_suppressed.saturating_add(1);
                    return;
                }
                *wildcards_this_window += 1;
            }

            out.push_str("{\"t\":\"probe_req\",\"ts\":");
            out.push_str(&now.to_string());
            out.push_str(",\"mac\":");
            push_mac(out, &rec.src);
            out.push_str(",\"ssid\":");
            push_str_escaped(out, rec.ssid());
            out.push_str(",\"named\":");
            out.push_str(if named { "true" } else { "false" });
            out.push_str(",\"rssi\":");
            out.push_str(&rec.rssi.to_string());
            out.push_str(",\"ch\":");
            out.push_str(&rec.channel.to_string());
            out.push_str(",\"rnd\":");
            out.push_str(if is_randomized(&rec.src) { "true" } else { "false" });
            out.push_str("}\n");
        }

        KIND_PROBE_RESP => {
            // Useful because a probe response reveals the SSID of an AP whose
            // beacons are cloaked.
            out.push_str("{\"t\":\"probe_resp\",\"ts\":");
            out.push_str(&now.to_string());
            out.push_str(",\"bssid\":");
            push_mac(out, &rec.bssid);
            out.push_str(",\"ssid\":");
            push_str_escaped(out, rec.ssid());
            out.push_str(",\"rssi\":");
            out.push_str(&rec.rssi.to_string());
            out.push_str(",\"ch\":");
            out.push_str(&rec.channel.to_string());
            out.push_str(",\"sec\":\"");
            out.push_str(sec_name(rec.sec));
            out.push_str("\"}\n");

            // Let a probe response fill in a hidden AP's name.
            if rec.ssid_len > 0 {
                if let Some(ap) = aps.get_mut(&rec.bssid) {
                    if ap.ssid_len == 0 {
                        ap.ssid = rec.ssid;
                        ap.ssid_len = rec.ssid_len;
                        ap.dirty = true;
                    }
                }
            }
        }

        _ => {}
    }
}

fn emit_beacon(out: &mut String, bssid: &[u8; 6], ap: &Ap, now: u64) {
    out.push_str("{\"t\":\"beacon\",\"ts\":");
    out.push_str(&now.to_string());
    out.push_str(",\"bssid\":");
    push_mac(out, bssid);
    out.push_str(",\"ssid\":");
    push_str_escaped(out, &ap.ssid[..ap.ssid_len as usize]);
    out.push_str(",\"hidden\":");
    out.push_str(if ap.ssid_len == 0 { "true" } else { "false" });
    out.push_str(",\"rssi\":");
    // rssi_best is reset to i8::MIN after each flush; if we somehow emit
    // without a sample, send a floor value the host can filter.
    out.push_str(&if ap.rssi_best == i8::MIN { -100 } else { ap.rssi_best }.to_string());
    out.push_str(",\"ch\":");
    out.push_str(&ap.channel.to_string());
    out.push_str(",\"sec\":\"");
    out.push_str(sec_name(ap.sec));
    out.push_str("\",\"count\":");
    out.push_str(&ap.count.to_string());
    out.push_str("}\n");
}
