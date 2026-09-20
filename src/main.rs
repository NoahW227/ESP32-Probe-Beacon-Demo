#![no_std]
#![no_main]

//! Passive 802.11 sniffer for the ESP32. Hops the 2.4 GHz channels and emits
//! newline-delimited JSON on UART0 at 115200 baud.
//!
//! Two constraints shape the design:
//!
//! * We never associate — that would pin the radio to one channel and kill
//!   channel hopping. It is also why the host link is serial, not WiFi.
//! * The sniffer callback runs on the WiFi task, so it copies what it needs
//!   into a queue and returns. Formatting happens in `main`.

extern crate alloc;

// espflash refuses an image without an ESP-IDF app descriptor in its header.
esp_bootloader_esp_idf::esp_app_desc!();

use alloc::collections::BTreeMap;
use core::{
    cell::RefCell,
    sync::atomic::{AtomicU32, Ordering},
};

use critical_section::Mutex;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock, interrupt::software::SoftwareInterruptControl, main, time::Instant,
    timer::timg::TimerGroup,
};
use esp_println::println;
use esp_radio::wifi::{
    sniffer::PromiscuousPkt, sta::StationConfig, Config, ControllerConfig, SecondaryChannel,
};
use heapless::{Deque, String as HString};
use ieee80211::{
    elements::{
        rsn::{IEEE80211AkmType, RsnElement},
        DSSSParameterSetElement, ReadElements, SSIDElement,
    },
    match_frames,
    mgmt_frame::{BeaconFrame, ProbeRequestFrame, ProbeResponseFrame},
};
use serde::Serialize;

// --- Tunables ---

const QUEUE_DEPTH: usize = 128;
const BEACON_FLUSH_MS: u64 = 1000;
const STAT_INTERVAL_MS: u64 = 2000;
const AP_STALE_MS: u64 = 300_000;

/// Max wildcard probes emitted per second. Named probes bypass this — they are
/// rare and are the whole point.
const WILDCARD_BUDGET: u32 = 150;

/// 1/6/11 carry most APs so they get a longer dwell; the rest get a quick look
/// to catch probes sprayed across the band. Full sweep 2.7 s.
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

// --- Shared state ---

static QUEUE: Mutex<RefCell<Deque<Frame, QUEUE_DEPTH>>> =
    Mutex::new(RefCell::new(Deque::new()));
static SEEN: AtomicU32 = AtomicU32::new(0);
static DROPS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Beacon,
    ProbeReq,
    ProbeResp,
}

#[derive(Clone, Copy, PartialEq)]
enum Sec {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
}

impl Sec {
    fn as_str(self) -> &'static str {
        match self {
            Sec::Open => "OPEN",
            Sec::Wep => "WEP",
            Sec::Wpa => "WPA",
            Sec::Wpa2 => "WPA2",
            Sec::Wpa3 => "WPA3",
        }
    }
}

/// Owned copy of one frame: `ieee80211` parses zero-copy against the driver's
/// buffer, which dies when the callback returns.
#[derive(Clone)]
struct Frame {
    kind: Kind,
    rssi: i8,
    channel: u8,
    src: [u8; 6],
    bssid: [u8; 6],
    ssid: HString<32>,
    /// False for a hidden AP or a wildcard probe.
    has_ssid: bool,
    sec: Sec,
}

// --- JSON — serde derives the whole wire format ---

#[derive(Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Event<'a> {
    Beacon {
        ts: u64,
        bssid: Mac,
        ssid: &'a str,
        hidden: bool,
        rssi: i8,
        ch: u8,
        sec: &'static str,
        count: u32,
    },
    ProbeReq {
        ts: u64,
        mac: Mac,
        ssid: &'a str,
        named: bool,
        rssi: i8,
        ch: u8,
        rnd: bool,
    },
    ProbeResp {
        ts: u64,
        bssid: Mac,
        ssid: &'a str,
        rssi: i8,
        ch: u8,
        sec: &'static str,
    },
    Stat {
        ts: u64,
        frames: u32,
        queue_drops: u32,
        probe_suppressed: u32,
        aps: usize,
        heap: usize,
    },
}

/// Serializes as `aa:bb:cc:dd:ee:ff` without allocating.
struct Mac([u8; 6]);

impl Serialize for Mac {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; 17];
        for (i, b) in self.0.iter().enumerate() {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            buf[i * 3] = HEX[(b >> 4) as usize];
            buf[i * 3 + 1] = HEX[(b & 0xf) as usize];
            if i < 5 {
                buf[i * 3 + 2] = b':';
            }
        }
        s.serialize_str(core::str::from_utf8(&buf).unwrap_or("??"))
    }
}

fn emit(ev: &Event<'_>) {
    if let Ok(s) = serde_json::to_string(ev) {
        println!("{}", s);
    }
}

/// A locally-administered address means the device is randomizing its MAC.
fn is_randomized(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

// --- Frame parsing ---

/// `ieee80211` validates SSIDs as UTF-8, so without checking the raw element a
/// non-UTF-8 name would look identical to a hidden network.
fn read_ssid(elements: ReadElements<'_>) -> (HString<32>, bool) {
    let mut out = HString::new();
    match elements.get_first_element::<SSIDElement>() {
        Some(el) if !el.ssid().is_empty() => {
            let _ = out.push_str(el.ssid());
            (out, true)
        }
        // Element parsed as absent/empty; if raw bytes exist it is non-UTF-8.
        _ => match elements.get_first_element_raw(ieee80211::elements::ElementID::Id(0)) {
            Some(raw) if !raw.slice.is_empty() => {
                let _ = out.push_str("<non-utf8>");
                (out, true)
            }
            _ => (out, false),
        },
    }
}

fn read_channel(elements: ReadElements<'_>, fallback: u8) -> u8 {
    elements
        .get_first_element::<DSSSParameterSetElement>()
        .map(|d| d.current_channel)
        .filter(|c| (1..=14).contains(c))
        .unwrap_or(fallback)
}

/// WPA3 is distinguished from WPA2 by the SAE AKM suite in the RSN element.
fn read_security(elements: ReadElements<'_>, privacy: bool) -> Sec {
    if let Some(rsn) = elements.get_first_element::<RsnElement>() {
        let sae = rsn.akm_list.into_iter().flatten().any(|akm| {
            matches!(
                akm,
                IEEE80211AkmType::Sae | IEEE80211AkmType::FTUsingSae
            )
        });
        return if sae { Sec::Wpa3 } else { Sec::Wpa2 };
    }
    // Legacy WPA1 advertises itself in a vendor element: OUI 00:50:F2, type 1.
    let wpa1 = elements
        .get_matching_elements_raw(ieee80211::elements::ElementID::Id(221))
        .any(|e| e.slice.starts_with(&[0x00, 0x50, 0xf2, 0x01]));
    match (wpa1, privacy) {
        (true, _) => Sec::Wpa,
        (false, true) => Sec::Wep,
        (false, false) => Sec::Open,
    }
}

fn push(frame: Frame) {
    critical_section::with(|cs| {
        let mut q = QUEUE.borrow_ref_mut(cs);
        if q.push_back(frame).is_err() {
            DROPS.fetch_add(1, Ordering::Relaxed);
        } else {
            SEEN.fetch_add(1, Ordering::Relaxed);
        }
    });
}

/// Runs on the WiFi task. Keep it short: parse, copy, enqueue.
fn sniff(pkt: PromiscuousPkt<'_>) {
    let rssi = pkt.rx_cntl.rssi as i8;
    let rx_ch = pkt.rx_cntl.channel as u8;

    // Trim the trailing FCS. (match_frames! has a `with_fcs:` arm, but it
    // parses ambiguously against its own `$binding:pat` fragment.)
    let Some(body) = pkt.data.get(..pkt.data.len().saturating_sub(4)) else {
        return;
    };

    let _ = match_frames! { body,
        beacon = BeaconFrame => {
            let el = beacon.elements;
            let (ssid, has_ssid) = read_ssid(el);
            push(Frame {
                kind: Kind::Beacon,
                rssi,
                channel: read_channel(el, rx_ch),
                src: *beacon.header.transmitter_address,
                bssid: *beacon.header.bssid,
                ssid,
                has_ssid,
                sec: read_security(el, beacon.body.capabilities_info.is_confidentiality_required()),
            });
        }
        probe = ProbeRequestFrame => {
            let el = probe.elements;
            let (ssid, has_ssid) = read_ssid(el);
            push(Frame {
                kind: Kind::ProbeReq,
                rssi,
                channel: rx_ch,
                src: *probe.header.transmitter_address,
                bssid: *probe.header.bssid,
                ssid,
                has_ssid,
                sec: Sec::Open,
            });
        }
        resp = ProbeResponseFrame => {
            let el = resp.elements;
            let (ssid, has_ssid) = read_ssid(el);
            push(Frame {
                kind: Kind::ProbeResp,
                rssi,
                channel: read_channel(el, rx_ch),
                src: *resp.header.transmitter_address,
                bssid: *resp.header.bssid,
                ssid,
                has_ssid,
                sec: read_security(el, resp.body.capabilities_info.is_confidentiality_required()),
            });
        }
    };
}

// --- Beacon aggregation ---

/// Every AP beacons ~10x/second, so collapse to one row per BSSID per second
/// carrying the strongest RSSI in that window.
struct Ap {
    ssid: HString<32>,
    has_ssid: bool,
    sec: Sec,
    channel: u8,
    rssi_best: i8,
    count: u32,
    last_seen: u64,
    dirty: bool,
}

fn now_ms() -> u64 {
    Instant::now().duration_since_epoch().as_millis()
}

#[main]
fn main() -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 96 * 1024);

    // esp-radio requires a running scheduler.
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw.software_interrupt0);

    let (mut controller, mut interfaces) =
        esp_radio::wifi::new(peripherals.WIFI, ControllerConfig::default()).expect("wifi new");

    // Station mode but we never connect — association would lock us to one
    // channel. set_config is also what starts the radio.
    controller
        .set_config(&Config::Station(StationConfig::default()))
        .expect("set config");

    interfaces.sniffer.set_receive_cb(sniff);
    interfaces
        .sniffer
        .set_promiscuous_mode(true)
        .expect("promiscuous");

    println!(r#"{{"t":"meta","fw":"wardrive-fw 0.2","band":"2.4GHz","schema":1}}"#);

    let mut aps: BTreeMap<[u8; 6], Ap> = BTreeMap::new();
    let mut hop = 0usize;
    let mut hop_due = now_ms();
    let mut flush_due = now_ms() + BEACON_FLUSH_MS;
    let mut stat_due = now_ms() + STAT_INTERVAL_MS;
    let mut window_start = now_ms();
    let mut wildcards = 0u32;
    let mut suppressed = 0u32;

    loop {
        let now = now_ms();

        // Channel hop.
        if now >= hop_due {
            let (ch, dwell) = HOP_PLAN[hop];
            let _ = controller.set_channel(ch, SecondaryChannel::None);
            hop = (hop + 1) % HOP_PLAN.len();
            hop_due = now + dwell;
        }

        // Drain whatever the sniffer queued.
        while let Some(frame) = critical_section::with(|cs| QUEUE.borrow_ref_mut(cs).pop_front()) {
            handle(frame, now, &mut aps, &mut wildcards, &mut suppressed);
        }

        if now.saturating_sub(window_start) >= 1000 {
            window_start = now;
            wildcards = 0;
        }

        if now >= flush_due {
            flush_due = now + BEACON_FLUSH_MS;
            for (bssid, ap) in aps.iter_mut() {
                if !ap.dirty {
                    continue;
                }
                emit(&Event::Beacon {
                    ts: now,
                    bssid: Mac(*bssid),
                    ssid: ap.ssid.as_str(),
                    hidden: !ap.has_ssid,
                    rssi: ap.rssi_best,
                    ch: ap.channel,
                    sec: ap.sec.as_str(),
                    count: ap.count,
                });
                ap.dirty = false;
                ap.rssi_best = i8::MIN;
            }
            aps.retain(|_, ap| now.saturating_sub(ap.last_seen) < AP_STALE_MS);
        }

        if now >= stat_due {
            stat_due = now + STAT_INTERVAL_MS;
            emit(&Event::Stat {
                ts: now,
                frames: SEEN.load(Ordering::Relaxed),
                queue_drops: DROPS.load(Ordering::Relaxed),
                probe_suppressed: suppressed,
                aps: aps.len(),
                heap: esp_alloc::HEAP.free(),
            });
        }
    }
}

fn handle(
    f: Frame,
    now: u64,
    aps: &mut BTreeMap<[u8; 6], Ap>,
    wildcards: &mut u32,
    suppressed: &mut u32,
) {
    match f.kind {
        Kind::Beacon => {
            let ap = aps.entry(f.bssid).or_insert_with(|| Ap {
                ssid: HString::new(),
                has_ssid: false,
                sec: f.sec,
                channel: f.channel,
                rssi_best: i8::MIN,
                count: 0,
                last_seen: now,
                dirty: true,
            });
            ap.count = ap.count.saturating_add(1);
            ap.last_seen = now;
            ap.channel = f.channel;
            ap.sec = f.sec;
            ap.rssi_best = ap.rssi_best.max(f.rssi);
            ap.dirty = true;
            // Never overwrite a known name with a hidden AP's empty one.
            if f.has_ssid {
                ap.ssid = f.ssid;
                ap.has_ssid = true;
            }
        }

        Kind::ProbeReq => {
            // Wildcard probes are the bulk of traffic; named ones always pass.
            if !f.has_ssid {
                if *wildcards >= WILDCARD_BUDGET {
                    *suppressed = suppressed.saturating_add(1);
                    return;
                }
                *wildcards += 1;
            }
            emit(&Event::ProbeReq {
                ts: now,
                mac: Mac(f.src),
                ssid: f.ssid.as_str(),
                named: f.has_ssid,
                rssi: f.rssi,
                ch: f.channel,
                rnd: is_randomized(&f.src),
            });
        }

        Kind::ProbeResp => {
            emit(&Event::ProbeResp {
                ts: now,
                bssid: Mac(f.bssid),
                ssid: f.ssid.as_str(),
                rssi: f.rssi,
                ch: f.channel,
                sec: f.sec.as_str(),
            });
            // A probe response can reveal a cloaked AP's name.
            if f.has_ssid {
                if let Some(ap) = aps.get_mut(&f.bssid) {
                    if !ap.has_ssid {
                        ap.ssid = f.ssid;
                        ap.has_ssid = true;
                        ap.dirty = true;
                    }
                }
            }
        }
    }
}
