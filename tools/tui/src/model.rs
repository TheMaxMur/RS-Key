// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Typed state model for rsk-tui — the vocabulary every other module speaks.
//!
//! Pure data: no device I/O, no ratatui, no terminal. That keeps the UI and the
//! navigation logic testable against a snapshot without any hardware (see the
//! `MockProvider` in `device.rs` and the `--demo` flag). Status is *typed* —
//! the renderer never parses strings back out of a status field.

use std::collections::VecDeque;

use zeroize::Zeroizing;

/// Health of a single status field — drives the OK / WARN / ERROR / UNKNOWN
/// indicator. Color is never the only signal: the renderer always prints the
/// word too, so the dashboard reads on a monochrome or color-blind terminal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Health {
    Ok,
    Warn,
    Error,
    Unknown,
    /// Supported by the device but intentionally not driven from the TUI
    /// (CLI-only). Shown plainly, never faked.
    NotApplicable,
}

impl Health {
    pub fn word(self) -> &'static str {
        match self {
            Health::Ok => "OK",
            Health::Warn => "WARN",
            Health::Error => "ERR",
            Health::Unknown => "UNK",
            Health::NotApplicable => "N/A",
        }
    }
}

/// One typed status row: a health classification plus a human label/value. The
/// renderer consumes these instead of re-deriving state from formatted strings.
#[derive(Clone, Debug)]
pub struct FeatureStatus {
    pub health: Health,
    pub key: String,
    pub value: String,
}

impl FeatureStatus {
    pub fn new(health: Health, key: impl Into<String>, value: impl Into<String>) -> Self {
        FeatureStatus {
            health,
            key: key.into(),
            value: value.into(),
        }
    }
}

/// A presence/answered indicator for a transport channel.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Link {
    #[default]
    Unknown,
    Present,
    Absent,
    /// Channel exists but the device would not talk (reader busy, etc.).
    Busy,
    Error,
}

impl Link {
    pub fn word(self) -> &'static str {
        match self {
            Link::Unknown => "unknown",
            Link::Present => "present",
            Link::Absent => "absent",
            Link::Busy => "busy",
            Link::Error => "error",
        }
    }
    pub fn health(self) -> Health {
        match self {
            Link::Present => Health::Ok,
            Link::Absent => Health::Unknown,
            Link::Busy => Health::Warn,
            Link::Error => Health::Error,
            Link::Unknown => Health::Unknown,
        }
    }
}

/// Which transports answered this gather.
#[derive(Clone, Debug, Default)]
pub struct TransportStatus {
    /// CTAPHID over hidapi (FIDO).
    pub hid: Link,
    /// The PC/SC subsystem / reader list.
    pub pcsc: Link,
    /// An RS-Key CCID applet that actually answered SELECT.
    pub ccid: Link,
    pub note: Option<String>,
}

/// Stable device identity, gathered from the rescue applet + FIDO getInfo.
#[derive(Clone, Debug, Default)]
pub struct Identity {
    pub serial: Option<String>,
    pub sdk: Option<String>,
    pub firmware: Option<String>,
    pub bcd_device: Option<u16>,
    pub aaguid: Option<String>,
    pub product: Option<String>,
    /// More than one FIDO HID device is attached, so the HID-sourced half of this
    /// identity (and every action, which re-opens the device) may belong to a
    /// different key than the CCID-sourced serial beside it.
    pub hid_ambiguous: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FidoState {
    pub present: bool,
    pub versions: Vec<String>,
    pub client_pin: Option<bool>,
    pub options: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct BackupState {
    pub sealed: bool,
    pub has_seed: bool,
}

impl BackupState {
    pub fn describe(self) -> String {
        format!("sealed={}  has_seed={}", self.sealed, self.has_seed)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LockState {
    pub locked: bool,
    pub unlocked: bool,
}

/// Applet-presence probe → health + label: `None` = not probed (CCID down).
pub fn present_health(p: Option<bool>) -> (Health, &'static str) {
    match p {
        Some(true) => (Health::Ok, "present"),
        Some(false) => (Health::Unknown, "absent"),
        None => (Health::Unknown, "not probed"),
    }
}

impl LockState {
    pub fn describe(self) -> &'static str {
        match (self.locked, self.unlocked) {
            (false, _) => "off",
            (true, true) => "LOCKED (unlocked this session)",
            (true, false) => "LOCKED — FIDO ops disabled until unlock",
        }
    }
    pub fn health(self) -> Health {
        if self.locked && !self.unlocked {
            Health::Warn
        } else {
            Health::Ok
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SecureBootState {
    pub enabled: bool,
    pub locked: bool,
    pub bootkey: u8,
}

impl SecureBootState {
    pub fn describe(self) -> &'static str {
        if self.locked {
            "LOCKED"
        } else if self.enabled {
            "ENABLED (not locked)"
        } else {
            "not enabled"
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RollbackState {
    pub required: bool,
    pub version: u8,
    pub capacity: u8,
}

impl RollbackState {
    pub fn describe(self) -> &'static str {
        if self.required {
            "required"
        } else {
            "not required"
        }
    }
}

#[derive(Clone, Debug)]
pub struct AttestationState {
    pub installed: bool,
    pub chain_sha256: Option<String>,
}

impl AttestationState {
    pub fn describe(&self) -> &'static str {
        if self.installed {
            "installed"
        } else {
            "not installed"
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FlashState {
    pub free: u32,
    pub used: u32,
    pub kv_total: u32,
    pub files: u32,
    pub chip: u32,
}

/// CCID applet presence. `None` = not probed; `Some(false)` = probed, absent.
#[derive(Clone, Copy, Debug, Default)]
pub struct Applets {
    pub openpgp: Option<bool>,
    pub piv: Option<bool>,
    pub oath: Option<bool>,
    pub otp: Option<bool>,
}

/// LED colour per device status, as an index into the firmware's 8-colour wheel
/// (`0=off, 1=red, … 7=white`). Read live in the gather so the LED section can
/// paint a swatch instead of only naming the colour.
#[derive(Clone, Copy, Debug)]
pub struct LedState {
    pub steady: bool,
    pub idle: u8,
    pub processing: u8,
    pub touch: u8,
    pub boot: u8,
}

/// OpenPGP application-related data worth showing without shelling out to `gpg`:
/// the card serial, the three PIN retry counters (PW1 / reset-code / PW3), and
/// how many of the sig/dec/auth slots hold a key. Parsed from the `6E` DO.
#[derive(Clone, Debug, Default)]
pub struct PgpInfo {
    pub serial: Option<String>,
    pub pin_retries: Option<[u8; 3]>,
    pub keys_present: u8,
}

/// PIV PIN metadata (GET METADATA of the PIN reference): retries remaining/total
/// and whether the PIN is still the factory default.
#[derive(Clone, Copy, Debug, Default)]
pub struct PivInfo {
    pub pin_left: u8,
    pub pin_total: u8,
    pub pin_default: bool,
}

/// Everything the dashboard knows about the device, all typed. Every field is
/// an honest read: `None`/absent means "not observed", never a faked default.
#[derive(Clone, Debug, Default)]
pub struct DeviceSnapshot {
    pub transport: TransportStatus,
    pub identity: Identity,
    pub fido: FidoState,
    pub backup: Option<BackupState>,
    pub lock: Option<LockState>,
    pub secure_boot: Option<SecureBootState>,
    pub rollback: Option<RollbackState>,
    pub attestation: Option<AttestationState>,
    pub flash: Option<FlashState>,
    pub applets: Applets,
    /// LED colours read live (idle/processing/touch/boot), for the LED preview.
    pub led: Option<LedState>,
    /// OpenPGP application-related data (parsed from the `6E` GET DATA template).
    pub pgp: Option<PgpInfo>,
    /// PIV PIN metadata (GET METADATA of the PIN reference).
    pub piv_meta: Option<PivInfo>,
    pub errors: Vec<String>,
    /// True when the snapshot came from the mock provider (`--demo`).
    pub demo: bool,
}

impl DeviceSnapshot {
    /// Is *any* RS-Key channel answering?
    pub fn any_device(&self) -> bool {
        self.fido.present || self.transport.ccid == Link::Present
    }

    pub fn pin_set(&self) -> bool {
        self.fido.client_pin == Some(true)
    }

    pub fn sealed(&self) -> bool {
        self.backup.map(|b| b.sealed).unwrap_or(false)
    }

    /// One-line device summary for the header.
    pub fn summary(&self) -> String {
        if !self.any_device() {
            return "no device detected".into();
        }
        let mut parts = Vec::new();
        if self.identity.hid_ambiguous {
            // Say so first and drop the serial: a header that pairs one key's serial
            // with another key's firmware is worse than no header at all.
            parts.push("MULTIPLE FIDO DEVICES — identity ambiguous".into());
        } else if let Some(s) = &self.identity.serial {
            parts.push(format!("serial {}", &s[..s.len().min(12)]));
        }
        if let Some(fw) = &self.identity.firmware {
            parts.push(format!("fw {fw}"));
        }
        if let Some(bcd) = self.identity.bcd_device {
            parts.push(format!("bcd {bcd:#06x}"));
        }
        if parts.is_empty() {
            "device present".into()
        } else {
            parts.join(" · ")
        }
    }

    /// The headline security fields as typed status rows (backup, lock, secure
    /// boot, anti-rollback, attestation, flash). The renderer just paints these.
    pub fn security_status(&self) -> Vec<FeatureStatus> {
        let mut out = Vec::new();
        match self.backup {
            Some(b) => out.push(FeatureStatus::new(
                if b.has_seed { Health::Ok } else { Health::Warn },
                "backup",
                b.describe(),
            )),
            None => out.push(FeatureStatus::new(Health::Unknown, "backup", "—")),
        }
        if let Some(l) = self.lock {
            out.push(FeatureStatus::new(l.health(), "seed lock", l.describe()));
        }
        match self.secure_boot {
            Some(sb) => {
                let h = if sb.locked {
                    Health::Ok
                } else if sb.enabled {
                    Health::Warn
                } else {
                    Health::Unknown
                };
                let t = sb.describe();
                out.push(FeatureStatus::new(
                    h,
                    "secure boot",
                    format!("{t}  bootkey {:#x}", sb.bootkey),
                ));
            }
            None => out.push(FeatureStatus::new(
                Health::Unknown,
                "secure boot",
                "CCID unavailable",
            )),
        }
        if let Some(r) = self.rollback {
            out.push(FeatureStatus::new(
                if r.required {
                    Health::Ok
                } else {
                    Health::Unknown
                },
                "anti-rollback",
                format!("{}  v{}/{}", r.describe(), r.version, r.capacity),
            ));
        }
        if let Some(a) = &self.attestation {
            out.push(FeatureStatus::new(
                if a.installed {
                    Health::Ok
                } else {
                    Health::Unknown
                },
                "org attest",
                a.describe(),
            ));
        }
        if let Some(fl) = self.flash {
            out.push(FeatureStatus::new(
                Health::Ok,
                "flash",
                format!("{}/{} B used, {} files", fl.used, fl.kv_total, fl.files),
            ));
        }
        out
    }

    /// Worst health across the headline fields — the header's overall dot.
    pub fn overall_health(&self) -> Health {
        if !self.any_device() {
            return Health::Unknown;
        }
        if !self.errors.is_empty() {
            return Health::Warn;
        }
        if let Some(l) = self.lock
            && l.locked
            && !l.unlocked
        {
            return Health::Warn;
        }
        Health::Ok
    }

    /// Hand-rolled JSON for `--json` (no extra deps; stable, explicit schema).
    pub fn to_json(&self) -> String {
        let id = &self.identity;
        let mut out = String::from("{");
        json_field(&mut out, "demo", &json_bool(self.demo), true);
        json_field(
            &mut out,
            "transport",
            &format!(
                "{{\"hid\":{},\"pcsc\":{},\"ccid\":{},\"note\":{}}}",
                json_str(self.transport.hid.word()),
                json_str(self.transport.pcsc.word()),
                json_str(self.transport.ccid.word()),
                json_opt_str(self.transport.note.as_deref()),
            ),
            false,
        );
        json_field(
            &mut out,
            "identity",
            &format!(
                "{{\"serial\":{},\"sdk\":{},\"firmware\":{},\"bcd_device\":{},\"aaguid\":{},\"product\":{}}}",
                json_opt_str(id.serial.as_deref()),
                json_opt_str(id.sdk.as_deref()),
                json_opt_str(id.firmware.as_deref()),
                id.bcd_device
                    .map(|b| json_str(&format!("{b:#06x}")))
                    .unwrap_or_else(|| "null".into()),
                json_opt_str(id.aaguid.as_deref()),
                json_opt_str(id.product.as_deref()),
            ),
            false,
        );
        json_field(
            &mut out,
            "fido",
            &format!(
                "{{\"present\":{},\"versions\":[{}],\"client_pin\":{},\"options\":[{}]}}",
                json_bool(self.fido.present),
                self.fido
                    .versions
                    .iter()
                    .map(|v| json_str(v))
                    .collect::<Vec<_>>()
                    .join(","),
                self.fido
                    .client_pin
                    .map(json_bool)
                    .unwrap_or_else(|| "null".into()),
                self.fido
                    .options
                    .iter()
                    .map(|v| json_str(v))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            false,
        );
        json_field(
            &mut out,
            "backup",
            &self
                .backup
                .map(|b| {
                    format!(
                        "{{\"sealed\":{},\"has_seed\":{}}}",
                        json_bool(b.sealed),
                        json_bool(b.has_seed)
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "lock",
            &self
                .lock
                .map(|l| {
                    format!(
                        "{{\"locked\":{},\"unlocked\":{}}}",
                        json_bool(l.locked),
                        json_bool(l.unlocked)
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "secure_boot",
            &self
                .secure_boot
                .map(|s| {
                    format!(
                        "{{\"enabled\":{},\"locked\":{},\"bootkey\":{}}}",
                        json_bool(s.enabled),
                        json_bool(s.locked),
                        s.bootkey
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "rollback",
            &self
                .rollback
                .map(|r| {
                    format!(
                        "{{\"required\":{},\"version\":{},\"capacity\":{}}}",
                        json_bool(r.required),
                        r.version,
                        r.capacity
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "attestation",
            &self
                .attestation
                .as_ref()
                .map(|a| {
                    format!(
                        "{{\"installed\":{},\"chain_sha256\":{}}}",
                        json_bool(a.installed),
                        json_opt_str(a.chain_sha256.as_deref())
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "flash",
            &self
                .flash
                .map(|f| {
                    format!(
                        "{{\"free\":{},\"used\":{},\"kv_total\":{},\"files\":{},\"chip\":{}}}",
                        f.free, f.used, f.kv_total, f.files, f.chip
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "applets",
            &format!(
                "{{\"openpgp\":{},\"piv\":{},\"oath\":{},\"otp\":{}}}",
                json_opt_bool(self.applets.openpgp),
                json_opt_bool(self.applets.piv),
                json_opt_bool(self.applets.oath),
                json_opt_bool(self.applets.otp),
            ),
            false,
        );
        json_field(
            &mut out,
            "led",
            &self
                .led
                .map(|l| {
                    format!(
                        "{{\"steady\":{},\"idle\":{},\"processing\":{},\"touch\":{},\"boot\":{}}}",
                        json_bool(l.steady),
                        l.idle,
                        l.processing,
                        l.touch,
                        l.boot
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "pgp",
            &self
                .pgp
                .as_ref()
                .map(|p| {
                    let retries = p
                        .pin_retries
                        .map(|r| format!("[{},{},{}]", r[0], r[1], r[2]))
                        .unwrap_or_else(|| "null".into());
                    format!(
                        "{{\"serial\":{},\"pin_retries\":{},\"keys_present\":{}}}",
                        json_opt_str(p.serial.as_deref()),
                        retries,
                        p.keys_present
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "piv_meta",
            &self
                .piv_meta
                .map(|p| {
                    format!(
                        "{{\"pin_left\":{},\"pin_total\":{},\"pin_default\":{}}}",
                        p.pin_left,
                        p.pin_total,
                        json_bool(p.pin_default)
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "errors",
            &format!(
                "[{}]",
                self.errors
                    .iter()
                    .map(|e| json_str(e))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            false,
        );
        out.push('}');
        out
    }
}

// ---- the sections of the cockpit ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    Overview,
    Fido,
    OpenPgp,
    Piv,
    OathOtp,
    Backup,
    Led,
    Audit,
    Reboot,
    Help,
}

impl Section {
    pub const ALL: [Section; 10] = [
        Section::Overview,
        Section::Fido,
        Section::OpenPgp,
        Section::Piv,
        Section::OathOtp,
        Section::Backup,
        Section::Led,
        Section::Audit,
        Section::Reboot,
        Section::Help,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Section::Overview => "Overview",
            Section::Fido => "FIDO",
            Section::OpenPgp => "OpenPGP",
            Section::Piv => "PIV",
            Section::OathOtp => "OATH / OTP",
            Section::Backup => "Backup",
            Section::Led => "LED",
            Section::Audit => "Audit",
            Section::Reboot => "Reboot / Maintenance",
            Section::Help => "Help",
        }
    }
}

// ---- actions ----

/// A device operation the TUI can perform itself. Destructive/irreversible
/// firmware rituals are deliberately *not* here — they stay in the `rsk` CLI.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Refresh,
    CredCount,
    LedGet,
    LedCycle,
    BackupExport,
    BackupExportSlip39,
    BackupRestore,
    BackupFinalize,
    AuditRead,
    Verify,
    RebootApp,
    RebootBootsel,
}

impl Action {
    /// Short label for the search palette.
    pub fn label(self) -> &'static str {
        match self {
            Action::Refresh => "Refresh status",
            Action::CredCount => "FIDO · count resident passkeys",
            Action::LedGet => "LED · read state",
            Action::LedCycle => "LED · cycle idle color",
            Action::BackupExport => "Backup · export (BIP-39)",
            Action::BackupExportSlip39 => "Backup · export (SLIP-39)",
            Action::BackupRestore => "Backup · restore (BIP-39)",
            Action::BackupFinalize => "Backup · finalize (seal window)",
            Action::AuditRead => "Audit · read journal",
            Action::Verify => "Verify device identity",
            Action::RebootApp => "Reboot → app",
            Action::RebootBootsel => "Reboot → BOOTSEL",
        }
    }

    pub fn section(self) -> Section {
        match self {
            Action::Refresh | Action::Verify => Section::Overview,
            Action::CredCount => Section::Fido,
            Action::LedGet | Action::LedCycle => Section::Led,
            Action::BackupExport
            | Action::BackupExportSlip39
            | Action::BackupRestore
            | Action::BackupFinalize => Section::Backup,
            Action::AuditRead => Section::Audit,
            Action::RebootApp | Action::RebootBootsel => Section::Reboot,
        }
    }

    /// The whole catalog, for the `/` search palette.
    pub const ALL: [Action; 12] = [
        Action::Refresh,
        Action::Verify,
        Action::CredCount,
        Action::LedGet,
        Action::LedCycle,
        Action::BackupExport,
        Action::BackupExportSlip39,
        Action::BackupRestore,
        Action::BackupFinalize,
        Action::AuditRead,
        Action::RebootApp,
        Action::RebootBootsel,
    ];
}

/// Secrets collected across a multi-step modal flow. `Zeroizing` wipes them on
/// drop; they are passed to the device once and never reach the log.
#[derive(Default)]
pub struct ActionInput {
    pub pin: Option<Zeroizing<String>>,
    pub phrase: Option<Zeroizing<String>>,
}

/// Outcome of a device operation.
pub enum ActionResult {
    /// Short, non-secret success message → status line + log.
    Ok(String),
    /// Non-secret failure message → status line + log (as an error).
    Failed(String),
    /// Multi-line, non-secret output → shown in a Message modal (audit, verify).
    Report { title: String, body: String },
    /// A secret to reveal once on-screen, then zeroize. NEVER logged.
    Reveal {
        title: String,
        body: Zeroizing<String>,
    },
}

// ---- the event/log ring ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogLevel {
    Info,
    Good,
    Warn,
    Error,
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub level: LogLevel,
    pub text: String,
}

/// A bounded ring of recent operations. The log is the one place text from
/// actions lands, so redaction lives here: see [`EventLog::push`].
#[derive(Default)]
pub struct EventLog {
    entries: VecDeque<LogEntry>,
}

impl EventLog {
    const CAP: usize = 200;

    /// Append an entry. `secrets` are substrings (live PIN/phrase buffers) that
    /// must never be persisted — a defensive backstop on top of the structural
    /// guarantee that secrets are never handed to the log in the first place.
    pub fn push(&mut self, level: LogLevel, text: impl Into<String>, secrets: &[&str]) {
        let mut text = text.into();
        for s in secrets {
            if !s.is_empty() && text.contains(s) {
                text = text.replace(s, "[redacted]");
            }
        }
        self.entries.push_back(LogEntry { level, text });
        while self.entries.len() > Self::CAP {
            self.entries.pop_front();
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---- tiny JSON helpers (hand-rolled; no serde dep) ----

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Escape every control and non-ASCII char to \uXXXX (like the Python
            // CLI's ensure_ascii): keeps output valid JSON while neutralizing a
            // hostile device's DEL/C1/bidi bytes in a raw --json terminal view.
            c if c.is_control() || !c.is_ascii() => {
                let u = c as u32;
                if u > 0xFFFF {
                    let v = u - 0x10000;
                    out.push_str(&format!(
                        "\\u{:04x}\\u{:04x}",
                        0xD800 + (v >> 10),
                        0xDC00 + (v & 0x3FF)
                    ));
                } else {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_opt_str(s: Option<&str>) -> String {
    s.map(json_str).unwrap_or_else(|| "null".into())
}

fn json_bool(b: bool) -> String {
    if b { "true".into() } else { "false".into() }
}

fn json_opt_bool(b: Option<bool>) -> String {
    b.map(json_bool).unwrap_or_else(|| "null".into())
}

fn json_field(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push_str(&json_str(key));
    out.push(':');
    out.push_str(value);
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
