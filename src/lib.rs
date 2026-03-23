//! Zero-dependency UUID implementation for `nexcore` ecosystem
//!
//! Provides `NexId` — a 128-bit universally unique identifier compatible with
//! UUID v4 (random) and v7 (timestamp + random) specifications.
//!
//! # Supply Chain Sovereignty
//!
//! This crate has **zero external dependencies**. It replaces the `uuid` crate
//! for the `nexcore` ecosystem, eliminating supply chain risk for identifier generation.
//!
//! # Security
//!
//! **Platform-dependent entropy quality:**
//!
//! | Platform | Entropy Source | CSPRNG |
//! |----------|----------------|--------|
//! | Unix (Linux, macOS, BSD) | `/dev/urandom` | Yes |
//! | Windows (Vista+) | `BCryptGenRandom` | Yes |
//! | WASM | Timestamp + xorshift | No |
//! | Other | Timestamp + xorshift | No |
//!
//! **WARNING:** On WASM and unsupported platforms, UUIDs are generated using a
//! timestamp-seeded xorshift64 PRNG that is **NOT cryptographically secure**.
//! Do not use for:
//! - Cryptographic keys or secrets
//! - Password reset tokens
//! - Security-sensitive session identifiers
//!
//! See `SECURITY.md` for full threat model and usage guidelines.
//!
//! # Examples
//!
//! ```
//! use nexcore_id::NexId;
//!
//! // Generate random v4 UUID
//! let id = NexId::v4();
//! println!("{id}"); // e.g., "550e8400-e29b-41d4-a716-446655440000"
//!
//! // Generate timestamp-based v7 UUID
//! let id = NexId::v7();
//!
//! // Parse from string
//! let id: NexId = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
// NOTE: unsafe_code is denied (not forbidden) to allow the isolated Windows FFI
// in fill_random_windows(). All other unsafe code is still rejected.
#![deny(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![cfg_attr(not(test), deny(clippy::panic))]
#![warn(missing_docs)]
#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;

use core::fmt;
use core::str::FromStr;

/// A 128-bit universally unique identifier.
///
/// Compatible with RFC 4122 UUID format. Supports v4 (random) and v7 (timestamp).
///
/// # Serialization
///
/// With the `serde` feature enabled, `NexId` serializes as a hyphenated string:
/// ```json
/// "550e8400-e29b-41d4-a716-446655440000"
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NexId([u8; 16]);

// ============================================================================
// Serde Support (optional feature)
// ============================================================================

#[cfg(feature = "serde")]
impl serde::Serialize for NexId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string_hyphenated())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NexId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NexIdVisitor;

        impl serde::de::Visitor<'_> for NexIdVisitor {
            type Value = NexId;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a UUID string (hyphenated or simple)")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(NexIdVisitor)
    }
}

/// Error returned when parsing a UUID string fails.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Input has wrong length (expected 36 chars with hyphens or 32 without)
    InvalidLength,
    /// Invalid character (not hex digit or hyphen)
    InvalidCharacter,
    /// Hyphen in wrong position
    InvalidFormat,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid UUID length"),
            Self::InvalidCharacter => write!(f, "invalid character in UUID"),
            Self::InvalidFormat => write!(f, "invalid UUID format"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

impl NexId {
    /// The nil UUID (all zeros).
    pub const NIL: Self = Self([0; 16]);

    /// The max UUID (all ones).
    pub const MAX: Self = Self([0xff; 16]);

    /// Creates a new `NexId` from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of this UUID.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns the UUID version (4 for random, 7 for timestamp).
    #[must_use]
    pub const fn version(&self) -> u8 {
        (self.0[6] >> 4) & 0x0f
    }

    /// Returns the UUID variant (should be 0b10xx for RFC 4122).
    #[must_use]
    pub const fn variant(&self) -> u8 {
        (self.0[8] >> 6) & 0x03
    }

    /// Returns true if this is the nil UUID.
    #[must_use]
    pub const fn is_nil(&self) -> bool {
        // Explicit comparison of all 16 bytes avoids indexing in const context.
        // `const fn` cannot use iterators, so each byte is checked individually.
        self.0[0] == 0
            && self.0[1] == 0
            && self.0[2] == 0
            && self.0[3] == 0
            && self.0[4] == 0
            && self.0[5] == 0
            && self.0[6] == 0
            && self.0[7] == 0
            && self.0[8] == 0
            && self.0[9] == 0
            && self.0[10] == 0
            && self.0[11] == 0
            && self.0[12] == 0
            && self.0[13] == 0
            && self.0[14] == 0
            && self.0[15] == 0
    }

    /// Generates a new random v4 UUID.
    ///
    /// # Entropy Source
    ///
    /// - **Unix:** `/dev/urandom` (CSPRNG)
    /// - **Windows:** Timestamp-seeded xorshift64 (**NOT CSPRNG**)
    /// - **Other:** Timestamp-seeded xorshift64 (**NOT CSPRNG**)
    ///
    /// # Security Warning
    ///
    /// On non-Unix platforms, the output is **predictable**. An attacker who knows
    /// the approximate generation time can enumerate possible UUIDs. Do not use
    /// for security-sensitive purposes on Windows.
    ///
    /// See `SECURITY.md` for full threat model.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn v4() -> Self {
        let mut bytes = [0u8; 16];
        fill_random(&mut bytes);

        // Set version to 4
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        // Set variant to RFC 4122
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        Self(bytes)
    }

    /// Generates a new timestamp-based v7 UUID.
    ///
    /// Combines Unix millisecond timestamp (48 bits) with random data (74 bits)
    /// for time-ordered uniqueness. UUIDs generated later have larger values.
    ///
    /// # Entropy Source
    ///
    /// Same as [`v4()`](Self::v4) — see security warnings for non-Unix platforms.
    ///
    /// # Ordering Guarantee
    ///
    /// v7 UUIDs are **coarsely** time-ordered (millisecond resolution). Within the
    /// same millisecond, ordering depends on the random component and is not
    /// guaranteed to be monotonic.
    ///
    /// # Timestamp Range
    ///
    /// Valid until year 10889 (48-bit millisecond counter from Unix epoch).
    #[cfg(feature = "std")]
    #[must_use]
    pub fn v7() -> Self {
        let mut bytes = [0u8; 16];

        // Get timestamp in milliseconds.
        // as_millis() returns u128; we truncate to u64 which holds ~584 million years
        // of milliseconds — far beyond the UUID v7 spec's 48-bit (year 10889) range.
        // Saturating at u64::MAX is safe: the upper bits are masked off anyway.
        let ts_millis: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        // Clamp to u64: values beyond u64::MAX (~584M years) are saturated safely.
        #[allow(
            clippy::as_conversions,
            reason = "ts_millis fits in u64 for any realistic timestamp: u64::MAX ms ~= 584 million years; saturating lossy cast is intentional"
        )]
        let ts = ts_millis as u64;

        // First 48 bits: timestamp bytes extracted by right-shift then truncation to u8.
        // Each shift isolates exactly 8 bits; the `as u8` discards upper bits deliberately.
        #[allow(
            clippy::as_conversions,
            reason = "byte extraction: right-shift isolates the target octet, as u8 discards upper bits intentionally"
        )]
        {
            bytes[0] = (ts >> 40) as u8;
            bytes[1] = (ts >> 32) as u8;
            bytes[2] = (ts >> 24) as u8;
            bytes[3] = (ts >> 16) as u8;
            bytes[4] = (ts >> 8) as u8;
            bytes[5] = ts as u8;
        }

        // Fill remaining with random
        let mut rand_bytes = [0u8; 10];
        fill_random(&mut rand_bytes);
        bytes[6..16].copy_from_slice(&rand_bytes);

        // Set version to 7
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        // Set variant to RFC 4122
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        Self(bytes)
    }

    /// Creates a `NexId` from a u128 value.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        Self(value.to_be_bytes())
    }

    /// Converts this `NexId` to a u128 value.
    #[must_use]
    pub const fn to_u128(&self) -> u128 {
        u128::from_be_bytes(self.0)
    }

    /// Returns the hyphenated string representation.
    #[must_use]
    pub fn to_string_hyphenated(&self) -> String {
        let mut s = String::with_capacity(36);
        for (i, byte) in self.0.iter().enumerate() {
            if i == 4 || i == 6 || i == 8 || i == 10 {
                s.push('-');
            }
            // nibble >> 4 and nibble & 0x0f are both in 0..=15, within HEX_CHARS bounds.
            let hi = usize::from(byte >> 4);
            let lo = usize::from(byte & 0x0f);
            s.push(HEX_CHARS.get(hi).copied().unwrap_or('?'));
            s.push(HEX_CHARS.get(lo).copied().unwrap_or('?'));
        }
        s
    }

    /// Returns the simple (non-hyphenated) string representation.
    #[must_use]
    pub fn to_string_simple(&self) -> String {
        let mut s = String::with_capacity(32);
        for byte in &self.0 {
            let hi = usize::from(byte >> 4);
            let lo = usize::from(byte & 0x0f);
            s.push(HEX_CHARS.get(hi).copied().unwrap_or('?'));
            s.push(HEX_CHARS.get(lo).copied().unwrap_or('?'));
        }
        s
    }
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

impl fmt::Display for NexId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_hyphenated())
    }
}

impl fmt::Debug for NexId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NexId({})", self.to_string_hyphenated())
    }
}

impl FromStr for NexId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // Support both hyphenated (36 chars) and simple (32 chars) formats
        match s.len() {
            36 => parse_hyphenated(s),
            32 => parse_simple(s),
            _ => Err(ParseError::InvalidLength),
        }
    }
}

fn parse_hyphenated(s: &str) -> Result<NexId, ParseError> {
    let bytes = s.as_bytes();

    // Verify hyphen positions: 8-4-4-4-12.
    // These indices are always valid: s.len() == 36 is checked by the caller.
    let b8 = bytes.get(8).copied().ok_or(ParseError::InvalidFormat)?;
    let b13 = bytes.get(13).copied().ok_or(ParseError::InvalidFormat)?;
    let b18 = bytes.get(18).copied().ok_or(ParseError::InvalidFormat)?;
    let b23 = bytes.get(23).copied().ok_or(ParseError::InvalidFormat)?;
    if b8 != b'-' || b13 != b'-' || b18 != b'-' || b23 != b'-' {
        return Err(ParseError::InvalidFormat);
    }

    let mut result = [0u8; 16];
    let mut byte_idx: usize = 0;

    for (i, chunk) in s.split('-').enumerate() {
        let expected_len = match i {
            0 => 8,
            1..=3 => 4,
            4 => 12,
            _ => return Err(ParseError::InvalidFormat),
        };

        if chunk.len() != expected_len {
            return Err(ParseError::InvalidFormat);
        }

        for pair in chunk.as_bytes().chunks(2) {
            let high = hex_digit(pair.first().copied().ok_or(ParseError::InvalidFormat)?)?;
            let low = hex_digit(pair.get(1).copied().ok_or(ParseError::InvalidFormat)?)?;
            let slot = result.get_mut(byte_idx).ok_or(ParseError::InvalidFormat)?;
            *slot = (high << 4) | low;
            byte_idx = byte_idx.saturating_add(1);
        }
    }

    Ok(NexId(result))
}

fn parse_simple(s: &str) -> Result<NexId, ParseError> {
    let mut result = [0u8; 16];

    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        if pair.len() != 2 {
            return Err(ParseError::InvalidLength);
        }
        let high = hex_digit(pair.first().copied().ok_or(ParseError::InvalidFormat)?)?;
        let low = hex_digit(pair.get(1).copied().ok_or(ParseError::InvalidFormat)?)?;
        let slot = result.get_mut(i).ok_or(ParseError::InvalidFormat)?;
        *slot = (high << 4) | low;
    }

    Ok(NexId(result))
}

const fn hex_digit(c: u8) -> Result<u8, ParseError> {
    match c {
        // Subtractions are bounded by match arm guards: c >= b'0' and c <= b'9',
        // so c - b'0' is in 0..=9 with no underflow possible.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "match arm guarantees c >= b'0' and c <= b'9', so subtraction cannot underflow"
        )]
        b'0'..=b'9' => Ok(c - b'0'),
        // c >= b'a' and c <= b'f', so c - b'a' is in 0..=5; adding 10 gives 10..=15, no overflow.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "match arm guarantees c in b'a'..=b'f', so c - b'a' is 0..=5 and adding 10 gives 10..=15, no overflow"
        )]
        b'a'..=b'f' => Ok(c - b'a' + 10),
        // c >= b'A' and c <= b'F', so c - b'A' is in 0..=5; adding 10 gives 10..=15, no overflow.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "match arm guarantees c in b'A'..=b'F', so c - b'A' is 0..=5 and adding 10 gives 10..=15, no overflow"
        )]
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ParseError::InvalidCharacter),
    }
}

/// Cached /dev/urandom handle for Unix systems.
#[cfg(all(feature = "std", unix))]
static URANDOM: std::sync::OnceLock<std::sync::Mutex<std::fs::File>> = std::sync::OnceLock::new();

/// Initialize the cached urandom file handle.
#[cfg(all(feature = "std", unix))]
fn init_urandom() -> std::sync::Mutex<std::fs::File> {
    use std::sync::Mutex;
    let file = std::fs::File::open("/dev/urandom").unwrap_or_else(|_| {
        std::fs::File::open("/dev/null").unwrap_or_else(|_| std::process::abort())
    });
    Mutex::new(file)
}

/// Fill buffer with random bytes using OS entropy.
///
/// # Performance
///
/// Uses a cached file handle to `/dev/urandom` on Unix, avoiding repeated
/// file open/close overhead (~2-3x speedup vs per-call open).
#[cfg(feature = "std")]
fn fill_random(buf: &mut [u8]) {
    #[cfg(unix)]
    {
        fill_random_unix(buf);
    }

    #[cfg(windows)]
    {
        fill_random_windows(buf);
    }

    #[cfg(not(any(unix, windows)))]
    {
        fallback_random(buf);
    }
}

// ============================================================================
// Windows CSPRNG via BCryptGenRandom (zero-dependency FFI)
// ============================================================================

/// Windows entropy via BCryptGenRandom (CSPRNG).
///
/// Uses `BCRYPT_USE_SYSTEM_PREFERRED_RNG` flag which allows passing NULL
/// for the algorithm handle, simplifying the implementation.
///
/// # Security
///
/// `BCryptGenRandom` is the recommended Windows CSPRNG since Vista/Server 2008.
/// It draws from the same entropy pool as `CryptGenRandom` but with a modern API.
///
/// # Fallback
///
/// If BCryptGenRandom fails (should never happen on modern Windows), falls back
/// to the weak timestamp-seeded PRNG with a warning in debug builds.
#[cfg(all(feature = "std", windows))]
fn fill_random_windows(buf: &mut [u8]) {
    // Raw FFI to bcrypt.dll - zero external dependencies
    #[link(name = "bcrypt")]
    extern "system" {
        // NTSTATUS BCryptGenRandom(
        //   BCRYPT_ALG_HANDLE hAlgorithm,  // NULL with BCRYPT_USE_SYSTEM_PREFERRED_RNG
        //   PUCHAR pbBuffer,
        //   ULONG cbBuffer,
        //   ULONG dwFlags
        // );
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    // BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
    // Allows hAlgorithm to be NULL, uses system default RNG
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    // STATUS_SUCCESS = 0x00000000
    const STATUS_SUCCESS: i32 = 0;

    // buf.len() is the byte count of a small stack buffer (16 or 10 bytes max);
    // it always fits in u32 (max value 4_294_967_295). The cast is safe.
    #[allow(
        clippy::as_conversions,
        reason = "buf is always 16 or 10 bytes (UUID-sized), well within u32::MAX; truncation is impossible"
    )]
    let buf_len = buf.len() as u32;

    // SAFETY: BCryptGenRandom is a well-documented Windows API.
    // We pass a valid buffer and length, NULL algorithm handle with the
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG flag as documented.
    #[allow(unsafe_code)] // Required for FFI, isolated to this function
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf_len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status != STATUS_SUCCESS {
        // BCryptGenRandom failed - this should never happen on modern Windows
        // Fall back to weak PRNG (better than panicking)
        #[cfg(debug_assertions)]
        eprintln!(
            "WARNING: BCryptGenRandom failed with status 0x{:08X}, using weak fallback",
            status
        );
        fallback_random(buf);
    }
}

/// Unix entropy via cached /dev/urandom handle.
#[cfg(all(feature = "std", unix))]
fn fill_random_unix(buf: &mut [u8]) {
    use std::io::Read;
    let mutex = URANDOM.get_or_init(init_urandom);
    let result = mutex.lock().map(|mut g| g.read_exact(buf));
    if result.is_err() || result.is_ok_and(|r| r.is_err()) {
        fallback_random(buf);
    }
}

/// Fallback random using timestamp and counter (not cryptographically secure).
#[cfg(feature = "std")]
#[allow(
    clippy::cast_possible_truncation,
    reason = "intentional: as_nanos() truncates u128 to u64 for xorshift seed (nanosecond precision, upper bits discarded); byte extraction via >> 56 then as u8 isolates the top byte deliberately"
)]
fn fallback_random(buf: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};

    // as_nanos() returns u128; truncating to u64 for the xorshift seed is intentional —
    // we only need nanosecond-granularity entropy, not the full 128-bit range.
    #[allow(
        clippy::as_conversions,
        reason = "truncating u128 nanoseconds to u64 for xorshift PRNG seed; upper bits are discarded intentionally as the lower 64 bits provide sufficient entropy variation"
    )]
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // Simple xorshift64 PRNG (constants from Marsaglia)
    let mut state = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);

    for byte in buf.iter_mut() {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        // >> 56 on a u64 isolates the top 8 bits into positions 0..=7; as u8 is exact.
        #[allow(
            clippy::as_conversions,
            reason = "state >> 56 produces a value in 0..=255 (top byte of u64), so as u8 is a lossless truncation"
        )]
        {
            *byte = (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8;
        }
    }
}

impl Default for NexId {
    fn default() -> Self {
        Self::NIL
    }
}

impl From<[u8; 16]> for NexId {
    fn from(bytes: [u8; 16]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<NexId> for [u8; 16] {
    fn from(id: NexId) -> Self {
        id.0
    }
}

impl From<u128> for NexId {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl From<NexId> for u128 {
    fn from(id: NexId) -> Self {
        id.to_u128()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nil() {
        assert!(NexId::NIL.is_nil());
        assert!(!NexId::MAX.is_nil());
    }

    #[test]
    fn test_v4_version() {
        let id = NexId::v4();
        assert_eq!(id.version(), 4);
        assert_eq!(id.variant(), 2); // 0b10
    }

    #[test]
    fn test_v7_version() {
        let id = NexId::v7();
        assert_eq!(id.version(), 7);
        assert_eq!(id.variant(), 2); // 0b10
    }

    #[test]
    fn test_v7_ordering() {
        let id1 = NexId::v7();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = NexId::v7();
        assert!(id1 < id2, "v7 UUIDs should be time-ordered");
    }

    #[test]
    fn test_parse_hyphenated() {
        let s = "550e8400-e29b-41d4-a716-446655440000";
        let id: NexId = s.parse().unwrap();
        assert_eq!(id.to_string(), s);
    }

    #[test]
    fn test_parse_simple() {
        let s = "550e8400e29b41d4a716446655440000";
        let id: NexId = s.parse().unwrap();
        assert_eq!(id.to_string_simple(), s);
    }

    #[test]
    fn test_roundtrip() {
        let original = NexId::v4();
        let s = original.to_string();
        let parsed: NexId = s.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_u128_conversion() {
        let value: u128 = 0x550e8400_e29b_41d4_a716_446655440000;
        let id = NexId::from_u128(value);
        assert_eq!(id.to_u128(), value);
    }

    #[test]
    fn test_uniqueness() {
        let ids: Vec<NexId> = (0..1000).map(|_| NexId::v4()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len(), "All v4 IDs should be unique");
    }
}

/// Serde serialization tests (only compiled with serde feature).
#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn test_serialize_json() {
        let id: NexId = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"550e8400-e29b-41d4-a716-446655440000\"");
    }

    #[test]
    fn test_deserialize_json_hyphenated() {
        let json = "\"550e8400-e29b-41d4-a716-446655440000\"";
        let id: NexId = serde_json::from_str(json).unwrap();
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_deserialize_json_simple() {
        let json = "\"550e8400e29b41d4a716446655440000\"";
        let id: NexId = serde_json::from_str(json).unwrap();
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = NexId::v4();
        let json = serde_json::to_string(&original).unwrap();
        let restored: NexId = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn test_deserialize_invalid() {
        let result: Result<NexId, _> = serde_json::from_str("\"not-a-uuid\"");
        assert!(result.is_err());
    }
}

/// NIST SP 800-22 mathematical helpers.
#[cfg(test)]
mod nist_math {
    /// Horner's method polynomial evaluation for erfc.
    fn erfc_poly(t: f64) -> f64 {
        let c = [
            0.170_872_77,
            -0.822_152_23,
            1.488_515_87,
            -1.135_203_98,
            0.278_868_07,
            -0.186_288_06,
            0.096_784_18,
            0.374_091_96,
            1.000_023_68,
            -1.265_512_23,
        ];
        let mut result = c[0];
        for &coef in &c[1..] {
            result = result * t + coef;
        }
        result
    }

    /// Complementary error function for p-value calculation.
    pub fn erfc(x: f64) -> f64 {
        let t = 1.0 / (1.0 + 0.5 * x.abs());
        let tau = t * (-x * x + erfc_poly(t)).exp();
        if x >= 0.0 { tau } else { 2.0 - tau }
    }

    /// Log-gamma via Lanczos approximation.
    pub fn ln_gamma(x: f64) -> f64 {
        let c = [
            76.180_091_729_471_46,
            -86.505_320_329_416_77,
            24.014_098_240_830_91,
            -1.231_739_572_450_155,
            0.001_208_650_973_866_179,
            -0.000_005_395_239_384_953,
        ];
        let y = x - 1.0;
        let mut sum = 1.000_000_000_190_015;
        for (i, &coef) in c.iter().enumerate() {
            // i is 0..=5 (array length 6), converting to f64 is exact and lossless.
            #[allow(
                clippy::as_conversions,
                reason = "i is 0..=5 from a fixed-length array iteration; f64 represents all integers up to 2^53 exactly"
            )]
            let i_f64 = i as f64;
            sum += coef / (y + i_f64 + 1.0);
        }
        let t = y + 5.5;
        0.5 * (2.0 * core::f64::consts::PI).ln() + (y + 0.5) * t.ln() - t + sum.ln()
    }

    /// Incomplete gamma Q(a,x) for chi-squared p-values.
    pub fn igamc(a: f64, x: f64) -> f64 {
        if x < 0.0 || a <= 0.0 {
            return 1.0;
        }
        if x < a + 1.0 {
            1.0 - igam_series(a, x)
        } else {
            igam_cf(a, x)
        }
    }

    fn igam_series(a: f64, x: f64) -> f64 {
        if x == 0.0 {
            return 0.0;
        }
        let mut sum = 1.0 / a;
        let mut term = sum;
        for n in 1..200 {
            // n is 1..200 (i32 range); converting to f64 is exact for all values <= 2^53.
            #[allow(
                clippy::as_conversions,
                reason = "n is 1..200, well within f64's exact integer range of 2^53"
            )]
            let n_f64 = n as f64;
            term *= x / (a + n_f64);
            sum += term;
            if term.abs() < sum.abs() * 1e-14 {
                break;
            }
        }
        sum * (-x + a * x.ln() - ln_gamma(a)).exp()
    }

    fn igam_cf(a: f64, x: f64) -> f64 {
        let mut f = 1e-30_f64;
        let mut c = 1e-30_f64;
        for n in 1..200 {
            let an = compute_an(n, a);
            // n is 1..200; converting to f64 is exact for all values <= 2^53.
            #[allow(
                clippy::as_conversions,
                reason = "n is 1..200, well within f64's exact integer range of 2^53"
            )]
            let n_f64 = n as f64;
            let bn = x + n_f64 - a;
            let d = clamp_small(1.0 / clamp_small(bn + an / f));
            c = clamp_small(bn + an / c);
            let delta = c * d;
            f *= delta;
            if (delta - 1.0).abs() < 1e-14 {
                break;
            }
        }
        (-x + a * x.ln() - ln_gamma(a)).exp() / f
    }

    fn compute_an(n: i32, a: f64) -> f64 {
        // n is 1..200 (i32); converting to f64 is exact.
        #[allow(
            clippy::as_conversions,
            reason = "n is 1..200 (i32), converting to f64 is exact; all values <= 2^53"
        )]
        if n % 2 == 1 {
            (n as f64 + 1.0) / 2.0
        } else {
            -(n as f64 / 2.0 - a)
        }
    }

    fn clamp_small(x: f64) -> f64 {
        if x.abs() < 1e-30 { 1e-30 } else { x }
    }
}

/// NIST SP 800-22 randomness tests.
#[cfg(test)]
mod nist_sp800_22 {
    use super::*;
    use nist_math::{erfc, igamc};

    const SAMPLE_BITS: usize = 100_000;
    const ALPHA: f64 = 0.01;

    fn collect_random_bits(n_bits: usize) -> Vec<u8> {
        let mut bits = Vec::with_capacity(n_bits);
        while bits.len() < n_bits {
            let id = NexId::v4();
            append_uuid_bits(id.as_bytes(), &mut bits, n_bits);
        }
        bits
    }

    fn append_uuid_bits(bytes: &[u8; 16], bits: &mut Vec<u8>, limit: usize) {
        for (i, &byte) in bytes.iter().enumerate() {
            append_byte_bits(byte, i, bits, limit);
        }
    }

    fn append_byte_bits(byte: u8, byte_idx: usize, bits: &mut Vec<u8>, limit: usize) {
        for bit_idx in 0..8 {
            if bits.len() >= limit {
                return;
            }
            let is_version = byte_idx == 6 && bit_idx >= 4;
            let is_variant = byte_idx == 8 && bit_idx >= 6;
            if !is_version && !is_variant {
                bits.push((byte >> bit_idx) & 1);
            }
        }
    }

    #[test]
    fn test_frequency_monobit() {
        let bits = collect_random_bits(SAMPLE_BITS);
        let p = frequency_monobit_pvalue(&bits);
        assert!(p >= ALPHA, "Frequency test FAILED: p={p:.6}");
    }

    fn frequency_monobit_pvalue(bits: &[u8]) -> f64 {
        // bits.len() is at most SAMPLE_BITS = 100_000, losslessly representable in f64.
        #[allow(
            clippy::as_conversions,
            reason = "bits.len() <= 100_000 which is exactly representable in f64 (< 2^53)"
        )]
        let n = bits.len() as f64;
        let s_n: i64 = bits
            .iter()
            .map(|&b| if b == 1 { 1i64 } else { -1i64 })
            .sum();
        // s_n is in -100_000..=100_000; converting to f64 is exact.
        #[allow(
            clippy::as_conversions,
            reason = "s_n is bounded by bits.len() <= 100_000, well within f64's exact integer range"
        )]
        let s_obs = (s_n as f64).abs() / n.sqrt();
        erfc(s_obs / core::f64::consts::SQRT_2)
    }

    #[test]
    fn test_frequency_block() {
        let bits = collect_random_bits(SAMPLE_BITS);
        let p = block_frequency_pvalue(&bits, 100);
        assert!(p >= ALPHA, "Block frequency FAILED: p={p:.6}");
    }

    fn block_frequency_pvalue(bits: &[u8], block_size: usize) -> f64 {
        let n_blocks = bits.len() / block_size;
        let chi_sq = block_chi_squared(bits, block_size, n_blocks);
        // n_blocks <= 1_000 (100_000 / 100), exactly representable in f64.
        #[allow(
            clippy::as_conversions,
            reason = "n_blocks <= 1_000, well within f64's exact integer range of 2^53"
        )]
        let n_blocks_f64 = n_blocks as f64;
        igamc(n_blocks_f64 / 2.0, chi_sq / 2.0)
    }

    fn block_chi_squared(bits: &[u8], m: usize, n: usize) -> f64 {
        let mut chi_sq = 0.0;
        for i in 0..n {
            let ones: usize = bits
                .get(i.saturating_mul(m)..i.saturating_mul(m).saturating_add(m))
                .map(|sl| sl.iter().map(|&b| usize::from(b)).sum())
                .unwrap_or(0);
            // ones <= m <= SAMPLE_BITS = 100_000, exactly representable in f64.
            // m <= SAMPLE_BITS = 100_000, exactly representable in f64.
            #[allow(
                clippy::as_conversions,
                reason = "ones and m are both bounded by SAMPLE_BITS = 100_000, well within f64's exact integer range"
            )]
            let pi = ones as f64 / m as f64;
            chi_sq += (pi - 0.5).powi(2);
        }
        // m <= 100_000, exactly representable in f64.
        #[allow(
            clippy::as_conversions,
            reason = "m <= SAMPLE_BITS = 100_000, well within f64's exact integer range of 2^53"
        )]
        {
            chi_sq * 4.0 * m as f64
        }
    }

    #[test]
    fn test_runs() {
        let bits = collect_random_bits(SAMPLE_BITS);
        let p = runs_pvalue(&bits);
        if let Some(pval) = p {
            assert!(pval >= ALPHA, "Runs test FAILED: p={pval:.6}");
        }
    }

    fn runs_pvalue(bits: &[u8]) -> Option<f64> {
        // bits.len() <= 100_000, exactly representable in f64.
        #[allow(
            clippy::as_conversions,
            reason = "bits.len() <= 100_000, well within f64's exact integer range of 2^53"
        )]
        let n = bits.len() as f64;
        let ones: usize = bits.iter().map(|&b| usize::from(b)).sum();
        // ones <= 100_000, exactly representable in f64.
        #[allow(
            clippy::as_conversions,
            reason = "ones <= bits.len() <= 100_000, well within f64's exact integer range"
        )]
        let pi = ones as f64 / n;
        let tau = 2.0 / n.sqrt();
        if (pi - 0.5).abs() >= tau {
            return None;
        }
        let v_obs = count_transitions(bits).saturating_add(1);
        let expected = 2.0 * n * pi * (1.0 - pi) + 1.0;
        let variance = 2.0 * n * pi * (1.0 - pi);
        // v_obs <= SAMPLE_BITS + 1 = 100_001, exactly representable in f64.
        #[allow(
            clippy::as_conversions,
            reason = "v_obs <= SAMPLE_BITS + 1 = 100_001, well within f64's exact integer range of 2^53"
        )]
        let z = (v_obs as f64 - expected).abs() / (2.0 * variance).sqrt();
        Some(erfc(z / core::f64::consts::SQRT_2))
    }

    fn count_transitions(bits: &[u8]) -> u64 {
        // count() returns usize; on any realistic platform this fits in u64.
        #[allow(
            clippy::as_conversions,
            reason = "transition count is bounded by bits.len() <= 100_000, well within u64::MAX"
        )]
        {
            bits.windows(2).filter(|w| w[0] != w[1]).count() as u64
        }
    }

    #[test]
    fn test_bit_independence() {
        let bits = collect_random_bits(SAMPLE_BITS);
        let p = independence_pvalue(&bits);
        assert!(p >= ALPHA, "Independence FAILED: p={p:.6}");
    }

    fn independence_pvalue(bits: &[u8]) -> f64 {
        let counts = count_bit_pairs(bits);
        // bits.len() - 1 is at most 99_999, exactly representable in f64.
        #[allow(
            clippy::as_conversions,
            reason = "bits.len() <= 100_000, so bits.len() - 1 <= 99_999, well within f64's exact integer range"
        )]
        let total = (bits.len() - 1) as f64;
        let expected = total / 4.0;
        let chi_sq = chi_squared_from_counts(&counts, expected);
        igamc(1.5, chi_sq / 2.0)
    }

    fn count_bit_pairs(bits: &[u8]) -> [u64; 4] {
        let mut c = [0u64; 4];
        for w in bits.windows(2) {
            // w[0] and w[1] are bits (0 or 1); index is 0*2+0=0, 0*2+1=1, 1*2+0=2, 1*2+1=3.
            // These are known safe: w is always length 2 from windows(2).
            let idx = usize::from(w[0]) * 2 + usize::from(w[1]);
            if let Some(slot) = c.get_mut(idx) {
                *slot = slot.saturating_add(1);
            }
        }
        c
    }

    fn chi_squared_from_counts(counts: &[u64; 4], expected: f64) -> f64 {
        counts
            .iter()
            // c is a u64 count bounded by SAMPLE_BITS; converting to f64 is exact.
            .map(|&c| {
                #[allow(clippy::as_conversions, reason = "c is a window count bounded by SAMPLE_BITS = 100_000, well within f64's exact integer range of 2^53")]
                let c_f64 = c as f64;
                (c_f64 - expected).powi(2) / expected
            })
            .sum()
    }
}
