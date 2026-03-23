# Security Policy for `nexcore-id`

> Zero-dependency UUID implementation for supply chain sovereignty.

## Threat Model

### What `nexcore-id` Protects Against

| Threat | Mitigation |
|--------|------------|
| **Supply chain attacks** | Zero external dependencies. All code auditable in-tree. |
| **UUID collision** | 122 random bits → p(collision) < 10⁻²⁰ for 1B IDs |
| **UUID predictability (Unix)** | Uses `/dev/urandom` (CSPRNG) |
| **Time-ordering attacks (v7)** | 48-bit millisecond timestamp + 74 random bits |

### What `nexcore-id` Does NOT Protect Against

| Threat | Status | Recommendation |
|--------|--------|----------------|
| **Predictability on Windows** | ⚠️ VULNERABLE | Fallback uses timestamp-seeded xorshift. Do not use for secrets. |
| **Predictability on WASM** | ⚠️ VULNERABLE | No entropy source. Do not use in browsers. |
| **Entropy exhaustion** | ⚠️ SILENT FALLBACK | If `/dev/urandom` fails, silently degrades to xorshift. |
| **Kernel entropy pool depletion** | Not mitigated | Relies on OS guarantees post-boot. |
| **VM snapshot/restore** | Partially mitigated | Use `v7()` for better entropy across restores (timestamp component). |

## Entropy Sources by Platform

| Platform | Source | CSPRNG | Notes |
|----------|--------|--------|-------|
| **Linux** | `/dev/urandom` | ✅ Yes | Non-blocking, seeded from kernel entropy pool |
| **macOS** | `/dev/urandom` | ✅ Yes | Backed by Fortuna CSPRNG |
| **FreeBSD/OpenBSD** | `/dev/urandom` | ✅ Yes | Arc4random-based |
| **Windows** | Timestamp + xorshift | ❌ No | **INSECURE** - predictable output |
| **WASM** | None | ❌ No | **UNUSABLE** - no entropy available |
| **Other Unix** | `/dev/urandom` | ✅ Likely | Depends on OS implementation |

## Security Classification

```
┌─────────────────────────────────────────────────────────────┐
│                    USAGE CLASSIFICATION                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ✅ SAFE for:                                                │
│     • Correlation IDs (logs, traces, events)                │
│     • Database primary keys                                  │
│     • Cache keys                                             │
│     • Non-security-critical identifiers                     │
│     • Testing and development                                │
│                                                              │
│  ⚠️  CONDITIONAL for:                                        │
│     • Session identifiers (Unix only, with TLS)             │
│     • API tokens (Unix only, combine with HMAC)             │
│                                                              │
│  ❌ UNSAFE for:                                               │
│     • Cryptographic key generation                          │
│     • Password reset tokens                                  │
│     • Any secret requiring unpredictability on Windows      │
│     • Browser-based applications (WASM)                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## API Security Properties

| Method | Entropy Source | Security Level |
|--------|----------------|----------------|
| `NexId::v4()` | Best available (CSPRNG or fallback) | Platform-dependent |
| `NexId::v7()` | Timestamp + best available random | Platform-dependent |
| `NexId::from_bytes()` | User-provided | User responsibility |
| `NexId::from_u128()` | User-provided | User responsibility |
| `NexId::NIL` | Constant | None (deterministic) |

## Known Limitations

### 1. Silent Fallback (CRITICAL)

When `/dev/urandom` is unavailable (chroot, permissions, unusual OS), the implementation silently falls back to timestamp-seeded xorshift64:

```rust
// Current behavior - NO WARNING
if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
    let _ = file.read_exact(buf);
    return;
}
fallback_random(buf);  // Silently uses weak PRNG
```

**Implication:** Callers cannot detect when CSPRNG is unavailable. UUIDs may be predictable without any indication.

**Planned fix:** Add `v4_secure() -> Result<NexId, EntropyError>` that fails rather than falls back.

### 2. Xorshift64 Is Not Cryptographically Secure

The fallback PRNG uses xorshift64 with constants from Marsaglia:
- State space: 64 bits (not 128)
- Seeded from: `SystemTime::now().as_nanos()`
- Period: 2⁶⁴ - 1

An attacker who knows the approximate generation time (±1 second) can enumerate ~10⁹ possible seeds and predict all subsequent UUIDs.

### 3. No Constant-Time Comparison

`PartialEq` uses standard byte comparison, which is not constant-time. Do not use `NexId` equality checks in security-sensitive contexts where timing attacks are possible.

## Audit Preparation

### Evidence of Security Claims

| Claim | Evidence | Status |
|-------|----------|--------|
| Zero dependencies | `Cargo.toml` has empty `[dependencies]` | ✅ Verified |
| Bit distribution uniformity | Gap analysis trial (10K samples, 45-55% per bit) | ✅ Verified |
| Thread safety | 80K concurrent IDs, 0 collisions | ✅ Verified |
| v7 timestamp integrity | Extracted timestamp matches system time | ✅ Verified |
| NIST SP 800-22 compliance | 4 tests (monobit, block freq, runs, independence) | ✅ Verified |
| Windows CSPRNG | Not implemented | ❌ Missing |

### Recommended Audit Scope

1. **Entropy source verification** - Confirm `/dev/urandom` usage on Unix
2. **Fallback path analysis** - Assess xorshift predictability
3. **Version/variant bit manipulation** - Confirm RFC 4122 compliance
4. **No unsafe code** - Verify `#![forbid(unsafe_code)]` is enforced

## Vulnerability Reporting

Report security vulnerabilities to: **security@nexvigilant.com**

- Do not open public GitHub issues for security vulnerabilities
- Include: affected versions, reproduction steps, impact assessment
- Expected response time: 48 hours

## Version History

| Version | Security Changes |
|---------|------------------|
| 0.1.0 | Initial release. Unix CSPRNG, fallback on other platforms. |

## References

- [RFC 4122](https://tools.ietf.org/html/rfc4122) - UUID specification
- [RFC 9562](https://tools.ietf.org/html/rfc9562) - UUID v7 specification
- [NIST SP 800-22](https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final) - Randomness testing
- [/dev/urandom myths](https://www.2uo.de/myths-about-urandom/) - Why urandom is safe
