# rsa-wasm-signatures

Fast RSA PKCS#1 v1.5 signatures (over SHA-256) for WebAssembly/WASI.

> This crate targets WASI, not native or browser builds. By default the hot loop
> uses the WebAssembly wide-arithmetic proposal, so the runtime has to enable it —
> for example `wasmtime -W wide-arithmetic=y`. Without it the module will not even
> validate. If you have to run on a runtime that does not implement the proposal,
> enable the [`no-wide-arithmetic`](#running-on-runtimes-without-wide-arithmetic)
> feature, which links a slower archive that runs anywhere.

## What it does

- PKCS#1 v1.5 signing and verification over SHA-256.
- Three modulus sizes, one module each: `rsa2048`, `rsa3072`, `rsa4096`.
- Keys are built from their CRT components — the same values you find in a PKCS#1
  private key — so no key parsing or generation lives in this crate.

It does not generate keys, parse DER/PEM, or implement PSS. Bring your own key
material as raw big-endian bytes.

## Running on runtimes without wide-arithmetic

The default archive uses the WebAssembly wide-arithmetic proposal and will not
validate on a runtime that lacks it. Older or more conservative runtimes do not
implement it yet. For those, turn on the `no-wide-arithmetic` feature:

```toml
[dependencies]
rsa-wasm-signatures = { version = "0.1", features = ["no-wide-arithmetic"] }
```

This links a second precompiled archive built without the feature. The Montgomery
inner loop then synthesizes its 64×64→128 products from plain `i64.mul`, so the
module validates and runs on any wasm runtime — no `-W wide-arithmetic=y` required.
The trade-off is speed: signing is roughly 2.8–3× slower.

| Size | sign (default) | sign (`no-wide-arithmetic`) |
| ---- | -------------: | --------------------------: |
| 2048 |        0.38 ms |                     1.18 ms |
| 3072 |        1.39 ms |                     4.06 ms |
| 4096 |        3.50 ms |                     9.81 ms |

The default and the no-wide build produce identical signatures; only the
performance and the runtime requirement differ.

## Usage

Signing takes the five CRT components: the primes `p` and `q`, the CRT exponents
`dp = d mod (p-1)` and `dq = d mod (q-1)`, and the coefficient `qinv = q⁻¹ mod p`.
Verification takes the modulus `n` and the public exponent `e`.

```rust
use rsa_wasm_signatures::rsa2048::{SecretKey, PublicKey};

let sk = SecretKey::from_components(&p, &q, &dp, &dq, &qinv)?;
let signature = sk.sign(b"message to sign");

let pk = PublicKey::new(&n, 65537)?;
pk.verify(b"message to sign", &signature)?;
```

The message is hashed internally with SHA-256. `sign` returns a fixed-size array
(`[u8; 256]` for RSA-2048), and `verify` returns `Ok(())` or
`Error::VerificationFailed`.

## Performance

PKCS#1 v1.5 + SHA-256, measured under Wasmtime with wide-arithmetic enabled. Key
setup is one-time and excluded from the per-signature figure, so this is pure
exponentiation. The "Zig baseline" column is the standalone
[rsa-wasm](https://github.com/dip-proto/rsa-wasm) signer timed on the same host;
the per-signature machine code is identical, and the numbers track within noise.

| Size | sign (this crate) | sign (Zig baseline) | verify |
| ---- | ----------------: | ------------------: | -----: |
| 2048 |          0.38 ms  |            0.38 ms  | 0.07 ms |
| 3072 |          1.39 ms  |            1.38 ms  | 0.15 ms |
| 4096 |          3.49 ms  |            3.47 ms  | 0.27 ms |

Run them yourself with `cargo bench`.

## Building the static library

Both compiled archives are committed, so building the crate needs no Zig
toolchain. Two archives ship side by side: `wasm-libs/librsa.a` (with
wide-arithmetic, the default) and `wasm-libs/librsa_nowide.a` (without, used by the
`no-wide-arithmetic` feature). To rebuild them from the Zig sources after a change:

```sh
cd wasm-libs
zig build                              # produces zig-out/lib/librsa.a
cp zig-out/lib/librsa.a librsa.a
zig build -Dwide-arithmetic=false      # produces zig-out/lib/librsa_nowide.a
cp zig-out/lib/librsa_nowide.a librsa_nowide.a
zig build test                         # native sign/verify correctness tests
```
