# rsa-wasm-signatures

Fast RSA PKCS#1 v1.5 signatures over SHA-256 for WebAssembly/WASI.

> This crate is for WASI, not native or browser builds.
> By default, the inner loop uses the WebAssembly wide-arithmetic proposal, so
> you'll need to enable it in your runtime, for example `wasmtime -W wide-arithmetic=y`.
> Without it, the module won't even validate.
>
> If your runtime doesn't support the proposal, enable the
> [`no-wide-arithmetic`](#running-on-runtimes-without-wide-arithmetic) feature.
> It links a slower archive that runs anywhere.

## What it does

- PKCS#1 v1.5 signing and verification over SHA-256.
- Three modulus sizes, with one module for each:
  - `rsa2048`
  - `rsa3072`
  - `rsa4096`
- You build keys from their CRT components, the same values you'd find in a PKCS#1
  private key, so the crate doesn't parse or generate keys.

You'll need to supply your key material as raw big-endian bytes.
The crate doesn't:

- Generate keys.
- Parse DER/PEM.
- Implement PSS.

## Running on runtimes without wide-arithmetic

The default archive uses the WebAssembly wide-arithmetic proposal, so it won't
validate if your runtime doesn't support it.
Older runtimes, or those that take longer to adopt new proposals, don't implement it yet.
If you're using one of those, turn on the `no-wide-arithmetic` feature:

```toml
[dependencies]
rsa-wasm-signatures = { version = "0.2", features = ["no-wide-arithmetic"] }
```

This links a second precompiled archive built without the feature.
The Montgomery inner loop then builds its 64×64→128 products from plain `i64.mul`,
so the module validates and runs on any wasm runtime, with no `-W wide-arithmetic=y` required.

The trade-off? Signing is roughly 2.8–3× slower.

| Size | sign (default) | sign (`no-wide-arithmetic`) |
| ---- | -------------: | --------------------------: |
| 2048 |        0.38 ms |                     1.18 ms |
| 3072 |        1.39 ms |                     4.06 ms |
| 4096 |        3.50 ms |                     9.81 ms |

Both builds produce identical signatures.
Only the speed and runtime requirement differ.

## Usage

To sign a message, you need five CRT components:

- The primes `p` and `q`.
- The CRT exponents `dp = d mod (p-1)` and `dq = d mod (q-1)`.
- The coefficient `qinv = q⁻¹ mod p`.

To verify a signature, you need the modulus `n` and public exponent `e`.

```rust
use rsa_wasm_signatures::rsa2048::{SecretKey, PublicKey};

let sk = SecretKey::from_components(&p, &q, &dp, &dq, &qinv)?;
let signature = sk.sign(b"message to sign");

let pk = PublicKey::new(&n, 65537)?;
pk.verify(b"message to sign", &signature)?;
```

The crate hashes your message with SHA-256 internally.
`sign` returns a fixed-size array (`[u8; 256]` for RSA-2048).
`verify` returns `Ok(())` or `Error::VerificationFailed`.

## Building the static library

Both compiled archives are committed, so you don't need a Zig toolchain to build the crate.
The crate ships both:

- `wasm-libs/librsa.a`, with wide-arithmetic, used by default.
- `wasm-libs/librsa_nowide.a`, without wide-arithmetic, used by the
  `no-wide-arithmetic` feature.

If you change the Zig sources, here's how to rebuild the archives:

```sh
cd wasm-libs
zig build                              # produces zig-out/lib/librsa.a
cp zig-out/lib/librsa.a librsa.a
zig build -Dwide-arithmetic=false      # produces zig-out/lib/librsa_nowide.a
cp zig-out/lib/librsa_nowide.a librsa_nowide.a
zig build test                         # native sign/verify correctness tests
```
