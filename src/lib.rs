//! # rsa-wasm-signatures
//!
//! Fast RSA PKCS#1 v1.5 signatures over SHA-256 for WebAssembly/WASI.
//!
//! The heavy lifting — CRT modular exponentiation with Montgomery arithmetic — is
//! done by a Zig implementation shipped as a precompiled static library, so the
//! crate has no runtime dependencies and signs as fast as the standalone Zig
//! signer it was lifted from. Three modulus sizes are supported, one module each:
//! [`rsa2048`], [`rsa3072`] and [`rsa4096`].
//!
//! A signing key is built from its CRT components (the two primes, both CRT
//! exponents and the coefficient), exactly the values found in a PKCS#1 private
//! key. Verification takes the public modulus and exponent.
//!
//! ```no_run
//! use rsa_wasm_signatures::rsa2048::{SecretKey, PublicKey};
//!
//! # fn run(p: &[u8], q: &[u8], dp: &[u8], dq: &[u8], qinv: &[u8], n: &[u8]) -> Result<(), rsa_wasm_signatures::Error> {
//! let sk = SecretKey::from_components(p, q, dp, dq, qinv)?;
//! let signature = sk.sign(b"message to sign");
//!
//! let pk = PublicKey::new(n, 65537)?;
//! pk.verify(b"message to sign", &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! > This crate targets WASI, not native or browser environments. The signing
//! > code relies on the WebAssembly wide-arithmetic proposal, so the runtime must
//! > enable it (for example `wasmtime -W wide-arithmetic=y`).

#![forbid(unsafe_op_in_unsafe_fn)]

use core::fmt::{self, Display};

/// Errors returned by key construction and signature verification.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// A key component did not fit the modulus size, or the public key was malformed.
    InvalidKey,
    /// The signature did not verify against the message and public key.
    VerificationFailed,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKey => write!(f, "Invalid key"),
            Error::VerificationFailed => write!(f, "Verification failed"),
        }
    }
}

macro_rules! rsa_module {
    (
        $(#[$meta:meta])*
        $name:ident, $bits:literal, $siglen:literal, $primelen:literal,
        $key_bytes:ident, $key_init:ident, $sign:ident, $verify:ident
    ) => {
        $(#[$meta])*
        pub mod $name {
            use crate::Error;

            mod zig {
                extern "C" {
                    pub fn $key_bytes() -> usize;
                    pub fn $key_init(
                        out: *mut u8,
                        p: *const u8, p_len: usize,
                        q: *const u8, q_len: usize,
                        dp: *const u8, dp_len: usize,
                        dq: *const u8, dq_len: usize,
                        qinv: *const u8, qinv_len: usize,
                    ) -> i32;
                    pub fn $sign(sig: *mut u8, key: *const u8, msg: *const u8, msg_len: usize);
                    pub fn $verify(
                        n: *const u8, n_len: usize, e: u64,
                        msg: *const u8, msg_len: usize,
                        sig: *const u8, sig_len: usize,
                    ) -> i32;
                }
            }

            /// Modulus size in bits.
            pub const MODULUS_BITS: usize = $bits;
            /// Signature length in bytes (the modulus size in bytes).
            pub const SIGNATURE_LEN: usize = $siglen;
            /// Maximum length in bytes of each CRT key component (`p`, `q`, `dp`, `dq`, `qinv`).
            pub const COMPONENT_LEN: usize = $primelen;

            /// An RSA private key in CRT form, ready to sign.
            ///
            /// The Montgomery constants derived from the key are computed once, when
            /// the key is built, so repeated [`SecretKey::sign`] calls only pay for
            /// the modular exponentiation itself.
            #[derive(Clone)]
            pub struct SecretKey {
                words: Vec<u64>,
            }

            impl SecretKey {
                /// Builds a signing key from its CRT components as big-endian bytes:
                /// the primes `p` and `q`, the CRT exponents `dp = d mod (p-1)` and
                /// `dq = d mod (q-1)`, and the coefficient `qinv = q^-1 mod p`.
                ///
                /// Leading zero bytes are accepted. Returns [`Error::InvalidKey`] if
                /// any component is longer than [`COMPONENT_LEN`].
                pub fn from_components(
                    p: impl AsRef<[u8]>,
                    q: impl AsRef<[u8]>,
                    dp: impl AsRef<[u8]>,
                    dq: impl AsRef<[u8]>,
                    qinv: impl AsRef<[u8]>,
                ) -> Result<Self, Error> {
                    let (p, q, dp, dq, qinv) =
                        (p.as_ref(), q.as_ref(), dp.as_ref(), dq.as_ref(), qinv.as_ref());
                    for component in [p, q, dp, dq, qinv] {
                        if component.len() > COMPONENT_LEN {
                            return Err(Error::InvalidKey);
                        }
                    }
                    let words_len = unsafe { zig::$key_bytes() }.div_ceil(8);
                    let mut words = vec![0u64; words_len];
                    let rc = unsafe {
                        zig::$key_init(
                            words.as_mut_ptr() as *mut u8,
                            p.as_ptr(), p.len(),
                            q.as_ptr(), q.len(),
                            dp.as_ptr(), dp.len(),
                            dq.as_ptr(), dq.len(),
                            qinv.as_ptr(), qinv.len(),
                        )
                    };
                    if rc != 0 {
                        return Err(Error::InvalidKey);
                    }
                    Ok(SecretKey { words })
                }

                /// Signs a message with PKCS#1 v1.5 padding over its SHA-256 digest.
                ///
                /// The message is hashed internally; the result is a
                /// [`SIGNATURE_LEN`]-byte big-endian signature.
                pub fn sign(&self, msg: impl AsRef<[u8]>) -> [u8; SIGNATURE_LEN] {
                    let msg = msg.as_ref();
                    let mut sig = [0u8; SIGNATURE_LEN];
                    unsafe {
                        zig::$sign(
                            sig.as_mut_ptr(),
                            self.words.as_ptr() as *const u8,
                            msg.as_ptr(),
                            msg.len(),
                        );
                    }
                    sig
                }
            }

            impl core::fmt::Debug for SecretKey {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.debug_struct("SecretKey").finish_non_exhaustive()
                }
            }

            /// An RSA public key: the modulus `n` and the public exponent `e`.
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub struct PublicKey {
                n: Vec<u8>,
                e: u64,
            }

            impl PublicKey {
                /// Builds a public key from the modulus `n` as big-endian bytes and
                /// the public exponent `e` (commonly `65537`).
                ///
                /// Returns [`Error::InvalidKey`] if `n` is empty, longer than
                /// [`SIGNATURE_LEN`] bytes, or if `e` is zero.
                pub fn new(n: impl AsRef<[u8]>, e: u64) -> Result<Self, Error> {
                    let n = n.as_ref();
                    if n.is_empty() || n.len() > SIGNATURE_LEN || e == 0 {
                        return Err(Error::InvalidKey);
                    }
                    Ok(PublicKey { n: n.to_vec(), e })
                }

                /// Verifies a PKCS#1 v1.5 + SHA-256 signature over `msg`.
                ///
                /// Returns `Ok(())` if the signature is valid, or
                /// [`Error::VerificationFailed`] otherwise.
                pub fn verify(
                    &self,
                    msg: impl AsRef<[u8]>,
                    sig: impl AsRef<[u8]>,
                ) -> Result<(), Error> {
                    let (msg, sig) = (msg.as_ref(), sig.as_ref());
                    if sig.len() != SIGNATURE_LEN {
                        return Err(Error::VerificationFailed);
                    }
                    let ok = unsafe {
                        zig::$verify(
                            self.n.as_ptr(), self.n.len(), self.e,
                            msg.as_ptr(), msg.len(),
                            sig.as_ptr(), sig.len(),
                        )
                    };
                    if ok == 1 {
                        Ok(())
                    } else {
                        Err(Error::VerificationFailed)
                    }
                }
            }
        }
    };
}

rsa_module!(
    /// RSA-2048 signing and verification.
    rsa2048, 2048, 256, 128,
    rsa2048_key_bytes, rsa2048_key_init, rsa2048_sign, rsa2048_verify
);

rsa_module!(
    /// RSA-3072 signing and verification.
    rsa3072, 3072, 384, 192,
    rsa3072_key_bytes, rsa3072_key_init, rsa3072_sign, rsa3072_verify
);

rsa_module!(
    /// RSA-4096 signing and verification.
    rsa4096, 4096, 512, 256,
    rsa4096_key_bytes, rsa4096_key_init, rsa4096_sign, rsa4096_verify
);

#[cfg(test)]
mod test;
