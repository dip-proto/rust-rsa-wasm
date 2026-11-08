//! # rsa-wasm-signatures
//!
//! Fast RSA PKCS#1 v1.5 signatures over SHA-256 for WebAssembly/WASI.
//!
//! Use [`rsa2048`], [`rsa3072`], or [`rsa4096`] for your key size.
//! The crate ships a compiled Zig library, so you don't need Zig to build it.
//!
//! Build a signing key from its CRT components, or a public key from its modulus and exponent.
//! Reuse keys to avoid repeating setup.
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
//! This crate targets WASI, not native apps or browsers.
//! The default build needs WebAssembly wide-arithmetic.
//! Use the `no-wide-arithmetic` feature if your runtime doesn't support it.

#![forbid(unsafe_op_in_unsafe_fn)]

use core::fmt::{self, Display};

/// Errors returned by key construction and signature verification.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// A key component did not fit the modulus size, or the public key was malformed.
    InvalidKey,
    /// The signature does not match the message and public key.
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
        $key_bytes:ident, $key_init:ident, $sign:ident,
        $public_key_bytes:ident, $public_key_init:ident, $verify:ident
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
                    pub fn $public_key_bytes() -> usize;
                    pub fn $public_key_init(out: *mut u8, n: *const u8, n_len: usize, e: u64) -> i32;
                    pub fn $verify(
                        key: *const u8,
                        msg: *const u8, msg_len: usize,
                        sig: *const u8, sig_len: usize,
                    ) -> i32;
                }
            }

            /// Modulus size in bits.
            pub const MODULUS_BITS: usize = $bits;
            /// Signature length in bytes.
            pub const SIGNATURE_LEN: usize = $siglen;
            /// Maximum length in bytes of each CRT key component (`p`, `q`, `dp`, `dq`, `qinv`).
            pub const COMPONENT_LEN: usize = $primelen;

            /// An RSA signing key.
            #[derive(Clone)]
            pub struct SecretKey {
                words: Vec<u64>,
            }

            impl SecretKey {
                /// Builds a signing key from big-endian CRT components.
                ///
                /// Pass the primes `p` and `q`, exponents `dp = d mod (p-1)` and `dq = d mod (q-1)`,
                /// and coefficient `qinv = q^-1 mod p`.
                ///
                /// Leading zero bytes are accepted, but count toward the [`COMPONENT_LEN`] limit.
                /// Returns [`Error::InvalidKey`] if any component is too long.
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

                /// Hashes a message with SHA-256 and signs it with PKCS#1 v1.5 padding.
                ///
                /// Returns the signature as big-endian bytes.
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

            /// An RSA key for checking signatures.
            #[derive(Clone, Eq, PartialEq)]
            pub struct PublicKey {
                words: Vec<u64>,
            }

            impl PublicKey {
                /// Builds a public key from big-endian modulus bytes `n` and an exponent `e` (usually `65537`).
                ///
                /// Leading zero bytes are accepted, but count toward the [`SIGNATURE_LEN`] limit.
                /// Returns [`Error::InvalidKey`] if `n` is too long, empty, or even, or if `e` is even or below 3.
                pub fn new(n: impl AsRef<[u8]>, e: u64) -> Result<Self, Error> {
                    let n = n.as_ref();
                    let words_len = unsafe { zig::$public_key_bytes() }.div_ceil(8);
                    let mut words = vec![0u64; words_len];
                    let rc = unsafe {
                        zig::$public_key_init(words.as_mut_ptr() as *mut u8, n.as_ptr(), n.len(), e)
                    };
                    if rc != 0 {
                        return Err(Error::InvalidKey);
                    }
                    Ok(PublicKey { words })
                }

                /// Checks a PKCS#1 v1.5 signature with SHA-256 against `msg`.
                ///
                /// Returns [`Error::VerificationFailed`] if the signature is invalid.
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
                            self.words.as_ptr() as *const u8,
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

            impl core::fmt::Debug for PublicKey {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.debug_struct("PublicKey").finish_non_exhaustive()
                }
            }
        }
    };
}

rsa_module!(
    /// RSA-2048 signing and verification.
    rsa2048, 2048, 256, 128,
    rsa2048_key_bytes, rsa2048_key_init, rsa2048_sign,
    rsa2048_public_key_bytes, rsa2048_public_key_init, rsa2048_verify
);

rsa_module!(
    /// RSA-3072 signing and verification.
    rsa3072, 3072, 384, 192,
    rsa3072_key_bytes, rsa3072_key_init, rsa3072_sign,
    rsa3072_public_key_bytes, rsa3072_public_key_init, rsa3072_verify
);

rsa_module!(
    /// RSA-4096 signing and verification.
    rsa4096, 4096, 512, 256,
    rsa4096_key_bytes, rsa4096_key_init, rsa4096_sign,
    rsa4096_public_key_bytes, rsa4096_public_key_init, rsa4096_verify
);

#[cfg(test)]
mod test;
