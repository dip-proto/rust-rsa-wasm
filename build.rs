use std::env;

pub fn main() {
    let src_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // The no-wide-arithmetic feature swaps in the archive built without the wasm
    // wide-arithmetic proposal, for runtimes that cannot validate it.
    let lib = if env::var_os("CARGO_FEATURE_NO_WIDE_ARITHMETIC").is_some() {
        "rsa_nowide"
    } else {
        "rsa"
    };
    println!("cargo:rustc-link-lib=static={lib}");
    println!("cargo:rustc-link-search=native={src_dir}/wasm-libs");
    println!("cargo:rerun-if-changed=wasm-libs/lib{lib}.a");
}
