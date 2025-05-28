fn main() {
    if std::env::var("CARGO_NEAR_ABI_GENERATION").unwrap_or_default() == "true" {
        println!("cargo:rustc-cfg=feature=\"abi\"");
    }
}
