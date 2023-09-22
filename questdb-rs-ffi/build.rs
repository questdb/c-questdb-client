#[cfg(feature = "gen_h")]
extern crate cbindgen;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.lock");

    #[cfg(feature = "gen_h")]
    {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR")?;
        let bindings = cbindgen::generate(crate_dir)?;
        bindings.write_to_file("../include/questdb/ingress/line_sender.gen.h");
    }

    Ok(())
}
