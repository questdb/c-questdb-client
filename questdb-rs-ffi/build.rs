#[cfg(feature = "gen_h")]
extern crate cbindgen;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.lock");

    #[cfg(feature = "gen_h")]
    {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR")?;
        let bindings = cbindgen::generate(crate_dir)?;
        bindings.write_to_file("../include/questdb/ilp/line_sender.gen.h");
    }

    #[cfg(feature = "gen_cython")]
    {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR")?;

        let config = cbindgen::Config {
            language: cbindgen::Language::Cython,
            documentation: false,
            cython: cbindgen::CythonConfig {
                header: Some("questdb/ilp/line_sender.h".to_owned()),
                cimports: std::collections::BTreeMap::new()},
            ..Default::default()
        };

        let bindings = cbindgen::Builder::new()
            .with_crate(crate_dir)
            .with_config(config)
            .generate()?;
        bindings.write_to_file("../cython/questdb/ilp/line_sender.pxd");
    }

    Ok(())
}
