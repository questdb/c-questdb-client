#[cfg(feature = "gen_h")]
extern crate cbindgen;

fn main() {
    #[cfg(feature = "gen_h")]
    {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let bindings = cbindgen::generate(crate_dir).unwrap();
        bindings.write_to_file("include/questdb/ilp/line_sender.h");
    }
}