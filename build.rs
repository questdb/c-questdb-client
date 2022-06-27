#[cfg(feature = "gen_h")]
extern crate cbindgen;

#[cfg(feature = "json_tests")]
pub mod json_tests {
    use std::path::PathBuf;
    use serde::{Serialize, Deserialize};
    use serde_json;

    #[derive(Debug, Serialize, Deserialize)]
    struct Symbol {
        name: String,
        value: String
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct StringColumn {
        name: String,
        value: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct LongColumn {
        name: String,
        value: i64,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct DoubleColumn {
        name: String,
        value: f64
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct BooleanColumn {
        name: String,
        value: bool
    }


    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "UPPERCASE")]
    enum Column {
        String(StringColumn),
        Long(LongColumn),
        Double(DoubleColumn),
        Boolean(BooleanColumn)
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Line {
        line: String
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "status", rename_all = "UPPERCASE")]
    enum Outcome {
        Success(Line),
        Error
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestSpec {
        #[serde(rename = "testName")]
        test_name: String,
        table: String,
        symbols: Vec<Symbol>,
        columns: Vec<Column>,
        result: Outcome
    }

    fn parse() -> Vec<TestSpec> {
        let mut json_path = PathBuf::from(
            std::env::var("CARGO_MANIFEST_DIR").unwrap());
        json_path.push("test");
        json_path.push("interop");
        json_path.push("ilp-client-interop-test.json");
        let file = std::fs::File::open(json_path).unwrap();
        serde_json::from_reader(file).unwrap()
    }

    pub fn build() {
        let specs = parse();
        eprintln!("W00t!: {:#?}", specs);
    }
}

fn main() {
    #[cfg(feature = "gen_h")]
    {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let bindings = cbindgen::generate(crate_dir).unwrap();
        bindings.write_to_file("include/questdb/ilp/line_sender.h");
    }

    #[cfg(feature = "json_tests")]
    json_tests::build();
}