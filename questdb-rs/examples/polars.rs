//! End-to-end polars × QuestDB demo: ingest a `DataFrame` over QWP/WS,
//! then read it back via the egress `Reader` directly into a polars
//! `DataFrame`.
//!
//! Run against a local QuestDB with QWP/WS enabled:
//!
//! ```bash
//! cargo run --example polars --features polars
//! ```

use std::error::Error;

use polars::prelude::{DataFrame, IntoColumn, NamedFrom, PlSmallStr, Series};
use questdb::{QuestDb, egress::Reader, ingress::polars::PolarsIngestOptions};

const TABLE: &str = "trades_polars_demo";

fn build_df() -> DataFrame {
    let symbol = Series::new(
        PlSmallStr::from("symbol"),
        &["ETH-USD", "BTC-USD", "ETH-USD", "BTC-USD"],
    );
    let price = Series::new(
        PlSmallStr::from("price"),
        &[2615.54, 65432.10, 2616.00, 65440.55],
    );
    let amount = Series::new(
        PlSmallStr::from("amount"),
        &[0.00044, 0.0012, 0.00050, 0.0008],
    );
    // Height-explicit DataFrame constructor. On polars >=0.53 it's the two-arg
    // `DataFrame::new(height, columns)`; on 0.52 it was `new_with_height` (0.52's
    // `new` took columns only).
    DataFrame::new(
        4,
        vec![
            symbol.into_column(),
            price.into_column(),
            amount.into_column(),
        ],
    )
    .unwrap()
}

fn ingest(host: &str, port: &str, df: &DataFrame) -> Result<(), Box<dyn Error>> {
    let db = QuestDb::connect(&format!("qwpws::addr={host}:{port};"))?;
    // `&str` table names "just work" via `TryInto<TableName>`; optional knobs
    // (batch size, designated-timestamp column, wire-type overrides) are built
    // with `PolarsIngestOptions`. The sender is borrowed from the pool and
    // returned internally — callers go straight through `db`.
    db.flush_polars_dataframe(TABLE, df, &PolarsIngestOptions::new().max_rows(10_000))?;
    Ok(())
}

fn read_back(host: &str, port: &str) -> Result<DataFrame, Box<dyn Error>> {
    let mut reader = Reader::from_conf(format!("ws::addr={host}:{port};"))?;
    let mut cursor = reader
        .prepare(format!("SELECT symbol, price, amount FROM {TABLE}"))
        .execute()?;
    Ok(cursor.fetch_all_polars()?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "9000".to_string());

    let df = build_df();
    println!("==== INGEST ====");
    println!("table:  {TABLE}");
    println!("shape:  {:?} (rows × cols)", df.shape());
    println!("schema: {:?}", df.schema());
    println!("{df}");

    ingest(&host, &port, &df)?;
    println!(
        "✓ flushed {} rows over QWP/WS to {host}:{port}\n",
        df.height()
    );

    println!("==== READ-BACK ====");
    let back = read_back(&host, &port)?;
    println!("shape:  {:?} (rows × cols)", back.shape());
    println!("schema: {:?}", back.schema());
    println!("n_chunks per column:");
    // `DataFrame::columns()` returns the column slice on polars >=0.53; 0.52
    // named it `get_columns()`.
    for col in back.columns() {
        println!("  {:>8} → {} chunk(s)", col.name(), col.n_chunks());
    }
    println!("{back}");

    Ok(())
}
