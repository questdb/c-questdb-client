//! Proof that an owning consumer needs no `unsafe`.
//!
//! This exercises the four shapes that made a hand-rolled self-referential
//! stream undefined behaviour in the ADBC driver before this API existed:
//! dropping by value, consuming by a by-value adaptor, moving across a thread,
//! and boxing as a trait object. `forbid(unsafe_code)` is the assertion — if
//! this file compiles, the property holds, because the compiler proved it.

#![forbid(unsafe_code)]

use arrow::array::RecordBatchReader;
use questdb::QuestDb;

fn main() -> questdb::Result<()> {
    let conf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws::addr=localhost:9000;".to_string());
    let db = QuestDb::connect(&conf)?;

    // 1. Dropped by value inside a call.
    let cursor = db.take_reader()?.query("SELECT 1").execute()?;
    drop(cursor);

    // 2. Consumed by a by-value iterator adaptor.
    let rows: usize = db
        .take_reader()?
        .query("SELECT 1")
        .execute()?
        .into_arrow_reader()?
        .map(|b| b.map(|b| b.num_rows()).unwrap_or(0))
        .sum();
    println!("rows: {rows}");

    // 3. Moved across a thread and consumed there.
    let reader = db
        .take_reader()?
        .query("SELECT 1")
        .execute()?
        .into_arrow_reader()?;
    let n = std::thread::spawn(move || reader.count()).join().unwrap();
    println!("batches: {n}");

    // 4. Boxed as a trait object — the ADBC shape.
    let boxed: Box<dyn RecordBatchReader + Send> = Box::new(
        db.take_reader()?
            .query("SELECT 1")
            .execute()?
            .into_arrow_reader()?,
    );
    println!("schema: {}", boxed.schema());

    Ok(())
}
