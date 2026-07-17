// One `questdb::pool` shared by two threads over QWP/WebSocket.
//
// The pool is created once on the main thread and handed to two worker threads
// by reference. Each worker takes its own short-lived borrow:
//
//  * The ingestion thread builds column-major batches with the `column_chunk`
//    API and publishes them through a `borrowed_sender`, checkpointing on
//    `qwpws_ack_level::ok`.
//  * The query thread polls the same table through a pooled `reader`, watching
//    rows become visible as the WAL is applied, then reports per-symbol stats.
//
// Both directions run concurrently against one pool, which is the intended
// deployment shape: one pool per process, a borrow per unit of work.
//
// Run against a local QuestDB (10.0+):
//
//     ./qwp_ws_chunk_and_query_cpp_example
//
// The example recreates its own `cpp_shared_pool_trades` table on every run.

#include <questdb/egress/reader.hpp>
#include <questdb/ingress/column_sender.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{

namespace in = questdb::ingress;

using namespace std::chrono_literals;

/// Separate caps for the two pools: this process holds at most one sender and
/// one reader borrow at a time, plus headroom for the main thread's DDL.
constexpr std::string_view DEFAULT_CONF =
    "ws::addr=localhost:9000;sender_pool_max=2;query_pool_max=2;";

constexpr std::string_view TABLE = "cpp_shared_pool_trades";

constexpr std::array<std::pair<std::string_view, double>, 4> INSTRUMENTS{{
    {"BTC-USDT", 65432.10},
    {"ETH-USDT", 2615.54},
    {"SOL-USDT", 141.27},
    {"ADA-USDT", 0.38},
}};

constexpr size_t BATCHES = 20;
constexpr size_t ROWS_PER_BATCH = 5000;
constexpr size_t TOTAL_ROWS = BATCHES * ROWS_PER_BATCH;

/// Batches published between `qwpws_ack_level::ok` checkpoints.
constexpr size_t CHECKPOINT_EVERY = 8;

/// Pause between batches, standing in for the arrival rate of a live feed.
constexpr auto BATCH_INTERVAL = 100ms;

/// Gap between query-visibility polls.
constexpr auto POLL_INTERVAL = 200ms;

/// `amount` bind for the final per-symbol query.
constexpr double LARGE_TRADE = 0.005;

constexpr auto ACK_TIMEOUT = 30s;
constexpr auto VISIBILITY_TIMEOUT = 60s;

/// xorshift64*, so the example needs no random-number dependency.
class xorshift64
{
public:
    explicit xorshift64(uint64_t seed) noexcept
        : _state{seed}
    {
    }

    uint64_t next() noexcept
    {
        _state ^= _state >> 12;
        _state ^= _state << 25;
        _state ^= _state >> 27;
        return _state * 0x2545f4914f6cdd1dULL;
    }

    /// Uniform in `[0, 1)`.
    double unit() noexcept
    {
        return static_cast<double>(next() >> 11) /
               static_cast<double>(1ULL << 53);
    }

    /// Uniform in `[-1, 1)`.
    double unit_spread() noexcept
    {
        return unit() * 2.0 - 1.0;
    }

private:
    uint64_t _state;
};

/// Runs DDL through a reader borrow. `execute` drives statements that return no
/// rows, and the cursor is drained to reach its terminal value.
void recreate_table(questdb::pool& db)
{
    auto reader = db.borrow_reader();

    const std::string table{TABLE};
    const std::string statements[] = {
        "DROP TABLE IF EXISTS " + table,
        "CREATE TABLE " + table +
            " ("
            "symbol SYMBOL, "
            "price DOUBLE, "
            "amount DOUBLE, "
            "timestamp TIMESTAMP"
            ") TIMESTAMP(timestamp) PARTITION BY DAY WAL",
    };

    for (const auto& statement : statements)
    {
        auto cursor = reader.execute(statement);
        while (cursor.next_batch())
        {
        }
    }

    std::cout << "table " << TABLE << " is ready\n";
}

/// Publishes `TOTAL_ROWS` rows as column-major chunks.
void ingest_trades(questdb::pool& db)
{
    auto sender = db.borrow_sender();

    // Arrow-style dictionary shared by every batch: a flat UTF-8 block plus
    // `int32_t` offsets, where `offsets[i]..offsets[i + 1]` spans entry `i`.
    std::vector<uint8_t> dict_bytes;
    std::vector<int32_t> dict_offsets{0};
    for (const auto& instrument : INSTRUMENTS)
    {
        const std::string_view name = instrument.first;
        dict_bytes.insert(dict_bytes.end(), name.begin(), name.end());
        dict_offsets.push_back(static_cast<int32_t>(dict_bytes.size()));
    }

    // Refilled in place by every batch.
    std::vector<int8_t> symbol_codes;
    std::vector<double> price;
    std::vector<double> amount;
    std::vector<int64_t> timestamp;
    symbol_codes.reserve(ROWS_PER_BATCH);
    price.reserve(ROWS_PER_BATCH);
    amount.reserve(ROWS_PER_BATCH);
    timestamp.reserve(ROWS_PER_BATCH);

    // One chunk for the whole run: a successful `flush` clears it while
    // retaining the table name and the descriptor-vec capacity, so each batch
    // re-appends its columns into the same allocation. A cleared chunk holds no
    // descriptors into the buffers above, which is what makes refilling them
    // safe.
    in::column_chunk chunk{TABLE};

    // `at_nanos` takes raw epoch nanoseconds, which `timestamp_nanos` unwraps.
    xorshift64 rng{0x5eed12349abcdef0ULL};
    int64_t row_ts = in::timestamp_nanos::now().as_nanos();
    const auto started = std::chrono::steady_clock::now();

    for (size_t batch = 0; batch < BATCHES; ++batch)
    {
        symbol_codes.clear();
        price.clear();
        amount.clear();
        timestamp.clear();

        for (size_t row = 0; row < ROWS_PER_BATCH; ++row)
        {
            const auto code =
                static_cast<size_t>(rng.next() % INSTRUMENTS.size());
            const double base_price = INSTRUMENTS[code].second;

            symbol_codes.push_back(static_cast<int8_t>(code));
            price.push_back(base_price * (1.0 + rng.unit_spread() * 0.001));
            amount.push_back(0.0001 + rng.unit() * 0.01);
            row_ts += 1000;
            timestamp.push_back(row_ts);
        }

        // The appended descriptors point into the buffers just filled and stay
        // valid until `flush` returns.
        chunk.symbol_i8(
            "symbol",
            symbol_codes.data(),
            symbol_codes.size(),
            dict_offsets.data(),
            dict_offsets.size(),
            dict_bytes.data(),
            dict_bytes.size());
        chunk.column_f64("price", price.data(), price.size());
        chunk.column_f64("amount", amount.data(), amount.size());
        chunk.at_nanos(timestamp.data(), timestamp.size());

        // Publishes to the local store-and-forward queue; delivery continues in
        // the background.
        sender.flush(chunk);

        if ((batch + 1) % CHECKPOINT_EVERY == 0)
        {
            // A bounded no-progress wait for everything published so far.
            sender.wait(in::qwpws_ack_level::ok, ACK_TIMEOUT);
            std::cout << "ingest: " << (batch + 1) * ROWS_PER_BATCH
                      << " rows acked\n";
        }

        // Paces the synthetic feed like a live market data source, so the query
        // thread observes the table growing rather than one finished bulk load.
        std::this_thread::sleep_for(BATCH_INTERVAL);
    }

    sender.wait(in::qwpws_ack_level::ok, ACK_TIMEOUT);
    const std::chrono::duration<double> elapsed =
        std::chrono::steady_clock::now() - started;
    std::printf(
        "ingest: all %zu rows acked in %.2fs\n", TOTAL_ROWS, elapsed.count());
}

/// An `ok` ack means the server accepted the frame; a row becomes visible only
/// once the WAL is applied, which happens asynchronously.
int64_t count_rows(questdb::pool& db)
{
    auto reader = db.borrow_reader();
    auto cursor = reader.execute("SELECT count() FROM " + std::string{TABLE});
    int64_t count = 0;

    while (auto batch_opt = cursor.next_batch())
    {
        auto& batch = *batch_opt;
        if (batch.row_count() == 0)
            continue;
        // A result column that is not the type this program expects is
        // reported by `get<T>` as a `questdb::error`, in the client's error
        // vocabulary. The optional is empty for a SQL NULL.
        if (const auto value = batch.column(0).get<int64_t>(0))
            count = *value;
    }

    return count;
}

void report_large_trades(questdb::pool& db)
{
    auto reader = db.borrow_reader();
    auto cursor =
        reader
            .prepare(
                "SELECT symbol, count() AS trades, "
                "avg(price) AS avg_price FROM " +
                std::string{TABLE} + " WHERE amount > $1 ORDER BY symbol")
            .bind_f64(LARGE_TRADE)
            .execute();

    std::printf("\ntrades with amount > %g:\n", LARGE_TRADE);
    while (auto batch_opt = cursor.next_batch())
    {
        auto& batch = *batch_opt;
        const auto symbol = batch.column(0);
        const auto trades = batch.column(1);
        const auto avg_price = batch.column(2);

        for (size_t row = 0; row < batch.row_count(); ++row)
        {
            const auto instrument = symbol.symbol(row);
            const auto trade_count = trades.get<int64_t>(row);
            const auto avg = avg_price.get<double>(row);
            if (!instrument || !trade_count || !avg)
                continue;
            std::printf(
                "  %-9.*s %6lld trades, avg price %.4f\n",
                static_cast<int>(instrument->size()),
                instrument->data(),
                static_cast<long long>(*trade_count),
                *avg);
        }
    }
}

/// Polls for query visibility, then reports per-symbol stats.
void follow_trades(questdb::pool& db)
{
    const auto deadline = std::chrono::steady_clock::now() + VISIBILITY_TIMEOUT;

    for (;;)
    {
        const int64_t visible = count_rows(db);
        std::cout << "query: " << visible << "/" << TOTAL_ROWS
                  << " rows visible\n";

        if (visible >= static_cast<int64_t>(TOTAL_ROWS))
            break;
        // The client's own operations report `questdb::error`. This deadline is
        // the example's own policy rather than a client failure, so it reports
        // a plain `std::runtime_error` (the base of `questdb::error`).
        if (std::chrono::steady_clock::now() >= deadline)
            throw std::runtime_error{
                "only " + std::to_string(visible) + "/" +
                std::to_string(TOTAL_ROWS) + " rows became visible"};
        std::this_thread::sleep_for(POLL_INTERVAL);
    }

    report_large_trades(db);
}

} // namespace

int main(int argc, const char* argv[])
{
    try
    {
        // The pool is thread-safe for borrow/return while this owner is alive,
        // and it is declared before the workers: a future's destructor joins
        // its thread, so every borrow is released before the pool is destroyed.
        const std::string_view conf = argc >= 2 ? argv[1] : DEFAULT_CONF;
        questdb::pool db{conf};

        recreate_table(db);

        // `std::async` gives each worker its own thread and re-raises whatever
        // it threw on `get()`, which an escaping exception from `std::thread`
        // could not do.
        auto ingest =
            std::async(std::launch::async, [&db] { ingest_trades(db); });
        auto query =
            std::async(std::launch::async, [&db] { follow_trades(db); });

        ingest.get();
        query.get();
        return 0;
    }
    catch (const questdb::error& e)
    {
        std::cerr << "Error (code " << static_cast<int>(e.code())
                  << "): " << e.what() << '\n';
        return 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
