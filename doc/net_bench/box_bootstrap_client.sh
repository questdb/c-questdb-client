#!/usr/bin/env bash
# Runs ON the client box (via ssmx.sh runfile). Installs Rust + Python + JDK
# toolchains, clones all client repos at the exact commits under test, and
# pre-builds the Rust bench examples and the Java bench jar so run_cell.sh
# measures benches, not compilation.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "== packages (full log on the box: /var/tmp/apt-install.log — SSM caps output at 24 KB)"
apt-get update -q >/var/tmp/apt-install.log 2>&1
apt-get install -qy build-essential pkg-config libssl-dev cmake git \
    iperf3 sysstat curl jq python3-dev libcurl4-openssl-dev \
    >>/var/tmp/apt-install.log 2>&1 \
    || { tail -40 /var/tmp/apt-install.log; exit 1; }

echo "== rust toolchain"
if [ ! -x /root/.cargo/bin/cargo ]; then
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
export PATH="/root/.cargo/bin:$PATH"

echo "== uv + python (3.10 — the pinned py client requires >=3.10; plan §10.3)"
if [ ! -x /root/.local/bin/uv ]; then
    curl -fsSL https://astral.sh/uv/install.sh | sh
fi
export PATH="/root/.local/bin:$PATH"

WORK=/opt/qwp-bench
mkdir -p "$WORK"

# Single-commit shallow fetches — no full-history clones (GitHub permits
# fetching an arbitrary SHA directly).
shallow_at() { # $1 = dir, $2 = repo url, $3 = commit
    if [ ! -d "$1/.git" ]; then
        git init -q "$1"
        git -C "$1" remote add origin "$2"
    fi
    git -C "$1" fetch --quiet --depth 1 origin "$3"
    git -C "$1" checkout -q "$3"
}

echo "== c-questdb-client @ ${QNB_C_CLIENT_COMMIT}"
shallow_at "$WORK/c-questdb-client" \
    https://github.com/questdb/c-questdb-client.git "$QNB_C_CLIENT_COMMIT"
cd "$WORK/c-questdb-client"

echo "== pre-build rust bench examples (release; log: /var/tmp/cargo-build.log)"
cd questdb-rs
cargo build --release \
    --features polars,sync-sender-qwp-ws,sync-sender-http \
    --example qwp_ingress_polars --example qwp_egress_polars --example qwp_ingress_row \
    >/var/tmp/cargo-build.log 2>&1 \
    || { tail -60 /var/tmp/cargo-build.log; exit 1; }

echo "== pre-build qwp_ingress_row under run_cell.sh's rust-row feature set (avoids an on-box recompile from feature-set unification mismatch; log: /var/tmp/cargo-build.log)"
cargo build --release --features sync-sender-qwp-ws,sync-sender-http --example qwp_ingress_row \
    >>/var/tmp/cargo-build.log 2>&1 \
    || { tail -60 /var/tmp/cargo-build.log; exit 1; }

echo "== c bench build (log: /var/tmp/cmake-build.log)"
cd "$WORK/c-questdb-client"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DQUESTDB_QWP_BENCH=ON \
    >/var/tmp/cmake-build.log 2>&1 \
    && cmake --build build --target qwp_ingress_c qwp_egress_c -j "$(nproc)" \
        >>/var/tmp/cmake-build.log 2>&1 \
    || { tail -60 /var/tmp/cmake-build.log; exit 1; }

echo "== jdk + maven for the java bench"
apt-get install -qy openjdk-25-jdk-headless maven >>/var/tmp/apt-install.log 2>&1 \
    || { tail -20 /var/tmp/apt-install.log; exit 1; }
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-arm64
export PATH="$JAVA_HOME/bin:$PATH"
[ -d "$JAVA_HOME" ] || { echo "ERROR: JAVA_HOME missing" >&2; exit 1; }

echo "== java-questdb-client + bench @ ${QNB_JAVA_CLIENT_COMMIT} (log: /var/tmp/mvn-bench.log)"
shallow_at "$WORK/java-questdb-client" \
    https://github.com/questdb/java-questdb-client.git "$QNB_JAVA_CLIENT_COMMIT"
if [ "$(cat "$WORK/java-questdb-client/.qnb-built" 2>/dev/null)" != "$QNB_JAVA_CLIENT_COMMIT" ]; then
    # `mvn package` alone does not build the native lib the QWP paths load at
    # runtime (Os.loadLib) -- CMake it first, same as ci/build_native.yaml's
    # Linux step, then drop the .so where `mvn package` bundles it from.
    echo "== java native lib (libquestdb.so; log: /var/tmp/cmake-java.log)"
    git -C "$WORK/java-questdb-client" submodule update --init --quiet --depth 1 \
        core/src/main/c/share/zstd
    cmake -S "$WORK/java-questdb-client/core" -B "$WORK/java-questdb-client/core/cmake-build-release" \
        -DCMAKE_BUILD_TYPE=Release \
        >/var/tmp/cmake-java.log 2>&1 \
        || { tail -60 /var/tmp/cmake-java.log; exit 1; }
    cmake --build "$WORK/java-questdb-client/core/cmake-build-release" --config Release -j "$(nproc)" \
        >>/var/tmp/cmake-java.log 2>&1 \
        || { tail -60 /var/tmp/cmake-java.log; exit 1; }
    [ -f "$WORK/java-questdb-client/core/target/classes/io/questdb/client/bin-local/libquestdb.so" ] \
        || { echo "ERROR: java native lib not built" >&2; exit 1; }
    mkdir -p "$WORK/java-questdb-client/core/src/main/resources/io/questdb/client/bin/linux-aarch64"
    cp "$WORK/java-questdb-client/core/target/classes/io/questdb/client/bin-local/libquestdb.so" \
        "$WORK/java-questdb-client/core/src/main/resources/io/questdb/client/bin/linux-aarch64/libquestdb.so"
    (cd "$WORK/java-questdb-client" && mvn -q -pl qwp-bench -am package -DskipTests) \
        >/var/tmp/mvn-bench.log 2>&1 || { tail -40 /var/tmp/mvn-bench.log; exit 1; }
    echo "$QNB_JAVA_CLIENT_COMMIT" > "$WORK/java-questdb-client/.qnb-built"
fi

echo "== py-questdb-client @ ${QNB_PY_CLIENT_COMMIT}"
shallow_at "$WORK/py-questdb-client" \
    https://github.com/questdb/py-questdb-client.git "$QNB_PY_CLIENT_COMMIT"
cd "$WORK/py-questdb-client"
git submodule update --init --recursive --depth 1

echo "== python env (editable install builds the native ext against the vendored core)"
if [ "$(cat .qnb-venv 2>/dev/null)" = "$QNB_PY_CLIENT_COMMIT" ]; then
    echo "   venv already built at this commit — skipping"
else
    # --clear: a half-built .venv from an earlier failed install must not
    # abort the bootstrap (venv creation is inside the non-fatal guard).
    # shellcheck disable=SC1091
    if uv venv --clear --python 3.10 .venv >/var/tmp/py-install.log 2>&1 \
        && . .venv/bin/activate \
        && uv pip install -e . pandas pyarrow polars numpy >>/var/tmp/py-install.log 2>&1; then
        echo "$QNB_PY_CLIENT_COMMIT" > .qnb-venv
    else
        tail -40 /var/tmp/py-install.log
        echo "WARNING: py install failed — Python cells blocked anyway until W1 (remote-host patch) lands"
    fi
fi

echo "== bootstrap done"
