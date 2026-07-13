#!/usr/bin/env bash
# Runs ON the client box (via ssmx.sh runfile). Installs Rust + Python
# toolchains, clones both client repos at the exact commits under test, and
# pre-builds the Rust bench examples so run_cell.sh measures benches, not
# compilation.
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
    --example qwp_ingress_polars --example qwp_egress_polars \
    >/var/tmp/cargo-build.log 2>&1 \
    || { tail -60 /var/tmp/cargo-build.log; exit 1; }

echo "== c bench build (log: /var/tmp/cmake-build.log)"
cd "$WORK/c-questdb-client"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DQUESTDB_QWP_BENCH=ON \
    >/var/tmp/cmake-build.log 2>&1 \
    && cmake --build build --target qwp_ingress_c qwp_egress_c -j "$(nproc)" \
        >>/var/tmp/cmake-build.log 2>&1 \
    || { tail -60 /var/tmp/cmake-build.log; exit 1; }

echo "== py-questdb-client @ ${QNB_PY_CLIENT_COMMIT}"
shallow_at "$WORK/py-questdb-client" \
    https://github.com/questdb/py-questdb-client.git "$QNB_PY_CLIENT_COMMIT"
cd "$WORK/py-questdb-client"
git submodule update --init --recursive --depth 1

echo "== python env (editable install builds the native ext against the vendored core)"
if [ "$(cat .qnb-venv 2>/dev/null)" = "$QNB_PY_CLIENT_COMMIT" ]; then
    echo "   venv already built at this commit — skipping"
else
    uv venv --python 3.10 .venv >/var/tmp/py-install.log 2>&1
    # shellcheck disable=SC1091
    . .venv/bin/activate
    if uv pip install -e . pandas pyarrow polars numpy >>/var/tmp/py-install.log 2>&1; then
        echo "$QNB_PY_CLIENT_COMMIT" > .qnb-venv
    else
        tail -40 /var/tmp/py-install.log
        echo "WARNING: py install failed — Python cells blocked anyway until W1 (remote-host patch) lands"
    fi
fi

echo "== bootstrap done"
