#!/usr/bin/env bash
# Runs ON the server box (via ssmx.sh runfile). Installs toolchain, builds
# QuestDB at $QNB_QUESTDB_COMMIT (or unpacks $QNB_TARBALL_S3 if set), mounts
# tmpfs for the data dir, installs the `qdb-server` control helper, and starts
# the server with the recommended receive buffer (16m).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "== packages (openjdk-25 from noble-updates; full log: /var/tmp/apt-install.log)"
apt-get update -q >/var/tmp/apt-install.log 2>&1
apt-get install -qy openjdk-25-jdk-headless maven git iperf3 sysstat curl jq docker.io \
    >>/var/tmp/apt-install.log 2>&1 || { tail -40 /var/tmp/apt-install.log; exit 1; }

# apt's `maven` pulls default-jdk (21) as a dep; force JDK 25 for the build via
# JAVA_HOME + PATH so mvn and the runtime both use it, not the apt default.
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-arm64
export PATH="$JAVA_HOME/bin:$PATH"
java -version

echo "== tmpfs data dir (10g cap; tmpfs only consumes what is used)"
mkdir -p /mnt/qdbtmp
mountpoint -q /mnt/qdbtmp || mount -t tmpfs -o size=10g tmpfs /mnt/qdbtmp

echo "== iperf3 server (for P0 channel validation)"
pkill -x iperf3 2>/dev/null || true
nohup iperf3 -s >/var/log/iperf3.log 2>&1 &

QDB_DIR=/opt/questdb
if [ -n "${QNB_TARBALL_S3:-}" ]; then
    echo "== QuestDB from tarball $QNB_TARBALL_S3"
    mkdir -p "$QDB_DIR"
    aws s3 cp "$QNB_TARBALL_S3" /var/tmp/questdb.tar.gz
    tar -xzf /var/tmp/questdb.tar.gz -C "$QDB_DIR" --strip-components=1
else
    echo "== QuestDB from source @ ${QNB_QUESTDB_COMMIT}"
    if [ "$(cat "$QDB_DIR/.qnb-commit" 2>/dev/null)" = "$QNB_QUESTDB_COMMIT" ]; then
        echo "   already built at this commit — skipping the build"
    else
        # Single-commit shallow fetch — no clone of the (large) full history;
        # GitHub permits fetching an arbitrary SHA directly.
        if [ ! -d /opt/questdb-src/.git ]; then
            git init -q /opt/questdb-src
            git -C /opt/questdb-src remote add origin https://github.com/questdb/questdb.git
        fi
        cd /opt/questdb-src
        git fetch --quiet --depth 1 origin "$QNB_QUESTDB_COMMIT"
        git checkout -q "$QNB_QUESTDB_COMMIT"
        # Mirror CI (.github/actions/detect-local-client): a SNAPSHOT
        # questdb.client.version is not on Maven Central — build the
        # java-questdb-client submodule in-reactor via the local-client profile.
        PROFILES=build-web-console,build-binaries
        if grep -q '<questdb.client.version>.*-SNAPSHOT<' core/pom.xml; then
            git submodule update --init --quiet --depth 1 java-questdb-client
            PROFILES="$PROFILES,local-client"
        fi
        # SSM caps command output at 24 KB — keep the full build log on the box.
        mvn -q clean package -DskipTests -P "$PROFILES" >/var/tmp/mvn-build.log 2>&1 \
            || { tail -60 /var/tmp/mvn-build.log; exit 1; }
        mkdir -p "$QDB_DIR"
        TARBALL=$(ls core/target/questdb-*-no-jre-bin.tar.gz core/target/questdb-*-bin.tar.gz 2>/dev/null | head -1)
        [ -n "$TARBALL" ] || { echo "ERROR: no binary tarball produced under core/target" >&2; exit 1; }
        tar -xzf "$TARBALL" -C "$QDB_DIR" --strip-components=1
        echo "$QNB_QUESTDB_COMMIT" > "$QDB_DIR/.qnb-commit"
    fi
fi

echo "== qdb-server control helper"
cat > /usr/local/bin/qdb-server <<'EOF'
#!/usr/bin/env bash
# qdb-server start|stop|restart|ensure|status [recv_buffer]
# qdb-server use-ent <image-ref> [recv_buffer]  switch to the ENT container
#            (image ref comes from internal docs; ECR login is automatic via
#            the instance role; built-in admin is enabled, password from
#            $QDB_ADMIN_PASSWORD, default "quest")
# qdb-server use-oss [recv_buffer]              back to the local OSS build
# recv_buffer feeds the canonical http.recv.buffer.size (server default: 2 MiB).
# `ensure` restarts only if the server is down or the buffer differs —
# preserves warm state (ClientSymbolCache etc.) across same-config cells.
set -euo pipefail
CMD="${1:?start|stop|restart|ensure|status|use-ent|use-oss}"
ROOT=/mnt/qdbtmp/qdb-root
STATE=/var/run/qdb-server-state   # "<mode> <image|-> <recv>"
MODE=oss; IMAGE=-
[ -f "$STATE" ] && read -r MODE IMAGE _ < "$STATE"
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-arm64
export PATH="$JAVA_HOME/bin:$PATH"
export QDB_TELEMETRY_ENABLED=false

ecr_login() {
    case "$IMAGE" in
        *.dkr.ecr.*.amazonaws.com/*)
            reg="${IMAGE%%/*}"
            region=$(echo "$reg" | sed -E 's/.*\.dkr\.ecr\.([^.]+)\.amazonaws\.com/\1/')
            aws ecr get-login-password --region "$region" \
                | docker login --username AWS --password-stdin "$reg" >/dev/null ;;
    esac
}
health() {
    if [ "$MODE" = ent ]; then
        curl -sf -u "admin:${QDB_ADMIN_PASSWORD:-quest}" \
            "http://127.0.0.1:9000/exec?query=select%201" >/dev/null
    else
        curl -sf "http://127.0.0.1:9000/exec?query=select%201" >/dev/null
    fi
}
stop() {
    pkill -f 'io.questdb.ServerMain' 2>/dev/null || true
    docker rm -f questdb >/dev/null 2>&1 || true
    sleep 2
}
start() {
    recv="$1"
    # tmpfs does not survive stop/start — remount or the data dir would
    # silently land on EBS and skew every bench number.
    mountpoint -q /mnt/qdbtmp || mount -t tmpfs -o size=10g tmpfs /mnt/qdbtmp
    mkdir -p "$ROOT"
    if [ "$MODE" = ent ]; then
        ecr_login
        docker pull -q "$IMAGE" >/dev/null
        docker run -d --name questdb --network host \
            -v "$ROOT":/var/lib/questdb \
            -e QDB_HTTP_RECV_BUFFER_SIZE="$recv" \
            -e QDB_TELEMETRY_ENABLED=false \
            -e QDB_ACL_ADMIN_USER_ENABLED=true \
            -e QDB_ACL_ADMIN_USER=admin \
            -e QDB_ACL_ADMIN_PASSWORD="${QDB_ADMIN_PASSWORD:-quest}" \
            "$IMAGE" >/dev/null
    else
        QDB_HTTP_RECV_BUFFER_SIZE="$recv" \
            /opt/questdb/questdb.sh start -d "$ROOT" >/var/log/questdb-start.log 2>&1
    fi
    for i in $(seq 1 30); do health && break; sleep 2; done
    health || { echo "ERROR: QuestDB did not become healthy" >&2; exit 1; }
    echo "$MODE $IMAGE $recv" > "$STATE"
    echo "questdb up: mode=$MODE image=$IMAGE recv=$recv root=$ROOT (tmpfs)"
}
case "$CMD" in
    use-ent) MODE=ent; IMAGE="${2:?image ref required}"; stop; start "${3:-16m}" ;;
    use-oss) MODE=oss; IMAGE=-; stop; start "${2:-16m}" ;;
    start)   start "${2:-16m}" ;;
    stop)    stop ;;
    restart) stop; start "${2:-16m}" ;;
    ensure)
        RECV="${2:-16m}"
        CUR=$(awk '{print $3}' "$STATE" 2>/dev/null || true)
        if health && [ "$CUR" = "$RECV" ]; then
            echo "questdb already up: mode=$MODE recv=$RECV (no restart)"
        else
            stop; start "$RECV"
        fi ;;
    status)  health && echo "up ($MODE)" || echo down ;;
esac
EOF
chmod +x /usr/local/bin/qdb-server

echo "== start with recommended buffer (16m)"
qdb-server restart 16m
echo "== bootstrap done"
