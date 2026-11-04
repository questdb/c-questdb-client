#!/usr/bin/env bash
# Only the diagnostic job needs the original runtime, not today's hosted JDK.
set -euo pipefail

[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]]
readonly EXPECTED_VERSION='25.0.3+9'
readonly ARCHIVE='OpenJDK25U-jdk_aarch64_mac_hotspot_25.0.3_9.tar.gz'
readonly SHA256='7baab4d69a15554e119b86ff78d40e3fdc28819b5b322955c913cebfe3f6a37c'

diagnostic_jdk="${JAVA_HOME:-}"
if [[ ! -x "$diagnostic_jdk/bin/java" ]] ||
        [[ "$("$diagnostic_jdk/bin/java" -version 2>&1)" != *"$EXPECTED_VERSION"* ]]; then
    mkdir -p build
    install_dir="$(mktemp -d "$PWD/build/qwp-diagnostic-jdk.XXXXXX")"
    curl --fail --location --retry 3 \
        "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.3%2B9/$ARCHIVE" \
        --output "$install_dir/$ARCHIVE"
    printf '%s  %s\n' "$SHA256" "$install_dir/$ARCHIVE" | shasum -a 256 -c -
    tar -xzf "$install_dir/$ARCHIVE" -C "$install_dir"
    diagnostic_jdk="$install_dir/jdk-25.0.3+9/Contents/Home"
fi
"$diagnostic_jdk/bin/java" -version
[[ "$("$diagnostic_jdk/bin/java" -version 2>&1)" == *"$EXPECTED_VERSION"* ]]
echo "##vso[task.setvariable variable=JAVA_HOME]$diagnostic_jdk"
echo "##vso[task.prependpath]$diagnostic_jdk/bin"
