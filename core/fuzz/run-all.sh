#!/bin/bash
# Bounded cargo-fuzz run of every target (libFuzzer, no sanitizer: the crate forbids unsafe).
# Usage: run-all.sh <seconds-per-target>
set -u
cd "$(dirname "$0")"
source ~/.cargo/env
export CXX=/opt/tools/zig/zig-c++ CUSTOM_LIBFUZZER_STD_CXX=c++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/opt/tools/zig/zig-c++
T=${1:-600}
date -Is > logs/started
for t in policy_yaml decide_json policy_and_request regex_portable redact; do
  mkdir -p corpus/$t
  cargo +nightly fuzz run -s none "$t" corpus/$t -- -max_total_time=$T -dict=policy.dict -max_len=8192 -timeout=10 -rss_limit_mb=2048 -print_final_stats=1 > logs/$t.log 2>&1 &
done
wait
date -Is > logs/finished
