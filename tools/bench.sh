#!/usr/bin/env bash
set -Cefu

# 1. Benchmark performance: `hyperfine` (in count-perf)
# 2. Measure syscalls: `dtruss -c` / `strace -c` (in count-syscalls) # sudo strace -Cf ./check_distro.sh
# 3. Measure lines and bytes `wc -cl` (in count-lbytes)

# - shc
# - hyperfine, time
# - tokei, wc
# - strace, dtruss
