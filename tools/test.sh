#!/usr/bin/env bash

# 1. test shells

# 2. test flags

exe_path() {
	exe_dir=${0%/*}/../
	exe_path=${exe_dir}src/behindTheCDN.sh

	$exe_path
}

case $- in
*i*) return 0 ;;
  *) set -Cefu
esac

exe_path -d matrix.org
exe_path -c -d matrix.org
exe_path -h -d matrix.org
exe_path -m -d matrix.org
exe_path -n -d matrix.org
exe_path -s -d matrix.org
exe_path -f tools/domains.txt -o output/log.txt
