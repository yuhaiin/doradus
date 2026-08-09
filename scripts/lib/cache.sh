#!/usr/bin/env bash

# Helpers for generated test artifacts under ~/.cache/yuhaiin-rust. Callers
# must pass the exact scenario directory they own; this helper never searches
# or removes anything outside that directory.

cache_prune_timestamped_runs() {
  local scenario_dir="$1"
  local keep_runs="${2:-3}"
  local -a runs=()
  local run
  local index=0

  [[ "${keep_runs}" =~ ^[0-9]+$ ]]
  mapfile -t runs < <(
    find "${scenario_dir}" -mindepth 1 -maxdepth 1 -type d \
      -regextype posix-extended -regex '.*/20[0-9]{12}-[0-9]+' \
      -printf '%T@ %p\n' | sort -rn | sed 's/^[^ ]* //'
  )
  for run in "${runs[@]}"; do
    if (( index >= keep_runs )); then
      rm -rf -- "${run}"
    fi
    index=$((index + 1))
  done
}
