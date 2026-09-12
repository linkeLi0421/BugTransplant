#!/bin/bash
# Build the FuzzBench runner images pass 1 needs but this box does not have.
# Each is built from the benchmark Dockerfile, which pins base-builder by
# digest, so the environment matches the campaign's by construction.
# Sequential, with a disk guard: the intermediates are ~7 GB per benchmark.
cd /home/user/oss-fuzz-build/fuzzbench
MIN_FREE_GB=${MIN_FREE_GB:-20}
for b in htslib_transplant_hts_open_fuzzer \
         opensc_transplant_fuzz_pkcs15_reader \
         ndpi_transplant_fuzz_process_packet \
         libredwg_transplant_llvmfuzz; do
  free=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
  echo "########## $b  $(date +%F\ %H:%M)  (${free}G free)"
  if [ "$free" -lt "$MIN_FREE_GB" ]; then
    echo "!! only ${free}G free, below MIN_FREE_GB=${MIN_FREE_GB} -- stopping"
    exit 1
  fi
  if docker image inspect "gcr.io/fuzzbench/runners/libfuzzer/$b:latest" >/dev/null 2>&1; then
    echo "   already present, skipping"; continue
  fi
  make "build-libfuzzer-$b" 2>&1 | tail -25
  docker image inspect -f '   built {{.Id}}' "gcr.io/fuzzbench/runners/libfuzzer/$b:latest" \
    || echo "   !! build did not produce the runner image"
done
echo "RUNNER_IMAGES_DONE $(date +%F\ %H:%M)"
