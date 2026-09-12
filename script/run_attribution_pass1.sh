#!/bin/bash
# Pass 1 -- dispatch-mask sweep (graft-triggered / composition-dependent /
# graft-independent), all 10 targets.
# Replays run in the campaign's own runner image
# (gcr.io/fuzzbench/runners/libfuzzer/<benchmark>:latest), which is built on the
# base-builder digest the benchmark Dockerfile pins -- not the floating
# base-runner:latest tag the v3 run used.
# Data source: /mnt/nas/linke/new_seeds ONLY, and each target reads only its
# own project's folder -- db, experiment-folders and coverage tar all come from
# $NS/<project>/experiment-data.  (The v3 drivers read htslib from ntopng's db
# copy and c-blosc2 from ghostscript's; that is what is corrected here.)
cd /home/user/oss-fuzz-build
NS=/mnt/nas/linke/new_seeds
OUT=${OUT:-/home/user/paper1/data/bug_attr}
W=${W:-/home/user/abl_work/bug_attr}
mkdir -p $OUT $W
# ONLY="htslib opensc" restricts the run to those targets; unset runs all ten.
run() {  # 1=benchmark 2=db 3=experiment 4=folders 5=target-binary 6=cov-tar 7=name
  if [ -n "${ONLY:-}" ] && ! grep -qw -- "$7" <<< "$ONLY"; then return; fi
  echo "########## $7 $(date +%F\ %H:%M)"
  local img="gcr.io/fuzzbench/runners/libfuzzer/$1:latest"
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    if [ "${RUNNER_FALLBACK:-0}" = 1 ]; then
      echo "   !! $img missing -- falling back to base-runner:latest (a DIFFERENT"
      echo "      environment from the campaign; record this if you keep the result)"
      img="gcr.io/oss-fuzz-base/base-runner:latest"
    else
      echo "   !! $img missing -- build it with:"
      echo "      (cd fuzzbench && make build-libfuzzer-$1)"
      echo "      or re-run with RUNNER_FALLBACK=1 to accept base-runner.  SKIPPED $7"
      return
    fi
  fi
  timeout 86400 python3 script/two_level_triage.py --benchmark-dir fuzzbench/benchmarks/$1 \
    --db "$2" --experiment "$3" --folders "$4" --target "$5" \
    --runner-image "$img" \
    --cov-tar "$6" --workdir $W --out $OUT --name "$7" --jobs 8 2>&1 \
    | grep -E "classes \(|mask 0 repro|^level|wrote|Error|Traceback"
  rm -rf $W/$7/raw $W/$7/variants $W/$7/v*
  echo "   disk: $(df -h / | tail -1 | awk '{print $4}') free"
}

# --- small targets first (fast feedback) ---
run ghostscript_transplant_gs_device_pdfwrite_fuzzer \
  $NS/ghostscript/experiment-data/local_clnode205.db gspdf-24h-6fuzzer \
  $NS/ghostscript/experiment-data/gspdf-24h-6fuzzer/experiment-folders gs_device_pdfwrite_fuzzer \
  $NS/ghostscript/experiment-data/gspdf-24h-6fuzzer/coverage-binaries/coverage-build-ghostscript_transplant_gs_device_pdfwrite_fuzzer.tar.gz gs_pdfwrite
run opensc_transplant_fuzz_pkcs15_reader \
  $NS/opensc/experiment-data/local.db opensc-24h-6fuzzer \
  $NS/opensc/experiment-data/opensc-24h-6fuzzer/experiment-folders fuzz_pkcs15_reader \
  $NS/opensc/experiment-data/opensc-24h-6fuzzer/coverage-binaries/coverage-build-opensc_transplant_fuzz_pkcs15_reader.tar.gz opensc
run ntopng_transplant_fuzz_dissect_packet \
  $NS/ntopng/experiment-data/local_clnode389.db ntopng-24h-6fuzzer \
  $NS/ntopng/experiment-data/ntopng-24h-6fuzzer/experiment-folders fuzz_dissect_packet \
  $NS/ntopng/experiment-data/ntopng-24h-6fuzzer/coverage-binaries/coverage-build-ntopng_transplant_fuzz_dissect_packet.tar.gz ntopng
run libavc_transplant_svc_dec_fuzzer \
  $NS/libavc/experiment-data/local.db libavc-24h-6fuzzer \
  $NS/libavc/experiment-data/libavc-24h-6fuzzer/experiment-folders svc_dec_fuzzer \
  $NS/libavc/experiment-data/libavc-24h-6fuzzer/coverage-binaries/coverage-build-libavc_transplant_svc_dec_fuzzer.tar.gz libavc
run htslib_transplant_hts_open_fuzzer \
  $NS/htslib/experiment-data/local.db htslib-24h-6fuzzer \
  $NS/htslib/experiment-data/htslib-24h-6fuzzer/experiment-folders hts_open_fuzzer \
  $NS/htslib/experiment-data/htslib-24h-6fuzzer/coverage-binaries/coverage-build-htslib_transplant_hts_open_fuzzer.tar.gz htslib
run c-blosc2_transplant_decompress_frame_fuzzer \
  $NS/c-blosc2/experiment-data/local.db c-blosc2-24h-6fuzzer \
  $NS/c-blosc2/experiment-data/c-blosc2-24h-6fuzzer/experiment-folders decompress_frame_fuzzer \
  $NS/c-blosc2/experiment-data/c-blosc2-24h-6fuzzer/coverage-binaries/coverage-build-c-blosc2_transplant_decompress_frame_fuzzer.tar.gz c-blosc2
run ndpi_transplant_fuzz_ndpi_reader \
  $NS/ndpi/experiment-data/local_clnode205.db ndpi-reader-v2-24h \
  $NS/ndpi/experiment-data/ndpi-reader-v2-24h/experiment-folders fuzz_ndpi_reader \
  $NS/ndpi/experiment-data/ndpi-reader-v2-24h/coverage-binaries/coverage-build-ndpi_transplant_fuzz_ndpi_reader.tar.gz ndpi_reader
run ghostscript_transplant_gstoraster_fuzzer \
  $NS/ghostscript/experiment-data/local_clnode061.db ghostscript-min-24h-v2 \
  $NS/ghostscript/experiment-data/ghostscript-min-24h-v2/experiment-folders gstoraster_fuzzer \
  $NS/ghostscript/experiment-data/ghostscript-min-24h-v2/coverage-binaries/coverage-build-ghostscript_transplant_gstoraster_fuzzer.tar.gz gstoraster
# --- the two big ones last ---
run ndpi_transplant_fuzz_process_packet \
  $NS/ndpi/experiment-data/local.db ndpi-24h-6fuzzer \
  $NS/ndpi/experiment-data/ndpi-24h-6fuzzer/experiment-folders fuzz_process_packet \
  $NS/ndpi/experiment-data/ndpi-24h-6fuzzer/coverage-binaries/coverage-build-ndpi_transplant_fuzz_process_packet.tar.gz ndpi_process
run libredwg_transplant_llvmfuzz \
  $NS/libredwg/experiment-data/local.db libredwg-24h-6fuzzer \
  $NS/libredwg/experiment-data/libredwg-24h-6fuzzer/experiment-folders llvmfuzz \
  $NS/libredwg/experiment-data/libredwg-24h-6fuzzer/coverage-binaries/coverage-build-libredwg_transplant_llvmfuzz.tar.gz libredwg
echo "ATTRIBUTION_PASS1_DONE $(date +%F\ %H:%M)"
