#!/bin/bash
# Pass 2 -- ungated (fix-gated) attribution of the graft-independent classes.
# Runs against the ungated replay containers (docker ps | grep ungated_).
# Data source: /mnt/nas/linke/new_seeds ONLY, each target from its own
# project's folder.  All 10 targets are listed; a target whose replay binary
# is not built yet SKIPs with a message instead of producing empty verdicts.
cd /home/user/oss-fuzz-build
NS=/mnt/nas/linke/new_seeds
OUT=${OUT:-/home/user/paper1/data/bug_attr/ungated}
# Pass 1's verdicts select the classes to sweep: graft-independent means
# "reproduces with every bit clear", not "was found with no bit set".
P1=${P1:-/home/user/paper1/data/bug_attr}
mkdir -p $OUT

# Bring up a replay container if it is not already running.  The binary lives
# in a host dir mounted at /out (that is why the ungated-base images ship an
# empty /out), so recreating the container is enough as long as that dir still
# holds the build; if it does not, the target needs its merge/build re-run and
# we say so instead of sweeping it into a NON-REPRODUCING result.
ensure_container() {  # 1=container 2=image 3=work-dir 4=project 5=/out/binary
  local c=$1 img=$2 w=$3 proj=$4 tp=$5
  if [ "$(docker inspect -f '{{.State.Running}}' $c 2>/dev/null)" = "true" ]; then
    docker exec $c test -x $tp && return 0
    echo "!! $c is up but $tp is missing -- rebuild it before this run"; return 1
  fi
  if [ ! -x "$w/out/${tp##*/}" ]; then
    echo "!! no built replay binary at $w/out/${tp##*/} -- run the merge/build for $proj first"
    return 1
  fi
  # Run on the resolved image id, never the tag: ungated-base:* tags are
  # rebuilt in place, so a tag cannot say which environment a verdict came from.
  local id
  id=$(docker image inspect -f '{{.Id}}' "$img" 2>/dev/null) || {
    echo "!! image $img not present -- build it before this run"; return 1; }
  echo "== creating $c from $img ($id)"
  docker rm -f $c >/dev/null 2>&1 || true
  docker run -d --name $c --privileged --shm-size=2g --entrypoint sleep \
    -v "$w/tree:/src/$proj" -v "$w/out:/out" -v "$w/inputs:/inputs:ro" \
    "$id" infinity >/dev/null
  docker exec $c test -x $tp
}

run() {  # 1=merge-dir 2=benchmark 3=project 4=container 5=/out/binary
         # 6=db 7=experiment 8=folders 9=name  [10..=extra flags]
  local m=$1 b=$2 p=$3 c=$4 t=$5 db=$6 e=$7 f=$8 n=$9; shift 9
  local img=$1 w=$2; shift 2
  echo "########## $n $(date +%F\ %H:%M)"
  ensure_container "$c" "$img" "$w" "$p" "$t" || { echo "   SKIPPED $n"; return; }
  # Prefer the necessity sweep's verdicts; fall back to the older sufficiency
  # sweep's classes file for targets that have not been re-run yet.
  local sel="--graft-independent"
  if [ -f "$P1/${n}_necessity.csv" ]; then
    sel="--level1 $P1/${n}_necessity.csv"
  elif [ -f "$P1/${n}_classes.csv" ]; then
    sel="--level1 $P1/${n}_classes.csv"
  else
    echo "   !! no $P1/${n}_classes.csv -- falling back to the recorded-prefix"
    echo "      filter, which reaches only ~16% of the graft-independent classes"
  fi
  timeout 86400 python3 script/ungated_attribute.py \
    --merge-dir data/ungated/$m \
    --benchmark-dir fuzzbench/benchmarks/$b \
    --target $p --container $c --target-path $t \
    --db "$db" --experiment "$e" --folders "$f" \
    $sel --jobs 4 --out $OUT/$n "$@" 2>&1 | tail -20
  # ungated_attribute always writes attribution.{csv,json} + run_metadata.json
  # into --out; flatten to the names the paper's data set uses.
  cp $OUT/$n/attribution.csv      $OUT/${n}_causal_attribution.csv      2>/dev/null
  cp $OUT/$n/attribution.json     $OUT/${n}_causal_attribution.json     2>/dev/null
  cp $OUT/$n/run_metadata.json    $OUT/${n}_causal_attribution.meta.json 2>/dev/null
}

run merge_offline_htslib_dd6f0b72 htslib_transplant_hts_open_fuzzer htslib \
  ungated_htslib_replay /out/hts_open_fuzzer \
  $NS/htslib/experiment-data/local.db htslib-24h-6fuzzer \
  $NS/htslib/experiment-data/htslib-24h-6fuzzer/experiment-folders htslib \
  ungated-base:htslib-hts_open_fuzzer /home/user/oss-fuzz-build/build/ungated/htslib_replay

run merge_offline_c-blosc2_79e921d9 c-blosc2_transplant_decompress_frame_fuzzer c-blosc2 \
  ungated_c-blosc2 /out/decompress_frame_fuzzer \
  $NS/c-blosc2/experiment-data/local.db c-blosc2-24h-6fuzzer \
  $NS/c-blosc2/experiment-data/c-blosc2-24h-6fuzzer/experiment-folders c-blosc2 \
  ungated-base:c-blosc2 /home/user/oss-fuzz-build/build/ungated/c-blosc2

run merge_offline_libavc_c38af025 libavc_transplant_svc_dec_fuzzer libavc \
  ungated_libavc_replay /out/svc_dec_fuzzer \
  $NS/libavc/experiment-data/local.db libavc-24h-6fuzzer \
  $NS/libavc/experiment-data/libavc-24h-6fuzzer/experiment-folders libavc \
  ungated-base:libavc-svc_dec_fuzzer /home/user/oss-fuzz-build/build/ungated/libavc_replay \
  --positive-attempts 10

run merge_offline_ntopng_b7b2810e ntopng_transplant_fuzz_dissect_packet ntopng \
  ungated_ntopng_replay /out/fuzz_dissect_packet \
  $NS/ntopng/experiment-data/local_clnode389.db ntopng-24h-6fuzzer \
  $NS/ntopng/experiment-data/ntopng-24h-6fuzzer/experiment-folders ntopng \
  ungated-base:ntopng-fuzz_dissect_packet /home/user/oss-fuzz-build/build/ungated/ntopng_replay

run merge_offline_opensc_6903aebf opensc_transplant_fuzz_pkcs15_reader opensc \
  ungated_opensc_replay /out/fuzz_pkcs15_reader \
  $NS/opensc/experiment-data/local.db opensc-24h-6fuzzer \
  $NS/opensc/experiment-data/opensc-24h-6fuzzer/experiment-folders opensc \
  ungated-base:opensc-fuzz_pkcs15_reader /home/user/oss-fuzz-build/build/ungated/opensc_replay \
  --runs 100

run merge_offline_ndpi_e695dd6e ndpi_transplant_fuzz_process_packet ndpi \
  ungated_ndpi_process /out/fuzz_process_packet \
  $NS/ndpi/experiment-data/local.db ndpi-24h-6fuzzer \
  $NS/ndpi/experiment-data/ndpi-24h-6fuzzer/experiment-folders ndpi_process \
  ungated-base:ndpi-fuzz_process_packet /home/user/oss-fuzz-build/build/ungated/ndpi_process

run merge_offline_ndpi_5cad39f0 ndpi_transplant_fuzz_ndpi_reader ndpi \
  ungated_ndpi_reader /out/fuzz_ndpi_reader \
  $NS/ndpi/experiment-data/local_clnode205.db ndpi-reader-v2-24h \
  $NS/ndpi/experiment-data/ndpi-reader-v2-24h/experiment-folders ndpi_reader \
  ungated-base:ndpi-fuzz_ndpi_reader /home/user/oss-fuzz-build/build/ungated/ndpi_reader

# gstoraster: 67 ungated bits -> 69 probes per class on the linear scan.
# --group-bits cuts that to ~12, at the cost of inferring rejections.
run merge_offline_ghostscript_2be8b436 ghostscript_transplant_gstoraster_fuzzer ghostscript \
  ungated_gstoraster_fuzzer /out/gstoraster_fuzzer \
  $NS/ghostscript/experiment-data/local_clnode061.db ghostscript-min-24h-v2 \
  $NS/ghostscript/experiment-data/ghostscript-min-24h-v2/experiment-folders gstoraster \
  ungated-agent-ghostscript-gstoraster_fuzzer:latest /home/user/oss-fuzz-build/build/ungated/ghostscript \
  --group-bits

# gs_pdfwrite: its container was repurposed for gstoraster, but the built
# binary is still on disk, so ensure_container just recreates it.
run merge_offline_ghostscript_e088d3a8 ghostscript_transplant_gs_device_pdfwrite_fuzzer ghostscript \
  ungated_gs_pdfwrite /out/gs_device_pdfwrite_fuzzer \
  $NS/ghostscript/experiment-data/local_clnode205.db gspdf-24h-6fuzzer \
  $NS/ghostscript/experiment-data/gspdf-24h-6fuzzer/experiment-folders gs_pdfwrite \
  ungated-base:ghostscript-gs_device_pdfwrite_fuzzer /home/user/oss-fuzz-build/build/ungated/ghostscript_pdfwrite

# libredwg: needs script/run_ungated_merge_libredwg.sh first (no merge dir /
# no built binary until then); this line SKIPs cleanly until it exists.
run merge_offline_libredwg_a67ea97d libredwg_transplant_llvmfuzz libredwg \
  ungated_libredwg /out/llvmfuzz \
  $NS/libredwg/experiment-data/local.db libredwg-24h-6fuzzer \
  $NS/libredwg/experiment-data/libredwg-24h-6fuzzer/experiment-folders libredwg \
  ungated-base:libredwg-llvmfuzz /home/user/oss-fuzz-build/build/ungated/libredwg

echo "ATTRIBUTION_PASS2_DONE $(date +%F\ %H:%M)"
