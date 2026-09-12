#!/bin/bash
# Replay one campaign crash at chosen dispatch masks, by hand.
#
#   script/handcheck_pass1.sh <target> <testcase> [mask ...]
#
# Extracts the crash from the NAS tarballs, rebuilds the input as
# [dispatch prefix][payload] for each mask, replays it in the target's pinned
# runner image on the campaign coverage build, and prints the sanitizer class
# plus the top frames.  Masks are DECIMAL bit values (1, 2, 4, ... 16384) --
# the same numbers pass 1 records in `repro_masks`.
set -u
T=${1:?target, e.g. c-blosc2}; TC=${2:?testcase, e.g. crash-abc123}; shift 2
MASKS=${*:-0}
W=/home/user/abl_work/bug_attr
H=$W/handcheck/$T; mkdir -p "$H"

case $T in
  c-blosc2)     B=c-blosc2_transplant_decompress_frame_fuzzer;      BIN=decompress_frame_fuzzer;      P=c-blosc2;    E=c-blosc2-24h-6fuzzer ;;
  htslib)       B=htslib_transplant_hts_open_fuzzer;                BIN=hts_open_fuzzer;              P=htslib;      E=htslib-24h-6fuzzer ;;
  libavc)       B=libavc_transplant_svc_dec_fuzzer;                 BIN=svc_dec_fuzzer;               P=libavc;      E=libavc-24h-6fuzzer ;;
  libredwg)     B=libredwg_transplant_llvmfuzz;                     BIN=llvmfuzz;                     P=libredwg;    E=libredwg-24h-6fuzzer ;;
  ntopng)       B=ntopng_transplant_fuzz_dissect_packet;            BIN=fuzz_dissect_packet;          P=ntopng;      E=ntopng-24h-6fuzzer ;;
  opensc)       B=opensc_transplant_fuzz_pkcs15_reader;             BIN=fuzz_pkcs15_reader;           P=opensc;      E=opensc-24h-6fuzzer ;;
  ndpi_process) B=ndpi_transplant_fuzz_process_packet;              BIN=fuzz_process_packet;          P=ndpi;        E=ndpi-24h-6fuzzer ;;
  ndpi_reader)  B=ndpi_transplant_fuzz_ndpi_reader;                 BIN=fuzz_ndpi_reader;             P=ndpi;        E=ndpi-reader-v2-24h ;;
  gs_pdfwrite)  B=ghostscript_transplant_gs_device_pdfwrite_fuzzer; BIN=gs_device_pdfwrite_fuzzer;    P=ghostscript; E=gspdf-24h-6fuzzer ;;
  gstoraster)   B=ghostscript_transplant_gstoraster_fuzzer;         BIN=gstoraster_fuzzer;            P=ghostscript; E=ghostscript-min-24h-v2 ;;
  *) echo "unknown target $T"; exit 1 ;;
esac
NS=/mnt/nas/linke/new_seeds/$P/experiment-data
COV=$W/$T/covbin
[ -x "$COV/$BIN" ] || { echo "no coverage build at $COV/$BIN -- run pass 1 for $T first"; exit 1; }

python3 - "$T" "$TC" "$H" "$NS/$E/experiment-folders" "$MASKS" <<'PY'
import sys
sys.path.insert(0, '/home/user/oss-fuzz-build/script')
from pathlib import Path
import json
from two_level_triage import extract, mask_prefix, load_meta
target, tc, hostdir, folders, masks = sys.argv[1:6]
bench = {'c-blosc2':'c-blosc2_transplant_decompress_frame_fuzzer','htslib':'htslib_transplant_hts_open_fuzzer',
 'libavc':'libavc_transplant_svc_dec_fuzzer','libredwg':'libredwg_transplant_llvmfuzz',
 'ntopng':'ntopng_transplant_fuzz_dissect_packet','opensc':'opensc_transplant_fuzz_pkcs15_reader',
 'ndpi_process':'ndpi_transplant_fuzz_process_packet','ndpi_reader':'ndpi_transplant_fuzz_ndpi_reader',
 'gs_pdfwrite':'ghostscript_transplant_gs_device_pdfwrite_fuzzer','gstoraster':'ghostscript_transplant_gstoraster_fuzzer'}[target]
bdir = Path('/home/user/oss-fuzz-build/fuzzbench/benchmarks')/bench
meta, nbytes, bits, always = load_meta(bdir)
inv = {v: k for k, v in bits.items()}
h = Path(hostdir)
if not (h/tc).exists():
    extract(folders, {tc}, h)
if not (h/tc).exists():
    raise SystemExit(f"{tc} not found in {folders}")
payload = (h/tc).read_bytes()[nbytes:]
for m in [int(x) for x in masks.split()]:
    (h/f"{tc}.m{m}").write_bytes(mask_prefix(m, nbytes) + payload)
    who = [inv[b] for b in sorted(bits.values()) if m >> b & 1]
    print(f"  mask {m:<8} = {' + '.join(who) if who else 'no graft'}")
PY

# The sanitizer options FuzzBench's measurer recorded these crashes with.
# detect_stack_use_after_return=1 in particular decides whether many c-blosc2
# crashes reproduce at all.
ASAN=$(python3 -c 'import sys; sys.path.insert(0,"/home/user/oss-fuzz-build/script"); import two_level_triage as t; print(t.MEASURER_ASAN)')
IMG=gcr.io/fuzzbench/runners/libfuzzer/$B:latest
echo
docker run --rm -v "$COV:/out" -v "$H:/in:ro" \
  -e ASAN_OPTIONS="$ASAN" -e UBSAN_OPTIONS=print_stacktrace=0:halt_on_error=0 \
  --entrypoint bash "$IMG" -c '
for m in '"$MASKS"'; do
  out=$(timeout 240 /out/'"$BIN"' -runs=10 "/in/'"$TC"'.m$m" 2>&1)
  # ASan prints SEGV in caps, so match any case; lowercase for display.
  cls=$(printf "%s" "$out" | grep -m1 -oE "ERROR: [A-Za-z]+Sanitizer: [A-Za-z0-9_-]+" | sed "s/.*: //" | tr "A-Z" "a-z")
  addrs=$(printf "%s" "$out" | grep -E "^ +#[0-9]+ 0x" | head -3 \
          | grep -oE "\+0x[0-9a-f]+\)" | tr -d "+)" )
  frames=""
  for a in $addrs; do
    f=$(addr2line -f -C -e /out/'"$BIN"' "$a" 2>/dev/null | head -1)
    frames="$frames${f:-?} "
  done
  printf "  mask %-8s %-26s %s\n" "$m" "${cls:-no crash}" "$frames"
done'
