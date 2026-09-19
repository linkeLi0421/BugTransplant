# dataset/ — everything this repo needs to run, in the repo

Inputs only. Pipeline *outputs* still go to `data/` (transplant diffs, traces,
crash logs), which stays untracked.

```
dataset/
  csv/per_target/<project>_<fuzz_target>.csv   10 bug matrices, one per target
  csv/builds/<project>_builds.csv              commit -> OSS-Fuzz image
  osv_testcases_summary.json                   OSV metadata, the 357 bugs used here
  osv_testcases_summary_all.json               OSV metadata, all 2,154 bugs
  testcases/testcase-<bug-id>                  357 PoCs, 8.4 MB
```

## The ten targets

Every `*_transplant_*` / `*_graft_*` benchmark under `fuzzbench/benchmarks/`
maps to one of these:

| project | fuzz target | commits | bugs |
|---|---|--:|--:|
| c-blosc2 | decompress_frame_fuzzer | 1643 | 34 |
| ghostscript | gs_device_pdfwrite_fuzzer | 156 | 27 |
| ghostscript | gstoraster_fuzzer | 256 | 96 |
| htslib | hts_open_fuzzer | 685 | 24 |
| libavc | svc_dec_fuzzer | 136 | 21 |
| libredwg | llvmfuzz | 204 | 68 |
| ndpi | fuzz_ndpi_reader | 2116 | 46 |
| ndpi | fuzz_process_packet | 176 | 78 |
| ntopng | fuzz_dissect_packet | 195 | 20 |
| opensc | fuzz_pkcs15_reader | 766 | 27 |

Verified: every bug in all 13 transplant/graft benchmarks appears as a column
in its target's matrix (0 missing), and all 357 have a PoC here.

## Matrix format

`commit_id` then one column per bug. A cell is `<triggers>|<builds>`, e.g.
`1|1` builds and triggers, `0.5|0` builds but does not. `buildAndtest.py`
writes these.

The c-blosc2 and libavc matrices are a **union** of the project-level and
per-target CSVs in `~/log`: the per-target files were stale and between them
they were missing 17 bugs that the benchmarks use. For both projects every
OSV bug in the project-level file targets that one fuzz target, so the union
is still per-target. The other eight are verbatim copies.

## Using it

```bash
export TESTCASES=$PWD/dataset/testcases
export BUGINFO_PATH=$PWD/dataset/osv_testcases_summary.json

python3 script/bug_transplant_batch.py dataset/csv/per_target/<proj>_<tgt>.csv \
  --bug_info $BUGINFO_PATH \
  --build_csv dataset/csv/builds/<proj>_builds.csv \
  --target <proj>
```

`script/setenv.sh` still points at the old absolute paths outside the repo;
override the two variables above, or update setenv.sh, to run self-contained.

## Not included

Docker images and project source. `builds.csv` pins the OSS-Fuzz image per
commit, so those are fetched, not vendored.
