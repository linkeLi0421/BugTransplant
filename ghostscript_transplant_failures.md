# Ghostscript gstoraster: transplant failures (final, 2026-10-02)

Target ghostscript `1d4dbb31` (2022-08-08), fuzz target `gstoraster_fuzzer`, 89 bugs attempted.
The benchmark in the fuzzbench repo (`ghostscript_gstoraster_fuzzer_graft_1d4dbb31`, 87 bugs,
90 slots, slice 2) is the result of record and is **not** changed by anything below.

Outcome of the pipeline (agent transplants, verified reruns of 2026-09-28):

| Bug | Pipeline result | In benchmark | Reason |
|---|---|---|---|
| OSV-2022-339 | not transplanted | no (slot 74 empty) | double-fixed bug, see §1 |
| OSV-2022-79  | transplanted (2nd attempt) | no (slot 57 empty) | heap-exhaustion trigger does not survive merging, §2 |
| OSV-2021-1684, -1687, OSV-2022-177 | transplanted on rerun | yes (slots 87-89) | first-run failures were infrastructure/metadata, §3 |
| other 84 | transplanted | yes | — |

## 1. OSV-2022-339 — the bug was fixed twice; the agent only ever reverted one fix

Crash: heap-use-after-free in the PostScript garbage collector at exit (`gc_trace`), freed by a
`restore`. Mechanism, from the fix's commit message: the PDF interpreter's operand stack overflows
and returns the generic `gs_error_stackoverflow`; the PostScript interpreter, which shares the error
space, takes this as an overflow of *its own* operand stack and extends it by zero elements; the
orphaned stack block is later traversed by the GC and references objects already freed by a
`restore`.

Two consecutive commits on 2022-04-14, same author, each remove the crash on their own:

* `4fae247b3` (C) "oss-fuzz 46672: Avoid PS stack extensions from pdfi error" — introduces a
  dedicated `gs_error_pdf_stackoverflow`, so the PostScript extension never happens.
* `9adc7cda` (PostScript, `Resource/Init/pdf_main.ps`) "Slight tidy up of
  /newpdf_gather_parameters", "noticed in passing when working on oss-fuzz 46672" — the 32-entry
  `PDFSwitches` array, previously rebuilt inside a local dictionary on every call, becomes one
  permanent object. The orphaned stack block no longer references a restore-freed object.

OSV records only the second. Measured at the target (original PoC):

| target `1d4dbb31` with | result |
|---|---|
| nothing reverted | clean |
| C fix reverted only | clean (instrumented: the overflow error reaches the PS extension code with `requested=0`, twice per run — mechanism restored, no UAF) |
| PostScript tidy-up reverted only | clean (0/3) |
| both reverted | heap-use-after-free in `gc_trace`, 5/5, stack identical to the original report |

`git bisect` from the C fix to the target, with the C fix reverted at every step, names
`9adc7cda` as the single commit after which the crash disappears.

Why the agent failed: not for lack of information. Every session found the C fix on its own, and
three of five also inspected `9adc7cda`; one wrote "both OSV 'fixed' hashes are decoys unrelated to
the bug". No session reverted `9adc7cda`, edited `pdf_main.ps`, or tried the two reverts together:
a 30-line stylistic change to a PostScript procedure, far from the C crash path, was dismissed by
reading rather than by experiment. The sessions were also cut short (three provider HTTP 400s, one
stop after context compaction, one 3-hour budget) before any bisection. The post-hoc transplant
(both reverts, `data/bug_transplant/ghostscript_OSV-2022-339/`) is recorded but deliberately **not**
added to the benchmark, so the published benchmark reflects what the pipeline produced.

Note the PoC runs clean at the target in ~31 s; the "timeout" seen in the merge verifier was its
10-runs-per-120-s cap, not a property of the bug.

## 2. OSV-2022-79 — transplanted, but the trigger is a heap-exhaustion event that merging disturbs

The dataset's buggy commit (`3c317be3`) already contained the fix and its recorded crash log came from
a different crash on an older tree; re-run at the pre-fix commit `717f8968`, the agent produced a
correct transplant (the first hunk of fix `b0f97408`) whose PoC crashes on the reference stack
(`gp_semaphore_close` ← `icc_linkcache_finalize` ← `gsicc_cache_new`). The crash only occurs when an
allocation inside `gsicc_cache_new` fails at the harness's 1 GiB cap, and the PoC is padded to hit
that point within ~100 bytes in the single-bug build. In the 88-patch merged build the allocation
pattern differs and the PoC no longer reaches the failing allocation (0/40 in the merge check, 0/20 in
replays at 2 GB and 24 GB). The same class occurs on pdfwrite OSV-2022-727.

## 3. OSV-2021-1684, OSV-2021-1687, OSV-2022-177 — first-run failures, recovered on rerun

* 1684: the first session died on a provider error. The PoC had to be rebuilt as a minimal PDF
  because the target's parser rejects the original's fake trailer; the code change is the exact
  revert of fix `7fe54b1d`.
* 1687: OSV's fix commit `31e249d5` is an ancestor of the buggy commit (OSS-Fuzz re-matched a later
  crash to the old issue); the real fix is `4107288eb`. Original PoC, verified both directions.
* 177: reverting fix `c8051ae` alone is masked by an unrelated reference-counting commit
  (`56c467bf2`, "don't reuse stack references"); found by bisection, minimised to one extra `pdfi_pop`.
  The first session's "impossible" verdict was wrong.

## Cross-cutting

* Fix metadata is unreliable in three ways seen here: the recorded fix predates the buggy commit
  (1687, 79), the recorded buggy commit already contains the fix (79), and the recorded fix is one of
  two independent fixes (339).
* Incidental changes outside the fix mask crashes (177, 339); bisection with the revert applied finds
  them in ~8 builds.
* Triggers that depend on resource exhaustion at an exact point (79, 727) do not survive the merged
  build even when the transplant is correct.
* With post-agent verification off, three sessions' "successes" were debug prints; the reruns used
  `--verify`.
