# Why six fuzzers found zero grafted bugs in ghostscript `gs_device_pdfwrite_fuzzer`

Experiment: `gs-graft-500seed-24h-v4`, clnode116, 6 fuzzers x 10 trials x 24 h
(60 trials, all complete). Benchmark
`ghostscript_gs_device_pdfwrite_fuzzer_graft_4c4dcc85`: 25 transplanted bugs,
1 dispatch byte, 26 slots, slice 9. All 25 verified triggering by their PoC at
merge time (`bug_metadata.json`: `triggered: true` for 25/25).

Data: `/mnt/nas/linke/buggraft2609/ghostscript/fuzzing_gs-graft-500seed-24h-v4`.

**The zero is real, and it is not a benchmark defect.** Five things stack up, and
they are worth separating because only the last two are about the grafting
method itself.

---

## 1. What actually came out of the campaign

723 unique artifacts across all 60 trials. 718 are libFuzzer/AFL **timeouts**.
Five are real crashes:

| fuzzer | trial | artifacts | head byte | slot |
|---|---|---|---|---|
| afl | 4 | 1 crash | 0x00 | 0 |
| aflplusplus | 15 | 4 crashes | 0x00 | 0 |

All five carry head byte `0x00`, i.e. **slot 0 = no bug selected**. They are
baseline-Ghostscript crashes wearing no selector. `headbyte_triage.py` therefore
emits an empty CSV, and `dispatch_zero_replay.py` reports
`0 unique gated inputs staged` — correctly.

FuzzBench's own `bugs_covered` column agrees: median 0, max 2, and those are the
same baseline crash keys.

## 2. Throughput: ~1 exec/s, a 3-4 order-of-magnitude deficit

This is the single largest factor.

| fuzzer | measured | 24 h budget |
|---|---|---|
| libfuzzer | 73k-83k runs in 86,400 s | **0.89 exec/s** |
| libafl | 148k-157k execs, self-reported | **1.75 exec/s** |
| aflplusplus | `exec_us` p50 = 404 ms, p90 = 493 ms | **~2.4 exec/s** ceiling |
| honggfuzz | **92,708 of 92,735** persistent workers SIGKILLed at the 25 s limit | ~1 input / 25 s / thread |
| afl | after 24 h fuzzing queue entry **#11-#69** of a queue grown to 2,877-5,374 | never finished 14% of cycle 1 |
| fairfuzz | after 24 h queue entry **#1-#11** of 840-3,049 | ~one seed deep |

A normal FuzzBench target runs 10^3-10^4 exec/s, so ~10^8-10^9 executions per
trial. Here each trial gets ~10^5. AFL and fairfuzz are worse than the raw rate
suggests: they never completed one pass over the 512-seed queue, so the large
majority of seeds were never mutated at all.

Coverage confirms saturation rather than progress: **66-84% of the 24 h edge
count is reached in the first hour**, and the entire second half of each
campaign adds 1.1-7.3%.

| fuzzer | e@30m | e@1h | e@6h | e@12h | e@24h | 1h/24h | gain 12h->24h |
|---|---|---|---|---|---|---|---|
| afl | 32,410 | 32,600 | 38,676 | 42,208 | 45,295 | 72% | +7.3% |
| aflplusplus | 27,426 | 28,842 | 38,369 | 41,228 | 43,696 | 66% | +6.0% |
| fairfuzz | 23,334 | 25,050 | 32,475 | 33,880 | 35,748 | 70% | +5.5% |
| honggfuzz | 30,038 | 34,144 | 39,382 | 40,079 | 40,522 | 84% | +1.1% |
| libafl | 30,588 | 36,453 | 43,616 | 46,702 | 49,106 | 74% | +5.1% |
| libfuzzer | 37,012 | 37,168 | 44,403 | 47,106 | 48,746 | 76% | +3.5% |

Note the earlier 10,875-seed run (`v5`, retired for incomplete trials) reached
*more* edges (52k-64k median) and also found zero grafted bugs. The 500-seed
reduction was meant to stop corpus cycling from eating the budget; it did not
change the outcome, which means **corpus cycling was not the binding
constraint** -- per-execution cost is.

### Measured on clnode309 (2026-09-29): the cost is per-execution init, not input size

Timing the libFuzzer build on the 500 seeds, bucketed by size:

| bucket | n | median | mean | max |
|---|---|---|---|---|
| <=4 KB | 288 | 0.467 s | 0.563 s | 1.018 s |
| 4-16 KB | 71 | 0.542 s | 0.588 s | 1.019 s |
| 16-64 KB | 70 | 0.519 s | 0.618 s | 1.173 s |
| 64-256 KB | 53 | 0.967 s | 1.049 s | 2.073 s |
| >256 KB | 18 | 1.245 s | 1.479 s | 2.676 s |

A 1000x range in input size costs only 2.7x in time, and capping the corpus at
64 KB would buy **1.16x**. Driving it to the floor:

| input | median |
|---|---|
| 2 bytes | 0.465 s |
| 16 random bytes | 0.442 s |
| 1 KB random | 0.441 s |
| minimal PostScript | 0.415 s |
| 4.2 MB PDF | 1.245 s |

`-runs=0` (process start + libFuzzer init, no execution) is 0.265 s. **A
two-byte input costs as much as a one-kilobyte input.** The per-execution cost
is Ghostscript re-initialising its interpreter, device and font machinery on
every call, not parsing the input. No corpus or `max_len` tuning addresses
this; only a persistent harness that resets in-process would, and Ghostscript's
global state is why the OSS-Fuzz harness does not do that.

One config item is still worth fixing, though it is worth little: honggfuzz's
25 s per-input limit is below the tail of this target's mutant execution time,
so it spends essentially the whole campaign being killed and relaunched.

## 3. The selector byte is *not* the bottleneck

A natural first hypothesis is that fuzzers never guess a non-zero head byte.
The corpora refute it. Head-byte distribution of the final corpus (one trial per
fuzzer; slot = byte / 9):

| fuzzer | corpus | slot 0 | gated | distinct non-zero slots |
|---|---|---|---|---|
| libafl | 5,738 | 2,714 | **3,024 (53%)** | all 28 |
| honggfuzz | 1,983 | 1,830 | 153 (7.7%) | 22 |
| aflplusplus | 6,145 | 6,065 | 80 (1.3%) | 20 |
| libfuzzer | 6,087 | 6,023 | 64 (1.1%) | 8 |
| afl | 3,628 | 3,581 | 47 (1.3%) | 19 |
| fairfuzz | 3,087 | 3,075 | 12 (0.4%) | 10 |

Every fuzzer retained inputs selecting real bug slots; libafl's corpus is
majority-gated. libFuzzer is the outlier at 1% and 8 slots, consistent with the
entropic scheduler pruning inputs that add no new features -- which is exactly
what a gated input looks like once the gate edge has been covered once (see §5).

## 4. The crash sites are reached, heavily

Per-bug crash line from `bug_metadata.json`, looked up in the FuzzBench llvm-cov
report (execution count of that line, merged corpus):

| bug | slot | crash site | afl | aflplusplus | fairfuzz | honggfuzz | libafl | libfuzzer |
|---|---|---|---|---|---|---|---|---|
| OSV-2022-719 | 3 | gsgdata.c:119 | 164M | 162M | 58.1M | 2.95M | 49.6M | 104M |
| OSV-2022-744 | 6 | gsgdata.c:127 | 104M | 108M | 36.8M | 1.82M | 33.1M | 69.8M |
| OSV-2022-1194 | 19 | stream.c:607 | 42.5M | 47.5M | 22.4M | 5.99M | 21.8M | 35.1M |
| OSV-2022-757 | 8 | pdf_stack.h:73 | 1.87M | 2.29M | 684k | 33.1k | 500k | 1.20M |
| OSV-2022-751 | 7 | gstype2.c:200 | 327k | 267k | 153k | 3.00k | 460k | 517k |
| OSV-2024-503 | 24 | gdevpdfg.c:75 | 263k | 189k | 52.2k | 3.20k | 86.9k | 366k |
| OSV-2022-949 | 15 | gp.h:296 | 118k | 91.1k | 72.5k | 67.5k | 154k | 141k |
| OSV-2022-1208 | 20 | gdevpsfm.c:60 | 93.9k | 51.3k | 30.1k | 4.28k | 118k | 188k |
| OSV-2022-726 / OSV-2023-970 | 5 / 22 | gdevnfwd.c:33 | 68.3k | 59.1k | 33.7k | 1.69k | 36.4k | 330k |
| OSV-2022-522 / -523 | 1 / 2 | ttinterp.c:4347 / 4344 | 5.36k | 40.6k | 693 | not cov | 7.35k | 5.51k |
| OSV-2023-88 | 21 | pdf_font1C.c:789 | 400 | 1.16k | 330 | 14 | 517 | 1.36k |

Totals: **11-16 of the 21 measurable crash lines were reached** (afl 15,
aflplusplus 13, fairfuzz 13, honggfuzz 11, libafl 16, libfuzzer 14; 4 lines have
no count cell because llvm-cov attributes the region to a neighbouring line).

So this is emphatically **not** a reachability failure. Vulnerable code runs
tens of millions of times per trial.

## 5. The actual blocker: the grafted condition is a removed guard on a rare predicate

This is the part that matters for the paper.

Most of these transplants are **check removals**, wrapped as
`if (!__BUG_ACTIVE(n)) { <the bounds check> }`. There is no alternative code
block -- arming slot *n* merely *skips a validation*. Two consequences:

**(a) A memory error only follows if the skipped check would have fired.** That
conditional probability is directly measurable: the count on the check's
rejecting statement divided by the count on the check itself.

| bug(s) | slot(s) | guard site | check ran | would have rejected | P(reject) |
|---|---|---|---|---|---|
| OSV-2022-523 / -818 | 2, 11 | gstype42.c:1389 | 8,640 | 111 | **1.3e-2** |
| OSV-2022-719 / -724 / -751 | 3, 4, 7 | gstype2.c:186 | 2,520,000 | 516 | **2.1e-4** |
| OSV-2022-726 | 5 | pdf_image.c:521 | 15,100 | 2 | 1.3e-4 |
| OSV-2022-726 | 5 | pdf_image.c:1797 | 15,000 | 1 | 6.7e-5 |
| OSV-2022-866 | 13 | gstype2.c:678 | 10 | 0 | 0 observed |
| OSV-2022-1021 | 16 | gstype2.c:800 | 8 | 0 | 0 observed |
| OSV-2022-1194 | 19 | pdf_colour.c:2511 | 136 | 0 | 0 observed |
| OSV-2022-724 | 4 | gstype2.c:728 | 0 | - | region never entered |
| OSV-2024-503 | 24 | gdevpdfi.c:3187 | 0 | - | region never entered |

(libafl report; `CS_CHECK_IPSTACK`-style macro guards at gxtype1.c:486/508 run
11.5M times but expand to no separate line, so their rate is not observable from
line coverage.)

Multiplying through for the most favourable bug: 1.5e5 execs x 1/26 slot
probability x 1.3e-2 guard rate = **~0.07 expected triggers per trial**. For the
gstype2.c:186 family it is ~1e-3. Over 60 trials the campaign's total
expectation is a small single-digit number at best and effectively zero for most
of the set -- which is precisely what was observed. The zero is the predicted
outcome of the budget, not an anomaly.

**(b) Where the bug *is* a distinct code block, we can prove it ran and still
did not crash.** Counting executions of the statements strictly inside
`if (__BUG_ACTIVE(n)) { ... }`:

| bug | slot | buggy statement | afl | aflplusplus | fairfuzz | honggfuzz | libafl | libfuzzer |
|---|---|---|---|---|---|---|---|---|
| OSV-2022-888 | 14 | gstype2.c:512 | 5.34k | 1.3k | 2.11k | 28 | 24.1k | **49.7k** |
| OSV-2022-1208 | 20 | pdf_cmap.c:139 / pdf_deref.c:1015 | **547k** | 368k | 196k | 10k | 284k | 389k |
| OSV-2022-818 | 11 | gstype42.c:1389 | 0 | 0 | 0 | 0 | 7.29k | 0 |
| OSV-2022-772 | 9 | pdf_font11.c:119 | 0 | 0 | 0 | 0 | 71 | 0 |
| OSV-2022-949 | 15 | gdevpdtb.c:752 | 0 | 0 | 0 | 0 | 10 | 0 |
| OSV-2024-503 | 24 | gdevpdfi.c:3133 | 7 | 0 | 0 | 0 | 0 | 0 |
| OSV-2024-1391 | 25 | gsicc_create.c:3279 | 4 | 0 | 0 | 0 | 0 | 0 |
| OSV-2022-1097 | 17 | gstype2.c:820 | 0 | 0 | 0 | 0 | 0 | 0 |
| OSV-2022-1148 | 18 | gstype2.c:876 | 0 | 0 | 0 | 0 | 0 | 0 |
| OSV-2023-970 | 22 | gdevpdfi.c:2262 | 0 | 0 | 0 | 0 | 0 | 0 |

For OSV-2022-888 and OSV-2022-1208 the bug was **selected, reached, and executed
hundreds of thousands of times, and still produced no sanitizer report.** Take
OSV-2022-888 concretely. The graft removes `if (ap + 1 <= csp)` around
`t1_hinter__rlineto(h, ap[0], ap[1])`, and the enclosing loop is
`for (ap = cstack; ap + 5 <= csp; ...)`. OSV records the bug as
*Stack-buffer-overflow READ 4*. Skipping the check lets `ap` pass the live stack
*top* -- but ASan only reports when the read passes the end of the `cstack`
**array**, past its redzone. Reading a few elements beyond `csp` while still
inside `cstack` is not a violation at all. The removed check is a far weaker
condition than the detectable fault.

That generalises across the set. **19 of 25 bugs are READ violations, 13 of them
1-4 bytes wide:**

| count | crash type |
|---|---|
| 4 | Stack-buffer-underflow READ 4 |
| 4 | Heap-buffer-overflow READ 1 |
| 3 | Heap-use-after-free READ 8 |
| 2 | Stack-buffer-overflow WRITE 8 |
| 2 | UNKNOWN WRITE |
| 1 each | Heap-buffer-overflow READ 4 / READ 12 / READ {*} / WRITE 8; Stack-buffer-overflow READ 1 / READ 4 / WRITE 1; Stack-buffer-underflow; Heap-UAF READ 1; Stack-use-after-return READ 4; Segv |

Small off-by-a-few reads are the least detectable class: the index must land in
a redzone, not merely outside the logical bound. The three heap-UAF bugs need a
free and a use to line up in one execution, which reaching the site does not
give you.

## 6. Ordering of causes (for the paper)

1. **Per-execution cost.** ~1 exec/s gives ~10^5 executions per trial against
   10^8-10^9 on a normal target. Everything else is multiplied by this.
2. **Detectability of the grafted fault.** 19/25 bugs are READs, 13 of them 1-4
   bytes. Reaching and even executing the buggy code is not sufficient; the
   access must land in a redzone.
3. **Rarity of the removed guard's predicate.** Measured at 1e-4 to 1e-2 where
   observable, zero for several bugs. This is the term that makes the expected
   trigger count ~0 even with the slot armed.
4. **Selector dilution.** 1/26 of the input space per bug, and the selector is
   coverage-neutral after its gate edge is first covered, so there is no gradient
   to follow. Visible as libFuzzer's entropic scheduler keeping only 1% gated
   inputs vs libafl's 53%.
5. **Seed-queue starvation** (AFL, fairfuzz only). Neither completed one pass
   over 512 seeds in 24 h, so most seeds were never mutated.

Causes 1, 4 and 5 are properties of the harness/benchmark and are partly
fixable. Causes 2 and 3 are properties of the *bugs* -- they are what makes
these real OSS-Fuzz findings hard, and they are the honest reason a 24 h
six-fuzzer campaign finds none of them.

## 7. Actionable follow-ups

Measured on clnode309, the throughput term has **no cheap fix**: per-execution
Ghostscript initialisation dominates and is input-independent (see the tables in
§2). Seed trimming and `-max_len` were my first proposal and the measurement
refuted them -- a 64 KB cap is worth 1.16x. What remains:

* **Budget, not tuning.** Report bug-finding on this target against an execution
  budget rather than wall-clock. A 7-day campaign gives ~1.2M executions per
  trial against ~10^5 at 24 h -- roughly 12x, and still four orders of magnitude
  below a normal FuzzBench target.
* **Raise honggfuzz's per-input timeout** above 25 s; 99.97% of its persistent
  workers were killed by the limit.
* `-max_len=65536` is free and keeps mutants out of the 2x-slower >64 KB band,
  but it is a second-order effect, not a fix.

Resolved, no longer an open caveat:

* `detect_stack_use_after_return=1` **was** active. `common/sanitizer.py` sets
  it in `ADDITIONAL_ASAN_OPTIONS` for every fuzz run, independent of the
  benchmark Dockerfile's `ENV`. So **OSV-2022-1097** was detectable, and its
  gate body executing 0 times means it was genuinely never reached -- not
  masked by a missing sanitizer option. (Note libafl's `fuzzer.py` overwrites
  `ASAN_OPTIONS` wholesale at lines 25/48, so libafl alone runs without it;
  the other five carry it.)

Still open:

* The five slot-0 crashes are unattributed baseline Ghostscript bugs. They are
  worth deduplicating and naming, since a paper claiming "0 bugs found" while
  the campaign produced 5 real crashes invites the question.
