# FuzzBench 实验 — 机器分配与状态记录

> 本文件分两轮：**§0 = 2026-09 bug-graft 轮（当前）**；§1–§6 = 2026-08 new_seeds 轮（历史记录，保持原样）。

## 0. 2026-09 bug-graft 轮（buggraft2609）

**benchmark**：各项目的 `<project>_<target>_graft_<commit>`（transplant 合并后的多 bug 版本，单字节独占 dispatch：
`slot = head_byte / slice`，slot 0 = 无 bug）
**配置**：10 trials × 24h × 6 fuzzers；种子 = dispatch-zero 公共语料
**NAS 归档**：`/mnt/nas/linke/buggraft2609/<project>/`（每个 target 只保留一个 `fuzzing_<exp>`，其余改名 `__retired`；
`analysis/` 下是 head-byte 归因 CSV 和 dispatch-zero 重放结果）

### 0.1 结果（dispatch-zero 重放确认的 bug；每格 = 单 trial 最高 bug 数）

「确认」= 该 crash 输入原样重放必崩、把 head byte 置零后不崩（`script/dispatch_zero_replay.py`，libFuzzer 构建重放）。
只看 head byte 会把基线代码的崩溃算到某个 bug 头上，所以以此为准。

| Benchmark | 实验名 | 节点 | graft bug 数 | 确认（并集） | afl | aflplusplus | fairfuzz | honggfuzz | libafl | libfuzzer |
|---|---|---|--:|--:|--:|--:|--:|--:|--:|--:|
| c-blosc2 | `c-blosc2-graft-24h-6fuzzer-v3` | 未记录 | 29 | 21 | 9 | 9 | 3 | **12** | 10 | 10 |
| htslib | `htslib-graft-4c1acb8f-24h-v3` | 未记录 | 11 | 4 | 1 | 3 | 0 | 3 | **4** | 2 |
| libredwg | `libredwg-graft-b9a24941-24h-v2` | clnode109 | 62 | 38 | 15 | 19 | 13 | **22** | 17 | 9 |
| ndpi / reader | `ndpi-reader-graft-24h-v2` | clnode101 | 35 | 32 | 11 | 12 | 1 | 20 | **21** | 11 |
| ndpi / packet | `ndpi-pkt-graft-6c581e1a-24h-v2` | clnode151 | 33 | 27 | 12 | 0 ‡ | **16** | 11 | 10 | 14 |
| ntopng | `ntopng-graft-08a87f27-24h-v2` | clnode309 | 18 | 15 | 7 | **8** | 3 | 5 | 7 | 7 |
| opensc | `opensc-graft-24h-6fuzzer-10t` | clnode151 | 23 | 20 | 2 | 5 | 0 | **10** | 7 | 3 |
| **小计（7 个）** | | | 211 | 157 | 57 | 56 | 36 | **83** | 76 | 56 |
| libavc / svc_dec | `libavc-svc-dec-graft-24h-v1` | clnode309 | — | 未重放 | | | | | | |
| ghostscript / pdfwrite | `gs-graft-500seed-24h-v4` | clnode116 | 25 | **0** | 见 §0.3 | | | | | |

‡ ndpi-packet 的 aflplusplus 在 triage 和重放里都**没有任何 crash 记录**（10 个 trial 全空），原因未查，不能当作「找到 0 个」。
graft bug 数 = dispatch slot 数 − 1。libavc 的 `analysis/` 是**已退役的 v3 run**（18 bugs，确认 14），
保留的 svc_dec v1 还没做重放。确认数不等于 bug 数上限：同一 bug 的 crash 可能来自多个 trial，并集按 bug 去重。

### 0.2 进行中（2026-09-26）

| 实验 | 节点 | fuzzer | 开始 | 状态 |
|---|---|---|---|---|
| `gs-500seed-t5k-afl` | clnode116 (`/mydata/BugTransplant/fuzzbench`) | afl, aflplusplus, fairfuzz | 09-26 ~09:00 UTC | 30 runner 在跑，约 09-27 09:00 结束 |
| `gs-500seed-t5k-rest` | clnode123 (`/mydata/fuzzbench`) | honggfuzz, libafl, libfuzzer | 09-26 ~09:00 UTC | 30 runner 在跑，约 09-27 09:00 结束 |

- benchmark `ghostscript_gs_device_pdfwrite_fuzzer_graft_4c4dcc85`，500 种子 corpus，`snapshot_period: 1800`。
- 两台各跑 3 个 fuzzer，结束后要把两个实验合并成一个再归档（同 §2 的三层合并）。
- 与 v4 的区别：libafl 单次执行超时从默认 1200ms 改为 5000ms（fuzzbench `8c6f5a5a`），与 afl 系（`-t 5000+`）对齐；
  honggfuzz 25s、libfuzzer 1200s 不变。
- tmux 会话名 `gsfuzz`，日志 `/mydata/<实验名>.log`。
- 另：本地正在重做 ghostscript gstoraster 的 merge（86 slot，新增 OSV-2022-3 / OSV-2022-456），
  5 个 transplant 失败的原因见 `ghostscript_transplant_failures.md`。

### 0.3 ghostscript pdfwrite（v4）为什么是 0

- 归档里有 77,360 个 `timeout-*`，只有 11 个 `crash-*`；11 个 crash 的 head byte **全落在 slot 0**（无 bug），
  重放阶段「0 unique gated inputs」。25 个 graft bug 一个都没找到。
- **timeout 不是 bug**。曾把 `timeout-*` 当 crash 数，误报「25/25 找到」，已撤回；已推送的 commit
  df355624 / ef828e769 的说明里的「~8 slots」证据也是这个错误。
- gs 单次执行慢（约 1s），而 libafl 的默认超时只有 1.2s，接近单次执行时间；本轮重跑把它对齐到 5s。
  77,360 个 timeout 在各 fuzzer 间的分布还没统计，不能断定是 libafl 独有的问题。

### 0.4 本轮新增的运维要点

- **数 crash 只数 `crash-*`**：FuzzBench 归档里同时有 `crash-*` / `timeout-*` / `oom-*`。
  以 measurer 的 `local.db` crash 表为准。
- **runner 容器名已不是 `runner-container-*`**（现在是 docker 随机名），按镜像数：
  `docker ps --format '{{.Image}}' | grep -oE 'runners/[a-z+]+' | sort | uniq -c`。
- **head byte ≠ 该 bug 触发的**：必须做 dispatch-zero 重放。重放要点：crash oracle 要算 abort / deadly signal；
  AFL 系 crash 用 libFuzzer 构建重放；UBSan crash 传 `--db` 在收集阶段丢掉。
- **重启实验前**先 `sudo rm -rf <fuzzbench>/config`（root 所有的旧 config 会挡住启动）；实验名重复要换名。
- **clnode116 的 fuzzbench 在 `/mydata/BugTransplant/fuzzbench`**，不是 `/mydata/fuzzbench`。

---

# 2026-08 new_seeds 轮（历史）

**集群**：Clemson CloudLab (`ssh linke@<node>.clemson.cloudlab.us`)，工作目录 `/mydata`
**统一配置**：10 trials × 24h (`max_total_time: 86400`) × `snapshot_period: 900` (96 cycles) × 6 fuzzers
（afl, aflplusplus, fairfuzz, honggfuzz, libafl, libfuzzer）
**初始语料**：各 benchmark 对应的「过滤后 dispatch-zero 公共 ClusterFuzz 语料」，见
`fuzzbench/corpora/<project>_<fuzz_target>/seeds_filtered/`，详见 `seed_corpus_report.md`
**NAS 归档根目录**：`/mnt/nas/linke/new_seeds/<project>/`
**benchmark 仓库**：`linkeLi0421/fuzzbench` master（种子以 `corpus_seeds*.zip` 形式入库）

---

## 1. 最终结果（每格 = 单 trial 最高 bug 数）

| Benchmark | afl | aflplusplus | fairfuzz | honggfuzz | libafl | libfuzzer | 最佳 |
|---|--:|--:|--:|--:|--:|--:|---|
| c-blosc2 / decompress_frame | 16 | 15 | 11 | **18** | 16 | 14 | honggfuzz |
| ghostscript / gstoraster | 22 | 2 ✗ | 16 | 11 | 29 | **41** | libfuzzer |
| ghostscript / gs_device_pdfwrite | 2 | 2 | 2 | 1 | **3** | **3** | libafl/libfuzzer |
| htslib / hts_open | 14 | 14 | 11 | **15** | **15** | 13 | honggfuzz/libafl |
| libavc / svc_dec | 6 | 6 | 3 | 8 | **13** | 5 | libafl |
| libredwg / llvmfuzz | 21 | 24 | 17 | 31 | **32** | 16 | libafl |
| ndpi / fuzz_process_packet | 12 | 12 | 10 | 12 | **13** | 12 | libafl |
| ndpi / fuzz_ndpi_reader † | 9 | 9 | 7 | 9 | 9 | **10** | libfuzzer | |
| ntopng / fuzz_dissect_packet | **6** | 5 | 4 | **6** | 5 | **6** | 三者并列 |
| opensc / fuzz_pkcs15_reader | 9 | 9 | 7 | **12** | **12** | 11 | honggfuzz/libafl |
| **总计（10 个 benchmark）** | 117 | 103 | 90 | 128 | **152** | 134 | |
| **最佳次数（含并列）** | 1 | 1 | 0 | 5 | **7** | 4 | |

✗ = aflplusplus 在 gstoraster 上 0.5h 崩溃退出（历史上就如此，与种子无关，见 §4）
† = ndpi_reader 因 ARG_MAX bug 重跑；跑到 28h 时按要求提前停止（超 24h 上限），
测量完整度 85–93%，缺的是**未及归档**的 cycle（非数据损坏，抽查 20 个档案全部可读）

**结论**：libafl 综合最强（总 143，9 个 benchmark 里 7 次最佳）。但它原本在 4 个 benchmark 上因构建/运行故障拿 0 数据，
全靠 §4 的修复才有这些结果 —— 不修的话总分只有 68，结论会完全反过来。

---

## 2. 最终归档状态（NAS）

每个项目**只保留一个合并后的实验目录**（补跑的 fuzzer 已并入主实验，失败数据已删除）。

| 项目 | 实验名 | 大小 | 机器 | 说明 |
|---|---|--:|---|---|
| c-blosc2 | `c-blosc2-24h-6fuzzer` | 11G | clnode061 c8220 (40核) | 含 libafl 补跑 |
| htslib | `htslib-24h-6fuzzer` | 9.6G | clnode389 r6615 (64核) | 含 libafl 补跑 |
| opensc | `opensc-24h-6fuzzer` | 9.8G | clnode031 c8220 (40核) | 含 libafl 补跑 |
| libredwg | `libredwg-24h-6fuzzer` | 109G | clnode205 c6420 (64核) | 含 honggfuzz+libafl 补跑 |
| libavc | `libavc-24h-6fuzzer` | 9.9G | clnode376 r6615 (64核) | 一次成功 |
| ndpi | `ndpi-24h-6fuzzer` | 13G | clnode376 r6615 (64核) | process_packet，一次成功 |
| ntopng | `ntopng-24h-6fuzzer` | 12G | clnode389 r6615 (64核) | 一次成功 |
| ghostscript | `ghostscript-min-24h-v2` | 44G | clnode061 c8220 (40核) | gstoraster，500 种子 + 离线补测量 |
| ghostscript | `gspdf-24h-6fuzzer` | 62G | clnode205 c6420 (64核) | gs_device_pdfwrite，500 种子 |
| ndpi | `ndpi-reader-v2-24h` | 15G | clnode205 c6420 (64核) | fuzz_ndpi_reader，ARG_MAX 修复后重跑 + 离线补测量 |

**已作废并从 NAS 删除**：`ndpi-reader-24h-6fuzzer`（首次跑，种子因 ARG_MAX 未生效，全程 fuzz 一个 2 字节假种子）。

**合并方式**（三层一致）：experiment-folders 目录替换、report `data.csv.gz` 的 `experiment` 字段统一、
`local.db` 删除失败 trial 并把补跑 trial 改归主实验。备份留 `local.db.bak` / `data.csv.gz.bak`。

**注意**：`local.db` 是**按节点**记录该节点跑过的所有实验，同一项目目录下若来自不同节点，
需用 `local_<node>.db` 命名，否则会互相覆盖（曾因此丢过 ndpi 的 db 记录，已修复）。

---

## 3. 进行中 / 待办

**全部 10 个 benchmark 的实验已完成。**

**空闲节点**：clnode061、clnode205、clnode376、clnode389
**失联节点**：clnode031（2026-08-09 起 SSH 超时；其上 opensc ×2 + ndpi_reader 数据早已归档，无损失）

**可选后续**：gstoraster 用「项目自带语料」（ghostpdl `examples/` 14 个示例 × 25 dispatch 变体 = 2,055）
再跑一次，验证「语料质量 vs 数量」对 honggfuzz 的影响（历史该配置下 honggfuzz 拿 49 bugs，
公共语料 500/10,637 时只有 11/21）。

---

## 4. 遇到并修复的故障（4 类根因）

| 根因 | 影响 | 修法 | 结果 |
|---|---|---|---|
| `__asan_default_options` 与 libafl 的 `libfuzzbench.a` 符号冲突 → 链接失败、无目标二进制 | c-blosc2（我们的 `combined.diff`）、opensc（上游 OpenSC 源码） | 标记 `__attribute__((weak))`，`$FUZZER` 门控 | libafl 16 / 12 bugs |
| libredwg 用 `-Werror`，honggfuzz 的 clang-15 报 `-Wsign-compare` → 库编不出来 | libredwg honggfuzz | `-Wno-error` + 从生成的 Makefile 剥离 `-Werror` | honggfuzz 31 bugs |
| 目标调用 `exit()` 而非 `abort()` → libafl respawner panic 整体退出 | htslib（58 处）、libredwg（51 处） | 全库 `.c` 文件 `exit()→abort()`，`$FUZZER` 门控 | libafl 15 / 32 bugs |
| **`ls /tmp/seeds_dispatch/*` 超 ARG_MAX 静默失败 → 种子 zip 从未生成** | **ndpi_reader**（35,372 种子 ≈ 2.06MB > 2MB 上限） | 改用 `find -quit`（不构造参数向量），20 个 benchmark 全改 | **afl 0→9 bugs，覆盖 1,719→8,703** |

### ARG_MAX 修复前后对比（ndpi_reader）

| Fuzzer | 修复前 bug | 修复后 bug | 修复前覆盖 | 修复后覆盖 |
|---|--:|--:|--:|--:|
| afl | **0** | **9** | 1,719（最低 trial 仅 30） | **8,703**（最低 3,955） |
| fairfuzz | 2 | 7 | 2,330 | 6,326 |
| libfuzzer | 3 | 10 | 2,778 | 9,877 |
| aflplusplus | 5 | 9 | 4,779 | 8,592 |
| honggfuzz | 5 | 9 | 4,952 | 10,524 |
| libafl | 5 | 9 | 5,184 | 10,884 |

「afl 在 ndpi_reader 上找不到 bug」完全是种子丢失的假象，不是 afl 弱。

**ARG_MAX 那个最隐蔽**：构建日志无任何报错，FuzzBench 只是发现空语料后造了个 2 字节假种子。
afl 因此用 3 个队列条目跑了 24h（62,031 个 queue cycle），覆盖 1,719 边 / 0 bug，而 libafl 有 5,184 边。
**判断实验是否有效，要看 `fuzzer-log.txt` 里有没有 `fake seed file in empty corpus`。**
已逐一核查：10 个实验中只有 ndpi_reader 中招，其余 9 个种子均正常。

**通用注意**：前三类补丁都用 `if [ "$FUZZER" = "libafl" ]` 门控（builder 镜像有 `ENV FUZZER`），
其他 5 个 fuzzer 的构建与首次实验完全一致，已归档数据仍然可比。

### 无解的问题
- **aflplusplus × gstoraster**：历史上就只跑 0.2h。实测用 afl-fuzz 直接判定，手挑的 20 个「独立执行不崩」
  的种子它照样全判崩溃 → 与种子选择无关，是该 harness 的插桩/sanitizer 不兼容。gstoraster 实际是 5-fuzzer 对比。

---

## 5. ghostscript 种子最小化（2026-08-05）

ghostscript 约 1 秒/次执行，10,637 个种子的 dry-run 校准耗尽全部 24h，afl/fairfuzz 从未进入正式 fuzzing。

| Benchmark | 原始 | `libFuzzer -merge=1` | 分层抽样 | 最终 |
|---|--:|--:|--:|--:|
| gstoraster | 10,637 | 9,146（仅 -14%） | 10 层 × 50 | **500** |
| gs_device_pdfwrite | 9,547 | 跳过（收益太低，耗时 3h） | 10 层 × 50 | **500** |

- **覆盖率去冗余解决不了问题**：merge 只减 14%，几乎每个种子都有独特覆盖 → 必须直接减数量。
- **500 的依据**：实测约 8 秒/种子校准，500 × 8s ≈ 67 分钟（占 24h 的 5%）。
- 抽样按大小分 10 层各取 50，`random.seed(20260805)` 可复现。
- **效果**：afl 2→22、fairfuzz 2→16。但仍不如历史的项目自带语料（afl 39 / fairfuzz 30 / honggfuzz 49），
  差异不在数量而在**质量**：自带 examples 是完整文档（含 384K/342K 的复杂 PDF），
  公共语料 49% 小于 1K（ClusterFuzz minimize 后的最小覆盖输入）。

### gstoraster 离线补测量（2026-08-09）
首次 500 种子实验跑满 24h，但 measurer 跟不上（coverage 快照仅 36–47/96），bug 数被大幅低估。
**用 FuzzBench 自己的 measurer 对归档语料补测，不重跑 fuzzing**：

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v /mydata/experiment-data:/mydata/experiment-data -v /mydata/report-data:/mydata/report-data \
  -v /mydata/fuzzbench:/work/src:ro -e WORK=/work -e LOCAL_EXPERIMENT=True \
  -e EXPERIMENT=<exp> -e "SQL_DATABASE_URL=sqlite:////mydata/experiment-data/local.db?check_same_thread=False" \
  -e EXPERIMENT_FILESTORE=/mydata/experiment-data -e REPORT_FILESTORE=/mydata/report-data \
  -e SNAPSHOT_PERIOD=900 -e DOCKER_REGISTRY=gcr.io/fuzzbench \
  --entrypoint /bin/bash gcr.io/fuzzbench/dispatcher-image -c \
  'cd /work/src && PYTHONPATH=/work/src python3 experiment/measurer/measure_manager.py 86400'
```
补测后需**单独重新生成报告**（`measure_manager.main()` 只做测量）：调 `reporter.output_report(cfg)`，
cfg 需含 `experiment` / `report_filestore` / `fuzzers` / `benchmarks` 四个键。
修正效果：libafl 8→29、afl 6→22、libfuzzer 30→41。

---

## 6. 运维要点

- **启动方式**：每个实验在节点上用独立 tmux 会话 + detached dispatcher 容器，SSH 断开不影响。
- **本地长任务也必须用 tmux**：后台 shell 会被会话 teardown 杀掉（曾因此白等 8 小时）。
  **判断存活要看实际进度增量**（日志 mtime、字节数变化），不能只看 `pgrep <脚本名>` —— 该模式会匹配到检查命令自身，产生假阳性。
- **实验名不可重复**：`local.db` 有记录时会报 `Experiment already exists in database`，需换新实验名。
- **venv 与镜像构建必须串行**：`make base-image` 也会触发 `.venv` 规则，并发会损坏 venv。
- **必须从源码构建 `base-image` / `dispatcher-image`**：拉取的公共 `dispatcher-image` 缺 `Orange3`，dispatcher 启动即崩。
- 配置 yaml 必须含 `docker_registry: gcr.io/fuzzbench`。
- **NAS 传输**：节点无法挂载 NAS，用 rsync 远程→NAS（大文件不走本地中转），做文件数 + 字节数校验。
  CIFS 约 10MB/s，libredwg 那种 100G+ 要数小时。
- **本地磁盘**：崩溃过滤时本地建的 benchmark 镜像会占上百 G（曾把根分区撑到 100% 导致所有命令失败）。
  用完及时 `docker builder prune -af && docker image prune -af`。
- **提前停止实验的正确做法**（ndpi_reader 踩过的坑，按顺序）：
  1. **先杀 `docker run` 客户端进程**，再删容器 —— 只删容器的话客户端会重连重建，表现为「怎么停都停不干净」。
     旧 dispatcher 的客户端进程可用 `pgrep -af "dispatcher-container-<exp>"` 找到。
  2. **别一次 kill 几十个容器** —— 曾导致 docker 守护进程卡死：`docker ps` 正常但**创建任何容器都超时**
     （连 `docker run ... echo HELLO` 都挂），需 `systemctl restart docker` 才能恢复。分批 kill 更稳。
  3. **手动停止后 `measure_loop` 不会退出** —— 因为 trial 的 `time_ended` 仍是 NULL，
     `scheduler.all_trials_ended()` 永远为假。测量其实早已完成，直接停容器再单独生成报告即可。
  4. 日志里的 `Corpus not found for cycle: N` 是**该 cycle 本来就没归档**（提前停止的正常结果），
     不是数据损坏 —— 可用 `tarfile.open(f).getmembers()` 抽查档案验证。
- **实验运行中 measurer 报 `tarfile.ReadError: unexpected end of data`** 是读写竞争
  （measurer 读到正在写入的档案），不是损坏。ndpi_reader 运行时报了 11,298 次，
  实验停止后离线补测只报 2 次，抽查 20 个档案全部可读。
- **GitHub 单文件 100MB 上限**：ndpi_reader 的种子 zip 105M，需拆成 `corpus_seeds.part1/2.zip`；
  build.sh 用 `for _z in /src/corpus_seeds*.zip` 循环解压。
