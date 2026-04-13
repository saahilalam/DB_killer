# DB_killer

A mutation-based SQL fuzzer for MariaDB/InnoDB crash testing. Combines **AST mutations**, **RQG grammar expansion**, and **schema-aware SQL generation** into a single tool that finds assertion failures, signal crashes, and other bugs in MariaDB server.

Built on the same principles as [ClickHouse's AST fuzzer](https://clickhouse.com/blog/fuzzing-click-house) and [pquery](https://github.com/mariadb-corporation/mariadb-qa) — but as a standalone Python tool that generates, replays, detects, deduplicates, and reduces crashes automatically.

## Architecture

```
                    +-------------------+
                    |  Schema Tracker   |  (live INFORMATION_SCHEMA)
                    +--------+----------+
                             |
              +--------------+--------------+
              |              |              |
    +---------v---+  +-------v-----+  +----v---------+
    | Schema-aware |  |  RQG Grammar |  | Grammar+AST  |
    | Generator    |  |  Expansion   |  | Hybrid       |
    | (55% of SQL) |  | (25% of SQL) |  | (15% of SQL) |
    +---------+---+  +-------+-----+  +----+---------+
              |              |              |
              +--------------+--------------+
                             |
                    +--------v----------+
                    |  Fuzzed SQL File  |
                    +--------+----------+
                             |
                    +--------v----------+
                    | pquery / mariadb  |  (replay against MariaDB)
                    |   client replay   |
                    +--------+----------+
                             |
                    +--------v----------+
                    | Crash Detection   |  (error log + core dump)
                    | Deduplication     |  (signature matching)
                    | GDB Backtrace     |  (automatic .bt file)
                    +-------------------+
```

### Four SQL generation pipelines

| Pipeline | % | Source | Purpose |
|----------|---|--------|---------|
| Schema-aware generator | 55% | `generator.py` + `schema.py` | Valid SQL against live schema (~70% hit rate) |
| RQG grammar expansion | 25% | `grammar.py` + 70+ `.yy` grammars | Complex query patterns from MariaDB's test suite |
| Grammar + AST mutation | 15% | `grammar.py` + `fuzzer.py` | Grammar output mutated via sqlglot AST walker |
| Malformed SQL | 5% | `main.py` | Truncated/shuffled/broken queries for parser stress |

## Prerequisites

### Required

- **Python 3.8+** with pip
- **MariaDB debug build** (the build you want to test). Must contain `bin/mariadbd` (or `bin/mysqld`) and `scripts/mariadb-install-db`
- **GDB** (for automatic backtrace extraction from core dumps)

### Required for crash reduction

- **mariadb-qa** (contains pquery binary and reducer.sh):
  ```bash
  git clone https://github.com/mariadb-corporation/mariadb-qa.git
  ```
  This is a [GPL-2.0 licensed](https://github.com/mariadb-corporation/mariadb-qa/blob/master/LICENSE.md) public repository maintained by MariaDB Corporation. It provides:
  - `pquery2-md` — fast multi-threaded SQL replay client (C++)
  - `reducer.sh` — battle-tested crash reduction framework

### Optional (recommended)

- **rr** (record & replay debugger) — enables deterministic crash replay:
  ```bash
  apt install rr    # or see https://rr-project.org
  ```
  When `--rr` is passed, mariadbd runs under `rr record`. On crash, the rr trace is saved and can be replayed with `rr replay` — step forwards and backwards through the exact execution. No more sporadic crashes.

### System requirements

- Linux (tested on Ubuntu 22.04+)
- `core_pattern` set to dump cores to a path GDB can read (the fuzzer sets this automatically)
- Sufficient disk space for core dumps (~500MB per crash for debug builds)
- For `--rr`: `perf_event_paranoid` must be <= 1 (`echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid`)

## Installation

```bash
git clone https://github.com/saahilalam/DB_killer.git
cd DB_killer

# Install Python dependencies
pip install sqlglot mysql-connector-python

# Clone mariadb-qa (for pquery + reducer)
git clone https://github.com/mariadb-corporation/mariadb-qa.git
```

Directory layout after setup:
```
DB_killer/
├── mariadb-qa/           # pquery + reducer (cloned)
│   ├── pquery/pquery2-md
│   └── reducer.sh
├── grammars/             # 70+ RQG .yy grammar files
│   ├── modules/
│   └── zz/              # .zz gendata files
├── seeds/                # 12K+ seed SQL statements
│   ├── innodb_basic.sql          # Core InnoDB operations
│   ├── innodb_stress.sql         # Boundary values and edge cases
│   ├── rqg_innodb_patterns.sql   # RQG-derived patterns
│   ├── pquery_patterns.sql       # Harvested from pquery SQL collections
│   └── mariadb_test_patterns.sql # Harvested from MariaDB mysql-test suite
├── crashes/              # Crash output (created at runtime)
├── main.py               # CLI entry point
├── run.sh                # Convenience wrapper
└── ...
```

### Seed files

The fuzzer ships with **12,000+ seed SQL statements** harvested from multiple sources for maximum diversity:

| File | Lines | Source |
|------|-------|--------|
| `innodb_basic.sql` | 103 | Hand-written InnoDB DDL/DML basics |
| `innodb_stress.sql` | 117 | Boundary values, edge cases, type limits |
| `rqg_innodb_patterns.sql` | 1,013 | Patterns derived from RQG grammar expansion |
| `pquery_patterns.sql` | 4,039 | Harvested from [mariadb-qa](https://github.com/mariadb-corporation/mariadb-qa) pquery SQL collections (main-ms-ps-md.sql, 11.3.sql, bugs_sql.sql, encryption_and_vault.sql) |
| `mariadb_test_patterns.sql` | 6,876 | Harvested from MariaDB's `mysql-test` suite (innodb, encryption, partitions, generated columns, versioning, FTS, JSON) |

The AST fuzzer parses these into ASTs, collects fragments (columns, literals, predicates, table structures), and cross-pollinates them across mutations. More diverse seeds = more diverse mutations = more bugs found.

## Quick Start

```bash
# Simplest — continuous fuzzing with randomized options
./run.sh /path/to/mariadb-debug-build

# Recommended — with rr tracing + fast/slow dirs
python3 main.py \
    --basedir /path/to/mariadb-debug-build \
    --seed-dir seeds/ \
    --grammar grammars/ \
    --rounds 0 \
    --round-delay 5 \
    --trials 10 \
    --randomize-options \
    --rr \
    --fast-dir /dev/shm/db_killer \
    --slow-dir /data/db_killer
```

That's it. The fuzzer will:
1. Initialize a fresh MariaDB datadir (alternating between fast/slow dirs)
2. Start the server with randomized InnoDB options
3. Randomly run under `rr record` (~2/3 of rounds) or without (~1/3 for native-aio coverage)
4. Create 14 test tables with diverse schemas
5. Generate ~30K+ fuzzed queries per round
6. Replay via pquery (multiple trials per round: sequential + shuffled)
7. Detect crashes, extract GDB backtraces, save rr traces, deduplicate by signature
8. Save everything to `./crashes/`
9. Stop the server, wait, start a new round with different options

## Command Line Options

### Core options

| Option | Default | Description |
|--------|---------|-------------|
| `--basedir` | (required) | Path to MariaDB build directory |
| `--seed-dir` | `seeds/` | Seed SQL files (directories scanned recursively) |
| `--grammar` | `grammars/` | RQG grammar files directory |
| `--rounds N` | 1 | Number of rounds (0 = infinite) |
| `--round-delay N` | 60 | Seconds between rounds |
| `--trials N` | 3 | pquery replay trials per round |
| `--randomize-options` | off | Randomize InnoDB startup options each round |
| `--crash-dir` | `./crashes` | Where crash reports are saved |

### rr tracing options

| Option | Description |
|--------|-------------|
| `--rr` | Auto-randomize per round: ~2/3 with rr, ~1/3 without (same as InnoDB_standard.cc). Alternates between `rr record --wait` and `rr record --chaos --wait`. Rounds without rr use `--innodb_use_native_aio=1` for libaio coverage. |
| `--rr='rr record --wait'` | Fixed mode: every round uses `rr record --wait` |
| `--rr='rr record --chaos --wait'` | Fixed mode: every round uses chaos mode (randomized thread scheduling, better for race conditions) |

When rr is active, the following mysqld options are auto-added (per InnoDB_standard.cc + local.cfg):
- `--innodb-use-native-aio=0` (rr can't handle libaio/liburing)
- `--innodb-write-io-threads=2` (reduces fake hangs under tracing)
- `--innodb-read-io-threads=1` (reduces fake hangs under tracing)
- `--loose-gdb --loose-debug-gdb` (rr+gdb compatibility)
- `--innodb_flush_method=fsync` (only when using slow/ext4 dir)

### Fast/slow directory options

Following the RQG `local.cfg` convention, runs can alternate between RAM-based (tmpfs) and disk-based (ext4) directories. This covers different filesystem code paths in InnoDB.

**Quick setup** — creates both dirs (ext4-on-tmpfs, same approach as RQG):
```bash
sudo -E bash setup_dirs.sh          # creates /dev/shm/db_killer + /dev/shm/db_killer_ext4
sudo -E bash setup_dirs.sh teardown  # clean up when done
```

| Option | Default | Description |
|--------|---------|-------------|
| `--fast-dir` | `/dev/shm/db_killer` | RAM-based directory (tmpfs). Higher I/O throughput, better for finding bugs. |
| `--slow-dir` | (none) | Disk-based directory (ext4/HDD/SSD). When set, rounds alternate 50/50 between fast and slow. Covers different filesystem code paths. With `--rr`, auto-adds `--innodb_flush_method=fsync`. |

### Generation options

| Option | Default | Description |
|--------|---------|-------------|
| `--runs N` | 10 | Mutations per seed query |
| `--max-queries N` | unlimited | Stop after N total queries |
| `--gen-time N` | 30 | Seconds to spend generating queries |
| `--seed N` | random | Random seed for reproducibility |

### Advanced options

| Option | Default | Description |
|--------|---------|-------------|
| `--pquery` | auto-detected | Path to pquery binary |
| `--known-bugs` | `known_bugs.strings` | File with known bug signatures to skip |
| `--no-transactions` | off | Don't inject transaction statements |
| `--no-alters` | off | Don't inject ALTER TABLE statements |
| `-v` | off | Verbose debug logging |

## Crash Output

Each crash produces:

```
crashes/
├── crash_0001.sql        # Full SQL reproducer (CREATE + INSERT + fuzzed queries)
├── crash_0001.opt        # mysqld startup options used
├── crash_0001.sig        # Crash signature (pquery-compatible format)
├── crash_0001.bt         # Full GDB backtrace (set print addr off; bt)
├── crash_0001.sh         # One-click repro script
├── crash_0001_reducer.sh # Pre-configured pquery reducer wrapper
├── crash_0001_rr/        # rr trace (when --rr enabled)
├── crash_0001_vardir/    # Server data directory snapshot
│   ├── data/             # InnoDB datadir + core dump
│   └── error.log         # MariaDB error log with crash details
└── crash_0001_repro/     # Reproduction working directory
```

### Replaying an rr trace

When a crash has an rr trace, you can replay the exact execution deterministically:

```bash
# Replay in GDB — step forwards AND backwards through the crash
rr replay crashes/crash_0001_rr

# Inside rr/gdb:
(rr) continue          # run to the crash point
(rr) bt                # see the backtrace
(rr) reverse-continue  # step backwards to find the root cause
(rr) watch -l some_var # hardware watchpoint, works in reverse too
```

This eliminates the "sporadic crash" problem entirely — every rr-traced crash is perfectly reproducible.

### Reproducing a crash

```bash
# Run the repro script (optionally override basedir)
bash crashes/crash_0001.sh /path/to/mariadb-debug-build

# Or reduce with pquery's reducer
./prep_reducer.sh /path/to/mariadb-debug-build crashes/crash_0001
bash crashes/crash_0001_reducer.sh
```

### Crash signatures

Signatures use the same format as pquery's `new_text_string.sh`:
```
assertion_text|SIGNAL|frame1|frame2|frame3|frame4
```

Example:
```
!(col->prtype & 256U)|SIGABRT|__pthread_kill_internal|row_merge_buf_add|row_merge_read_clustered_index|row_merge_build_indexes
```

Known bugs can be listed in `known_bugs.strings` (one signature substring per line) — matching crashes are auto-deleted.

## How the fuzzer works

### InnoDB option randomization

Each round picks random values for 17 InnoDB configuration axes (modeled after MariaDB's `InnoDB_standard.cc` test matrix):

- `innodb_page_size` (4K, 8K, 16K, 32K, 64K)
- `innodb_file_per_table` (on/off)
- `innodb-sync-debug` (on/off)
- `innodb_stats_persistent` (on/off)
- `innodb_adaptive_hash_index` (on/off)
- `innodb_random_read_ahead` (on/off)
- `innodb_undo_log_truncate` (on/off)
- `innodb_rollback_on_timeout` (on/off)
- `sql_mode` (traditional, strict, permissive variants)
- And more (see `server.py`)

### RQG grammar expansion

The fuzzer includes a Python reimplementation of the RQG `.yy` grammar expansion engine. It loads 70+ grammars sourced from [mleich1/rqg](https://github.com/mleich1/rqg) (the actively maintained RQG fork used by MariaDB QA) and expands them with:

- Live schema resolution (`_table`, `_field`, `_field_int`, etc. resolve against actual tables)
- Randomized fallbacks for Perl-only rules (rules that use `$prng` in the original RQG)
- Base + redefine grammar combination (same as `InnoDB_standard.cc`)

### AST mutations

Queries parsed by [sqlglot](https://github.com/tobymao/sqlglot) get AST-level mutations:

- **Literal fuzzing**: boundary integers (0, -1, INT_MAX, INT64_MAX), NaN/Infinity, empty strings, NULL injection, type crossover (int as string, string as date)
- **Clause mutations**: add/remove/replace WHERE, GROUP BY, HAVING, ORDER BY, LIMIT
- **JOIN mutations**: change join types, add/remove joins, synthetic ON conditions
- **Function swapping**: 40+ equivalence groups (COUNT <-> SUM, UPPER <-> LOWER, etc.)
- **Subquery injection**: wrap expressions in scalar subqueries
- **CASE wrapping**: wrap columns/literals in CASE WHEN ... IS NULL
- **Fragment cross-pollination**: columns, literals, and predicates from one query substituted into another

### Schema-aware generation

`generator.py` generates valid SQL against the live `INFORMATION_SCHEMA`:

- SELECT with random JOINs, subqueries, window functions
- INSERT/REPLACE with boundary values
- UPDATE/DELETE with generated WHERE clauses
- ALTER TABLE (ADD/DROP/MODIFY columns, ADD/DROP indexes, ALGORITHM/LOCK hints)
- DDL (CREATE/DROP tables, views, triggers, procedures)

## Configuration

### Mutation probabilities

All probability constants are in `config.py` (`Prob` class). Lower N = more frequent:

```python
REPLACE_WITH_NULL = 20     # 1/20 chance any literal becomes NULL
TOGGLE_DISTINCT = 15       # 1/15 chance to toggle DISTINCT
ADD_WHERE = 8              # 1/8 chance to add a WHERE clause
INJECT_SUBQUERY = 50       # 1/50 chance to wrap in subquery
```

### Known bugs file

`known_bugs.strings` lists crash signatures to skip (one per line). Substring matching, case-insensitive. Once a bug is filed upstream, add its signature here so future runs auto-skip it.

**Workflow after filing a bug (e.g. MDEV-XXXXX):**

1. Get the crash signature from the `.sig` file:
   ```bash
   cat crashes/crash_0008.sig
   ```
   Example output:
   ```
   # Tag: SIGABRT___pthread_kill_internal
   backup_stage <= BACKUP_WAIT_FOR_FLUSH || backup_stage >= BACKUP_END|SIGABRT|__pthread_kill_internal|backup_log_ddl|mysql_create_or_drop_trigger
   ```

2. Append a substring of the signature to `known_bugs.strings` with your bug ID:
   ```bash
   echo "backup_stage <= BACKUP_WAIT_FOR_FLUSH|SIGABRT|backup_log_ddl  ## MDEV-XXXXX" >> known_bugs.strings
   ```

   A short, distinctive substring is enough — matching uses fixed-string substring (like `grep -F`).

3. On the next run, the fuzzer will auto-skip matching crashes:
   ```
   CRASH #N is a KNOWN BUG — deleting
     Signature: backup_stage <= BACKUP_WAIT_FOR_FLUSH...
   ```

**Tip:** After every run, `crashes/seen_signatures.strings` contains a copy-paste-ready list of all unique signatures seen in that run. Use it for bulk updates:
```bash
cat crashes/seen_signatures.strings >> known_bugs.strings
```

Example `known_bugs.strings`:
```
# Format: SIGNATURE  ## MDEV-XXXXX or comment
row0merge.cc:771|row_merge_buf_add                     ## MDEV-12345
backup_log_ddl|mysql_create_or_drop_trigger            ## MDEV-67890
!(col->prtype & 256U)|SIGABRT|row_merge_buf_add        ## MDEV-11111
```

## Tips for effective fuzzing

1. **Use debug builds** (`-DCMAKE_BUILD_TYPE=Debug` or `-Og` optimization) — they have assertions enabled that catch bugs release builds silently corrupt through
2. **Use `--rounds 0 --randomize-options`** — different InnoDB configurations exercise different code paths
3. **Use `--rr`** — rr traces make every crash deterministically replayable. No more "sporadic" crashes. The `--rr` auto mode (2/3 rr, 1/3 without) matches MariaDB's own QA setup
4. **Use `--fast-dir` + `--slow-dir`** — alternating between tmpfs and ext4 covers different InnoDB I/O paths
5. **Increase `--trials`** for non-rr runs — `--trials 10` gives 10x more chances per round
6. **Add your own seed files** — regression test queries, bug reproducers, and application queries all make excellent seeds
7. **Check the `.bt` files** — full GDB backtraces are saved automatically for every crash
8. **Feed crash queries back as seeds** — add reduced crash queries to `seeds/` for the next run
9. **Use `rr replay`** to debug crashes — step backwards from the crash point to find root causes

## License

This project uses:
- [sqlglot](https://github.com/tobymao/sqlglot) (MIT License) for SQL parsing
- [mariadb-qa](https://github.com/mariadb-corporation/mariadb-qa) (GPL-2.0 License) for pquery binary and reducer.sh
- RQG grammar files from [mleich1/rqg](https://github.com/mleich1/rqg) (GPL-2.0 License)

## Acknowledgments

- [ClickHouse AST Fuzzer](https://clickhouse.com/blog/fuzzing-click-house) — the fragment cross-pollination concept
- [pquery / mariadb-qa](https://github.com/mariadb-corporation/mariadb-qa) — the crash replay, reduction, and signature matching approach
- [RQG / Random Query Generator](https://github.com/mleich1/rqg) (mleich1 fork) — the `.yy`/`.zz` grammar files included in `grammars/`
- [sqlglot](https://github.com/tobymao/sqlglot) — SQL parsing and AST manipulation
