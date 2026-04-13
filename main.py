#!/usr/bin/env python3
"""
MariaDB AST Fuzzer — CLI entry point.

Generates mutated SQL queries from seed files for InnoDB crash testing.
Output is compatible with pquery and RQG test runners.

Usage:
    # Generate fuzzed queries to stdout
    python main.py --seed-dir ./seeds/ --runs 100

    # Write to file for pquery
    python main.py --seed-dir ./seeds/ --runs 50 -o fuzzed_queries.sql

    # Live mode: connect to MariaDB and detect crashes
    python main.py --seed-dir ./seeds/ --runs 100 --live \
        --host 127.0.0.1 --port 3306 --user root --database test
"""

import argparse
import glob
import hashlib
import logging
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from fuzzer import Fuzzer

logger = logging.getLogger("ast_fuzzer")


# ===================================================================
# Crash signature extraction and deduplication (pquery-style)
# ===================================================================

# Frames to strip from backtraces — signal handler boilerplate, libc internals,
# unwinder noise.  Matches pquery's new_text_string.sh filter list.
_NOISE_FRAMES = {
    '__interceptor_strcmp', 'std::terminate', 'fprintf', '__pthread_kill',
    '__GI___pthread_kill', '__GI_raise', '__GI_abort', '__assert_fail',
    '__assert_fail_base', 'memmove', 'memcpy', 'memset', '??',
    'signal handler called', '_Unwind_Resume', 'uw_update_context_1',
    'uw_init_context_1', '__restore_rt', '__pthread_kill_implementation',
    'raise', 'abort', 'my_print_stacktrace', 'handle_fatal_signal',
    '_nl_load_domain', 'clone3', 'start_thread',
}

# Generic dispatcher frames — if we have enough specific frames above these,
# we strip them to keep the signature focused on the actual bug location.
_DISPATCHER_FRAMES = {
    'do_command', 'do_handle_one_connection', 'handle_one_connection',
    'mysql_parse', 'dispatch_command', 'mysql_execute_command',
}


def _generate_malformed_sql(schema, grammar_pool):
    """Generate intentionally malformed SQL to exercise parser error paths.

    MariaDB's SQL parser has had bugs triggered by truncated queries,
    unbalanced parens, unexpected tokens, partial clauses, etc.  This
    pipeline (~5% of queries) creates such inputs to cover those paths.
    """
    strategy = random.randint(0, 9)

    if strategy <= 3 and grammar_pool:
        # Truncate a grammar query at a random point
        sql = grammar_pool.generate_query(
            schema if schema and schema.has_tables() else None)
        if sql:
            cut = random.randint(len(sql) // 4, len(sql) - 1)
            return sql[:cut]

    if strategy <= 5 and grammar_pool:
        # Shuffle clauses of a grammar query
        sql = grammar_pool.generate_query(
            schema if schema and schema.has_tables() else None)
        if sql:
            words = sql.split()
            # Swap a random pair of words
            if len(words) > 4:
                i, j = random.sample(range(len(words)), 2)
                words[i], words[j] = words[j], words[i]
            return ' '.join(words)

    if strategy <= 7:
        # Inject unbalanced parens / bad tokens into valid SQL
        tbl = 't1'
        if schema and schema.has_tables():
            t = schema.random_table()
            if t:
                tbl = t.name
        templates = [
            f"SELECT ((( * FROM {tbl}",
            f"SELECT * FROM {tbl} WHERE (((col_int > 1",
            f"SELECT * FROM {tbl} WHERE col_int IN (1,2,",
            f"UPDATE {tbl} SET",
            f"DELETE FROM {tbl} WHERE",
            f"ALTER TABLE {tbl} ADD COLUMN",
            f"SELECT * FROM {tbl} GROUP BY ORDER BY HAVING LIMIT",
            f"SELECT * FROM {tbl} WHERE col_int BETWEEN AND",
            f"INSERT INTO {tbl} VALUES ((((",
            f"SELECT * FROM (SELECT * FROM (SELECT * FROM {tbl}))",
            f"CREATE TABLE IF NOT EXISTS {tbl} LIKE",
            f"SELECT 1 UNION SELECT 1,2 UNION SELECT 1,2,3",
            f"SELECT * FROM {tbl} WHERE col_int = (SELECT",
        ]
        return random.choice(templates)

    # Random bytes as SQL — deep parser stress test
    length = random.randint(10, 200)
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 (),.*=<>!;\'\"'
    return ''.join(random.choices(chars, k=length))


def _sanitize_for_sqlglot(sql):
    """Strip MariaDB-specific syntax that sqlglot can't parse.

    Only used in the grammar→AST mutation pipeline (pipeline 3).
    The raw grammar output sent directly to MariaDB (pipeline 2)
    is NOT sanitized — those modifiers exercise real code paths.
    """
    # DML modifiers — strip all combinations of LOW_PRIORITY/DELAYED/
    # HIGH_PRIORITY/QUICK/IGNORE that appear between the verb and the rest
    sql = re.sub(r'\b(UPDATE|INSERT|DELETE)\s+'
                 r'(?:(?:LOW_PRIORITY|DELAYED|HIGH_PRIORITY|QUICK|IGNORE)\s+)+',
                 r'\1 ', sql)
    # PROCEDURE ANALYSE(...)
    sql = re.sub(r'\bPROCEDURE\s+ANALYSE\s*\([^)]*\)', '', sql)
    # UPDATE (...) → UPDATE ... (strip parens around table list)
    m = re.match(r'(UPDATE\s*)\(\s*', sql, re.IGNORECASE)
    if m:
        start = m.end()
        depth = 1
        i = start
        while i < len(sql) and depth > 0:
            if sql[i] == '(':
                depth += 1
            elif sql[i] == ')':
                depth -= 1
            i += 1
        if depth == 0:
            sql = m.group(1) + sql[start:i - 1] + sql[i:]
    # Empty GROUP BY / ORDER BY
    sql = re.sub(r'\bGROUP BY\s*(?=;|\s*$|\s*ORDER|\s*HAVING|\s*LIMIT|\s*UNION|\s*\))',
                  '', sql)
    sql = re.sub(r'\bORDER BY\s*(?=;|\s*$|\s*LIMIT|\s*UNION|\s*\))',
                  '', sql)
    # ORDER BY ASC/DESC without column
    sql = re.sub(r'\bORDER BY\s+(ASC|DESC)\b', r'ORDER BY 1 \1', sql)
    # Collapse whitespace
    sql = re.sub(r'\s+', ' ', sql).strip()
    return sql


def _extract_crash_signature(mysqld_binary, crash_info, error_log_path):
    """
    Extract a pquery-style crash signature from a core dump using GDB.

    Returns a tuple: (signature_string, short_tag)
      signature_string: e.g. "SIGABRT|Diagnostics_area::set_ok_status|mysql_insert|..."
      short_tag:        e.g. "SIGABRT_Diagnostics_area_set_ok_status"

    If GDB fails or no core, falls back to error-log-based extraction.
    """
    sig_signal = _get_signal_name(crash_info)
    frames = []

    # --- Try GDB on core dump first (cleanest backtrace) ---
    core_path = crash_info.get('core_path', '') if crash_info else ''
    if core_path and not core_path.startswith('coredumpctl') and os.path.exists(core_path):
        frames = _gdb_backtrace(mysqld_binary, core_path)

    # --- Fallback: try coredumpctl ---
    if not frames and crash_info and crash_info.get('core_dump') and 'coredumpctl' in str(core_path):
        pid = crash_info.get('pid')
        if pid:
            frames = _coredumpctl_backtrace(pid)

    # --- Fallback: parse error log backtrace ---
    if not frames and error_log_path and os.path.exists(error_log_path):
        frames = _errorlog_backtrace(error_log_path)

    # --- Check for assertion in error log ---
    assertion = ''
    if error_log_path and os.path.exists(error_log_path):
        assertion = _extract_assertion(error_log_path)

    # --- Build signature ---
    if not frames and not assertion:
        # Last resort: just the signal
        sig = sig_signal or 'UNKNOWN'
        return sig, sig

    parts = []
    if assertion:
        parts.append(assertion)
    parts.append(sig_signal or 'UNKNOWN')
    parts.extend(frames[:4])  # Top 4 meaningful frames (pquery convention)

    signature = '|'.join(parts)
    # Short tag for filenames: signal + top frame, alphanumeric only
    top_frame = frames[0] if frames else (assertion[:40] if assertion else 'unknown')
    short_tag = f"{sig_signal}_{top_frame}".replace('::', '_').replace(' ', '_')
    short_tag = re.sub(r'[^a-zA-Z0-9_]', '', short_tag)[:60]

    return signature, short_tag


def _get_signal_name(crash_info):
    """Extract clean signal name from crash_info."""
    if not crash_info:
        return 'UNKNOWN'
    sig = crash_info.get('signal')
    if sig == 6:
        return 'SIGABRT'
    elif sig == 11:
        return 'SIGSEGV'
    elif sig == 7:
        return 'SIGBUS'
    elif sig == 8:
        return 'SIGFPE'
    elif sig == 4:
        return 'SIGILL'
    elif sig:
        return f'SIG{sig}'
    exit_code = crash_info.get('exit_code', 0)
    if exit_code < 0:
        return f'SIG{-exit_code}'
    return 'UNKNOWN'


def _gdb_backtrace(mysqld_binary, core_path):
    """Run GDB on a core dump and extract clean stack frames."""
    try:
        result = subprocess.run(
            ['gdb', '-batch', '-n',
             '-ex', 'set print demangle on',
             '-ex', 'set print asm-demangle on',
             '-ex', 'set print frame-arguments none',
             '-ex', 'set print max-depth 1',
             '-ex', 'bt',
             mysqld_binary, core_path],
            capture_output=True, text=True, timeout=30,
        )
        return _parse_bt_output(result.stdout + '\n' + result.stderr)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
        logger.debug(f"GDB backtrace failed: {e}")
        return []


def _gdb_full_backtrace(mysqld_binary, core_path):
    """Run GDB on a core dump and return the stack trace.

    Mirrors manual workflow: connect to core, set print addr off, bt.
    """
    try:
        result = subprocess.run(
            ['gdb', '-batch', '-n',
             '-ex', 'set print addr off',
             '-ex', 'bt',
             mysqld_binary, core_path],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout + '\n' + result.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
        logger.debug(f"GDB backtrace failed: {e}")
        return ''


def _coredumpctl_backtrace(pid):
    """Try getting backtrace via coredumpctl."""
    try:
        result = subprocess.run(
            ['coredumpctl', 'debug', str(pid), '--', '-batch',
             '-ex', 'bt'],
            capture_output=True, text=True, timeout=30,
        )
        return _parse_bt_output(result.stdout + '\n' + result.stderr)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
        logger.debug(f"coredumpctl backtrace failed: {e}")
        return []


def _parse_bt_output(text):
    """
    Parse GDB backtrace output into a list of clean function names.
    Skips noise frames, stops at dispatcher frames if we have enough context.
    """
    frames = []
    past_signal_handler = False

    for line in text.split('\n'):
        line = line.strip()
        # GDB frame lines look like: #N  0xADDR in func_name (...) at file:line
        m = re.match(r'#\d+\s+(?:0x[0-9a-f]+\s+in\s+)?(.+)', line)
        if not m:
            continue

        rest = m.group(1).strip()

        # Detect "signal handler called" — skip everything before it
        if 'signal handler called' in rest:
            past_signal_handler = True
            frames.clear()
            continue

        # Extract function name — strip arguments, address, file info
        # "func_name (args...) at file:line" or "func_name () from lib"
        func_m = re.match(r'([a-zA-Z_][\w:~<>]*(?:\s*\([^)]*\))?)', rest)
        if not func_m:
            continue

        raw_func = func_m.group(1).strip()
        # Remove arguments: keep just "Class::method" or "function"
        func_name = re.sub(r'\s*\(.*', '', raw_func).strip()

        if not func_name or func_name in _NOISE_FRAMES:
            continue

        # Check partial matches for noise (e.g. __GI_ prefixed things)
        if any(func_name.startswith(n) for n in ('__GI_', '__interceptor_', '__libc_')):
            continue

        frames.append(func_name)

    # Trim dispatcher frames if we have enough specific frames
    if len(frames) > 4:
        trimmed = []
        for f in frames:
            base_name = f.split('::')[-1] if '::' in f else f
            if base_name in _DISPATCHER_FRAMES:
                break
            trimmed.append(f)
        if len(trimmed) >= 3:
            frames = trimmed

    return frames


def _errorlog_backtrace(error_log_path):
    """
    Parse MariaDB error log backtrace as fallback when GDB is unavailable.
    Error log frames look like:
      sql/sql_insert.cc:1422(mysql_insert(THD*, ...))[0x...]
      /lib/x86_64-linux-gnu/libc.so.6(+0x3b517)[0x...]
    """
    frames = []
    in_bt = False
    try:
        with open(error_log_path, 'r', errors='replace') as f:
            for line in f:
                if 'Attempting backtrace' in line:
                    in_bt = True
                    frames.clear()
                    continue
                if not in_bt:
                    continue
                stripped = line.strip()
                # End of backtrace markers
                if stripped.startswith('Connection ID') or \
                   stripped.startswith('Optimizer switch') or \
                   stripped.startswith('Status:') or \
                   stripped.startswith('Query ('):
                    if frames:
                        break
                    continue
                # Skip info lines
                if stripped.startswith('Thread pointer') or \
                   stripped.startswith('stack_bottom') or \
                   stripped.startswith('(note:') or \
                   not stripped:
                    continue
                # MariaDB error log format: path/file.cc:LINE(func_name(args...))[0xADDR]
                # Extract the function name between first ( and next ( or )
                m = re.match(r'.*\.\w+:\d+\((\w[\w:~]*)', stripped)
                if m:
                    func_name = m.group(1)
                    if func_name not in _NOISE_FRAMES and \
                       not any(func_name.startswith(n) for n in ('__GI_', '__interceptor_')):
                        frames.append(func_name)
    except Exception as e:
        logger.debug(f"Error log backtrace parse failed: {e}")

    # Trim dispatcher frames
    if len(frames) > 4:
        trimmed = []
        for f in frames:
            base_name = f.split('::')[-1] if '::' in f else f
            if base_name in _DISPATCHER_FRAMES:
                break
            trimmed.append(f)
        if len(trimmed) >= 3:
            frames = trimmed

    return frames


def _extract_assertion(error_log_path):
    """Extract assertion condition from error log if present."""
    try:
        with open(error_log_path, 'r', errors='replace') as f:
            for line in f:
                # MariaDB assertion format: "Assertion `condition' failed."
                m = re.search(r"Assertion\s+[`'](.+?)[`']\s+failed", line)
                if m:
                    return m.group(1).strip()
                # InnoDB assertion: "Failing assertion: condition"
                m = re.search(r"Failing assertion:\s*(.+)", line)
                if m:
                    return m.group(1).strip()
    except Exception:
        pass
    return ''


def _load_known_bugs(path):
    """Load known bug signatures from a pquery-compatible known_bugs.strings file."""
    known = []
    if not os.path.exists(path):
        return known
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Strip trailing comment: "signature  ## MDEV-12345"
                sig = line.split('##')[0].strip()
                if sig:
                    known.append(sig)
    except Exception as e:
        logger.warning(f"Failed to load known_bugs: {e}")
    return known


def _is_known_or_seen(signature, known_sigs, seen_sigs):
    """
    Check if a signature matches a known bug or was already seen.
    Uses fixed-string substring matching (same as pquery's grep -F).

    Returns:
        'known'  — matches a known_bugs.strings entry
        'dup'    — matches a previously seen crash this run
        None     — new unique crash
    """
    # Check known bugs (substring match, case-insensitive — same as pquery)
    sig_lower = signature.lower()
    for known in known_sigs:
        if known.lower() in sig_lower or sig_lower in known.lower():
            return 'known'

    # Check seen signatures this run
    if signature in seen_sigs:
        return 'dup'

    return None


def _delete_crash_files(crash_prefix, crash_vardir):
    """Remove all files for a duplicate/known crash."""
    for ext in ('.sql', '.opt', '.cnf', '.sh', '.sig', '.bt'):
        path = crash_prefix + ext
        if os.path.exists(path):
            os.remove(path)
    if os.path.isdir(crash_vardir):
        shutil.rmtree(crash_vardir, ignore_errors=True)
    # Also remove the rr trace directory
    rr_dir = crash_prefix + '_rr'
    if os.path.isdir(rr_dir):
        shutil.rmtree(rr_dir, ignore_errors=True)


def setup_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress sqlglot parser warnings — they flood the output with
    # "contains unsupported syntax" for every MariaDB-specific statement
    logging.getLogger("sqlglot").setLevel(logging.ERROR)


def collect_seed_files(seed_paths):
    """Collect all .sql files from given paths (files or directories)."""
    files = []
    for path in seed_paths:
        if os.path.isfile(path):
            files.append(path)
        elif os.path.isdir(path):
            for pattern in ["*.sql", "*.test"]:
                files.extend(sorted(glob.glob(os.path.join(path, "**", pattern), recursive=True)))
        else:
            logger.warning(f"Seed path not found: {path}")
    return files


def run_generate(args):
    """Generate fuzzed queries and write to file or stdout."""
    fuzzer = Fuzzer(seed=args.seed)

    # Load seeds
    seed_files = collect_seed_files(args.seed_dir)
    if not seed_files:
        logger.error("No seed files found. Provide --seed-dir with .sql files.")
        sys.exit(1)

    for f in seed_files:
        logger.info(f"Loading seed: {f}")
        fuzzer.load_seed_file(f)

    logger.info(f"Loaded {len(fuzzer.seed_queries)} seed queries total")
    logger.info(fuzzer.pool.stats())

    # Open output
    out = sys.stdout
    if args.output:
        out = open(args.output, 'w')
        logger.info(f"Writing to {args.output}")

    count = 0
    try:
        for mutated_sql in fuzzer.fuzz_all(
            runs_per_query=args.runs,
            include_transactions=not args.no_transactions,
            include_alters=not args.no_alters,
        ):
            if mutated_sql and mutated_sql.strip():
                # Clean up for pquery/RQG compatibility
                sql = mutated_sql.strip().rstrip(';') + ';'
                out.write(sql + '\n')
                count += 1

                if args.max_queries and count >= args.max_queries:
                    break

    except KeyboardInterrupt:
        logger.info("Interrupted")
    finally:
        if args.output:
            out.close()

    logger.info(f"Generated {count} fuzzed queries")


def run_live(args):
    """Connect to MariaDB, run fuzzed queries, detect crashes."""
    try:
        import mysql.connector
    except ImportError:
        logger.error("mysql-connector-python required for live mode. pip install mysql-connector-python")
        sys.exit(1)

    fuzzer = Fuzzer(seed=args.seed)

    seed_files = collect_seed_files(args.seed_dir)
    if not seed_files:
        logger.error("No seed files found.")
        sys.exit(1)

    for f in seed_files:
        fuzzer.load_seed_file(f)

    logger.info(f"Loaded {len(fuzzer.seed_queries)} seeds, connecting to MariaDB...")

    crash_queries = []
    error_queries = []
    interesting_errors = set()
    count = 0
    crash_count = 0
    error_count = 0
    start_time = time.time()
    crash_details = []  # list of dicts with info for crash summary report

    # Error codes that indicate potential bugs (not just syntax/permission errors)
    INTERESTING_ERRORS = {
        1030,  # Got error from storage engine
        1034,  # Incorrect key file
        1035,  # Old key file
        1194,  # Table is crashed
        1195,  # Table is crashed and last repair failed
        1196,  # Some non-transactional tables not rolled back
        1205,  # Lock wait timeout (interesting at boundary values)
        1213,  # Deadlock
        1220,  # Not enough memory
        1297,  # Got temporary error from NDB
        2002,  # Can't connect (server crashed)
        2003,  # Can't connect (server crashed)
        2006,  # Server has gone away (CRASH!)
        2013,  # Lost connection during query (CRASH!)
        2055,  # Lost connection (CRASH!)
    }

    CRASH_ERRORS = {2002, 2003, 2006, 2013, 2055}

    def get_connection():
        return mysql.connector.connect(
            host=args.host,
            port=args.port,
            user=args.user,
            password=args.password or "",
            database=args.database,
            connection_timeout=args.timeout,
        )

    conn = get_connection()

    # Create output directories
    os.makedirs(args.crash_dir, exist_ok=True)

    try:
        for mutated_sql in fuzzer.fuzz_all(
            runs_per_query=args.runs,
            include_transactions=not args.no_transactions,
            include_alters=not args.no_alters,
        ):
            if not mutated_sql or not mutated_sql.strip():
                continue

            sql = mutated_sql.strip().rstrip(';')
            count += 1

            if args.max_queries and count > args.max_queries:
                break

            try:
                cursor = conn.cursor()
                cursor.execute(sql)
                try:
                    cursor.fetchall()
                except Exception:
                    pass
                cursor.close()

            except mysql.connector.Error as e:
                errno = e.errno if hasattr(e, 'errno') else 0

                if errno in CRASH_ERRORS:
                    crash_count += 1
                    crash_queries.append(sql)
                    logger.warning(f"CRASH detected (errno {errno}): {sql[:120]}...")

                    # Save crash query immediately
                    crash_file = os.path.join(args.crash_dir, f"crash_{crash_count:04d}.sql")
                    with open(crash_file, 'w') as f:
                        f.write(f"-- Crash errno: {errno}\n")
                        f.write(f"-- Error: {e}\n")
                        f.write(f"-- Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(sql + ';\n')

                    crash_details.append({
                        'num': crash_count, 'status': 'unique',
                        'unique_num': crash_count,
                        'signature': f'errno_{errno}',
                        'tag': f'errno_{errno}',
                        'query': sql[:200],
                        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'prefix': os.path.abspath(crash_file.replace('.sql', '')),
                        'vardir': None,
                        'signal': None,
                        'reproducer': os.path.abspath(crash_file),
                        'error_msg': str(e),
                    })

                    # Try to reconnect
                    try:
                        conn.close()
                    except Exception:
                        pass

                    logger.info("Waiting for server to recover...")
                    for attempt in range(args.reconnect_attempts):
                        time.sleep(args.reconnect_delay)
                        try:
                            conn = get_connection()
                            logger.info("Reconnected successfully")
                            break
                        except Exception:
                            if attempt == args.reconnect_attempts - 1:
                                logger.error("Could not reconnect. Server may be down.")
                                _save_results(args, crash_queries, error_queries, count, crash_count, error_count, start_time)
                                sys.exit(2)

                elif errno in INTERESTING_ERRORS:
                    error_count += 1
                    err_key = (errno, str(e)[:100])
                    if err_key not in interesting_errors:
                        interesting_errors.add(err_key)
                        error_queries.append((errno, str(e), sql))
                        logger.info(f"Interesting error (errno {errno}): {str(e)[:100]}")

                        err_file = os.path.join(args.crash_dir, f"error_{error_count:04d}.sql")
                        with open(err_file, 'w') as f:
                            f.write(f"-- Error errno: {errno}\n")
                            f.write(f"-- Error: {e}\n")
                            f.write(sql + ';\n')

            except Exception as e:
                fail_count += 1
                logger.debug(f"Non-MySQL error: {e}")

            # Progress reporting
            if count % 1000 == 0:
                elapsed = time.time() - start_time
                qps = count / elapsed if elapsed > 0 else 0
                hit_pct = (success_count * 100 // count) if count > 0 else 0
                logger.info(
                    f"Progress: {count} queries ({success_count} OK / {fail_count} err = "
                    f"{hit_pct}% hit rate), "
                    f"{crash_count} crashes, {error_count} interesting, {qps:.0f} q/s"
                )

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    _save_results(args, crash_queries, error_queries, count, crash_count, error_count, start_time)

    # Write crash summary report
    _write_crash_summary(args.crash_dir, crash_details, count, crash_count,
                         crash_count, 0, error_count, start_time,
                         total_rounds=1)


def run_basedir(args):
    """Start a MariaDB server from a build directory, then fuzz it.

    Architecture: AST fuzzer generates SQL → pquery replays (C++, fast).
    With --rounds N (or 0 for infinite), automatically cycles through
    different randomized InnoDB configurations between rounds.  Crash
    deduplication state persists across all rounds so duplicates are
    caught even when they appear under different server options.
    """
    # Verify pquery binary exists
    if not os.path.exists(args.pquery):
        logger.error(f"pquery binary not found at {args.pquery}")
        logger.error("Install from: https://github.com/nicholasgasior/pquery")
        sys.exit(1)

    # Verify rr is installed if --rr is used
    if args.rr:
        if shutil.which("rr") is None:
            logger.error("--rr requested but 'rr' is not installed.")
            logger.error("Install: apt install rr  (or see https://rr-project.org)")
            sys.exit(1)
        logger.info(f"rr tracing enabled — server will run under: {args.rr}")

    from server import MariaDBServer, pick_innodb_combination, pick_rr_mode
    from schema import generate_setup_sql, build_schema_from_setup, SchemaTracker
    from generator import generate_statement
    from grammar import GrammarPool

    # --- One-time setup (shared across all rounds) ---

    fuzzer = Fuzzer(seed=args.seed)

    seed_files = collect_seed_files(args.seed_dir)
    if not seed_files:
        logger.error("No seed files found.")
        sys.exit(1)

    for f in seed_files:
        fuzzer.load_seed_file(f)

    logger.info(f"Loaded {len(fuzzer.seed_queries)} seeds")

    # Prepare setup SQL (CREATE TABLEs, seed data) — same every round
    setup_stmts = generate_setup_sql()

    if args.gendata:
        from gendata import load_zz_and_generate_setup
        zz_stmts, zz_info = load_zz_and_generate_setup(args.gendata)
        setup_stmts.extend(zz_stmts)
        logger.info(f"Gendata: {len(zz_info)} additional tables from .zz files")
        for tname, ncols, nrows in zz_info:
            logger.info(f"  {tname}: {ncols} cols, {nrows} rows")

    # Load RQG grammars (once, shared across rounds)
    grammar_pool = GrammarPool()
    if args.grammar:
        grammar_pool.load_files(args.grammar)
        logger.info(f"Grammar pool: {grammar_pool.stats()}")
        for fname, g in grammar_pool.base_grammars[:8]:
            logger.info(f"  Base: {fname} ({len(g.rules)} rules)")
        if len(grammar_pool.base_grammars) > 8:
            logger.info(f"  ... and {len(grammar_pool.base_grammars) - 8} more base grammars")
        for fname, g in grammar_pool.redefine_grammars[:5]:
            logger.info(f"  Redefine: {fname} ({len(g.rules)} rules)")
        if len(grammar_pool.redefine_grammars) > 5:
            logger.info(f"  ... and {len(grammar_pool.redefine_grammars) - 5} more redefines")

    has_grammars = grammar_pool.has_grammars()

    # --- Cross-round state (persists across all rounds) ---

    crash_queries = []
    error_queries = []
    interesting_errors = set()
    count = 0           # total queries across all rounds
    crash_count = 0
    unique_crash_count = 0
    dup_crash_count = 0
    error_count = 0
    start_time = time.time()
    crash_details = []

    known_sigs = _load_known_bugs(args.known_bugs)
    if known_sigs:
        logger.info(f"Loaded {len(known_sigs)} known bug signatures from {args.known_bugs}")
    seen_sigs = {}  # signature -> crash_prefix (first occurrence kept)

    INTERESTING_ERRORS = {1030, 1034, 1035, 1194, 1195, 1196, 1205, 1213, 1220, 1297}
    CRASH_ERRORS = {2002, 2003, 2006, 2013, 2055}

    os.makedirs(args.crash_dir, exist_ok=True)

    max_rounds = args.rounds if args.rounds > 0 else None  # None = infinite
    round_num = 0
    server = None
    conn = None

    if max_rounds is None:
        logger.info("Continuous mode: running infinite rounds (Ctrl+C to stop)")
    elif max_rounds > 1:
        logger.info(f"Running {max_rounds} rounds, {args.round_delay}s delay between rounds")

    try:
        while max_rounds is None or round_num < max_rounds:
            round_num += 1
            round_start = time.time()
            round_count = 0
            success_count = 0
            fail_count = 0

            # --- Pick new InnoDB options for this round ---
            extra_args = list(args.mysqld_args or [])
            if args.randomize_options:
                combo = pick_innodb_combination()
                extra_args.extend(combo)

            logger.info("")
            logger.info("=" * 60)
            logger.info(f"ROUND {round_num}" +
                        (f"/{max_rounds}" if max_rounds else "") +
                        f" — {time.strftime('%Y-%m-%d %H:%M:%S')}")
            if args.randomize_options:
                logger.info(f"InnoDB options: {' '.join(combo)}")
            logger.info("=" * 60)

            # --- Pick fast or slow dir for this round ---
            # When --slow-dir is set, alternate 50/50 (same as InnoDB_standard.cc)
            if args.slow_dir and round_num % 2 == 0:
                dbdir_type = 'slow'
                round_tmpdir = tempfile.mkdtemp(prefix="db_killer_", dir=args.slow_dir)
            else:
                dbdir_type = 'fast'
                os.makedirs(args.fast_dir, exist_ok=True)
                round_tmpdir = tempfile.mkdtemp(prefix="db_killer_", dir=args.fast_dir)

            # --- Pick rr mode for this round ---
            # --rr (auto): rr always on, randomly pick options each round
            # --rr='rr record --chaos --wait': fixed mode for all rounds
            # No --rr: never use rr
            rr_mode = False
            if args.rr:
                if args.rr == 'auto':
                    # rr always on, but randomize the options
                    rr_mode = random.choice([
                        'rr record --wait',
                        'rr record --chaos --wait',
                        'rr record --chaos',
                    ])
                    logger.info(f"rr mode this round: {rr_mode}")
                else:
                    rr_mode = args.rr  # fixed mode for all rounds

            # --- Start fresh server for this round ---
            server = MariaDBServer(
                basedir=args.basedir,
                datadir=args.datadir if round_num == 1 else None,  # fresh tmpdir after round 1
                port=args.port if args.port != 3306 else None,
                tmpdir=round_tmpdir,
                rr_trace=rr_mode if rr_mode else False,
                dbdir_type=dbdir_type,
            )
            logger.info(f"Data dir: {round_tmpdir} ({dbdir_type})")

            try:
                server.start(extra_args=extra_args)
            except RuntimeError as e:
                logger.error(f"Server failed to start: {e}")
                logger.info("Skipping this round, trying next...")
                server.stop()
                shutil.rmtree(round_tmpdir, ignore_errors=True)
                time.sleep(args.round_delay)
                continue

            import mysql.connector

            def get_connection():
                return mysql.connector.connect(
                    unix_socket=server.socket_path,
                    user="root",
                    database="test",
                    connection_timeout=args.timeout,
                )

            conn = get_connection()

            # --- Phase 1: Setup — create tables and seed data ---
            logger.info("Running setup phase (creating tables, seeding data)...")

            for stmt in setup_stmts:
                try:
                    cursor = conn.cursor()
                    cursor.execute(stmt)
                    try:
                        cursor.fetchall()
                    except Exception:
                        pass
                    cursor.close()
                except mysql.connector.Error as e:
                    logger.debug(f"Setup: {e} — {stmt[:80]}")
            conn.commit()

            # --- Phase 2: Load schema from server ---
            schema = SchemaTracker()
            schema.populate_from_server(conn)
            if not schema.has_tables():
                logger.warning("No tables found after setup, falling back to offline schema")
                schema = build_schema_from_setup()

            logger.info(f"Schema ready: {len(schema.tables)} tables — "
                        f"{', '.join(f'{t.name}({len(t.columns)}c)' for t in schema.tables.values())}")

            # --- Phase 3: Generate queries → write to file → pquery replay ---
            #
            # Architecture (same as pquery-run.sh + RQG):
            #   1. AST fuzzer generates N queries → writes to .sql file
            #   2. pquery replays the file against the server (C++, fast)
            #   3. Check error log for crashes after pquery finishes
            #   4. The .sql file IS the reproducer (exact same queries)

            max_queries = args.max_queries  # None = unlimited (use duration)
            duration = args.duration        # seconds to generate, 0 = use max_queries

            if not max_queries and not duration:
                duration = 30  # default: 30 seconds of generation

            # Generate queries to a temp file
            if duration:
                logger.info(f"Generating fuzzed queries for {duration}s...")
            else:
                logger.info(f"Generating {max_queries} fuzzed queries...")
            gen_start = time.time()
            gen_deadline = gen_start + duration if duration else None
            infile = os.path.join(server.tmpdir, "fuzzed_input.sql")
            generated = 0

            with open(infile, 'w') as qf:
                # Write setup SQL first (CREATE TABLEs, seed data)
                for stmt in setup_stmts:
                    clean = stmt.strip().rstrip(';').replace('\x00', '')
                    if clean:
                        qf.write(f"{clean};\n")
                        generated += 1

                # Generate fuzzed queries until time or count limit
                def _keep_generating():
                    if gen_deadline:
                        return time.time() < gen_deadline
                    return generated < max_queries

                while _keep_generating():
                    sql = None
                    roll = random.randint(1, 100)

                    if has_grammars and roll <= 25:
                        # Pipeline 2: raw grammar → MariaDB
                        sql = grammar_pool.generate_query(schema)
                    elif has_grammars and roll <= 40:
                        # Pipeline 3: grammar → AST mutation → MariaDB
                        raw = grammar_pool.generate_query(schema)
                        if raw:
                            # Grammar may produce multi-statement output
                            # (e.g. "ALTER ...; SELECT ...").  Pick the last
                            # statement for AST mutation — it's usually the
                            # interesting query; earlier stmts are setup (index
                            # creation etc.) and get written out via the split
                            # at line 835 anyway on a subsequent roll<=25 hit.
                            parts = [p.strip() for p in raw.split(';') if p.strip()]
                            stmt = parts[-1] if parts else None
                            if stmt:
                                # Sanitize for sqlglot (strip MariaDB-only
                                # modifiers that sqlglot can't parse).  This
                                # ONLY affects the AST-mutation pipeline, not
                                # the raw grammar output in pipeline 2.
                                stmt = _sanitize_for_sqlglot(stmt)
                                sql = fuzzer.fuzz_one(stmt)
                    elif roll <= 45:
                        # Pipeline 4: malformed SQL — exercises parser
                        # error-handling paths in MariaDB (truncated
                        # queries, broken syntax, partial clauses).
                        sql = _generate_malformed_sql(schema, grammar_pool
                                                      if has_grammars else None)

                    if not sql or not sql.strip():
                        sql = generate_statement(schema)

                    if not sql or not sql.strip():
                        continue

                    # Split multi-statement strings
                    raw_sql = sql.strip().rstrip(';')
                    for part in raw_sql.split(';'):
                        part = part.strip().replace('\x00', '')
                        part = ''.join(c for c in part if c >= ' ' or c in '\t\n\r')
                        if part:
                            qf.write(f"{part};\n")
                            generated += 1
                            if max_queries and generated >= max_queries:
                                break

            gen_elapsed = time.time() - gen_start
            gen_qps = generated / gen_elapsed if gen_elapsed > 0 else 0
            logger.info(f"Generated {generated} queries in {gen_elapsed:.1f}s "
                        f"({gen_qps:.0f} q/s) → {infile}")

            round_count = generated
            count += generated

            # Replay with pquery — multiple trials with different ordering
            # Trial 1: sequential (--no-shuffle) — preserves causal chains
            # Trials 2..N: shuffled — different orderings hit different bugs
            pquery_bin = args.pquery
            num_trials = args.trials
            replay_start = time.time()
            crashed_in_trial = False

            for trial in range(1, num_trials + 1):
                if crashed_in_trial:
                    break

                pquery_log_dir = os.path.join(server.tmpdir, f"pquery_log_t{trial}")
                os.makedirs(pquery_log_dir, exist_ok=True)

                shuffle = trial > 1  # First trial sequential, rest shuffled

                # Pick thread count for this trial
                if args.multi_threaded:
                    # Same thread counts as InnoDB_standard.cc
                    num_threads = random.choice([1, 2, 3, 6, 9, 33])
                else:
                    num_threads = 1

                pquery_cmd = [
                    pquery_bin,
                    f"--infile={infile}",
                    f"--socket={server.socket_path}",
                    "--user=root",
                    "--database=test",
                    f"--threads={num_threads}",
                    f"--queries-per-thread={generated}",
                    f"--logdir={pquery_log_dir}",
                    "--log-all-queries",
                ]
                if not shuffle:
                    pquery_cmd.append("--no-shuffle")

                mode_str = "shuffled" if shuffle else "sequential"
                thread_str = f", {num_threads} threads" if num_threads > 1 else ""
                logger.info(f"  Trial {trial}/{num_trials} ({mode_str}{thread_str})...")

                try:
                    pquery_proc = subprocess.run(
                        pquery_cmd,
                        capture_output=True, text=True,
                        timeout=max(generated // 100, 300),
                    )
                except subprocess.TimeoutExpired:
                    logger.warning(f"  Trial {trial}: pquery timed out")
                except Exception as e:
                    logger.warning(f"  Trial {trial}: pquery error: {e}")

                # Check if server crashed after this trial
                if not server.is_alive():
                    crashed_in_trial = True
                    break

                # Server survived — restart for next trial (fresh state)
                if trial < num_trials:
                    try:
                        # Shut down cleanly, reinit for next trial
                        import mysql.connector as mc
                        tmp_conn = mc.connect(
                            unix_socket=server.socket_path,
                            user="root", database="test",
                            connection_timeout=10,
                        )
                        # Re-run setup for next trial
                        for stmt in setup_stmts:
                            try:
                                c = tmp_conn.cursor(); c.execute(stmt)
                                try: c.fetchall()
                                except: pass
                                c.close()
                            except: pass
                        tmp_conn.commit()
                        tmp_conn.close()
                    except Exception:
                        # Server might have died between check and here
                        if not server.is_alive():
                            crashed_in_trial = True
                            break

            replay_elapsed = time.time() - replay_start
            replay_qps = (generated * min(trial, num_trials)) / replay_elapsed if replay_elapsed > 0 else 0
            logger.info(f"pquery replay done: {trial}/{num_trials} trials in "
                        f"{replay_elapsed:.1f}s ({replay_qps:.0f} q/s total)")

            # Wait for server to fully exit if it crashed
            time.sleep(1)

            # Check if server crashed
            if not server.is_alive():
                try:
                    server.process.wait(timeout=10)
                except Exception:
                    pass
                time.sleep(1)  # Give OS time to write core

                crash_info = server.check_crash()
                crash_count += 1

                if crash_info:
                    sig_info = crash_info.get("signal_name", f"exit code {crash_info.get('exit_code', '?')}")
                    logger.warning(f"SERVER CRASH #{crash_count} ({sig_info})")
                else:
                    logger.warning(f"CRASH detected (server not alive)")

                # Preserve vardir
                crash_vardir = os.path.join(args.crash_dir, f"crash_{crash_count:04d}_vardir")
                _preserve_vardir(server, crash_vardir, crash_info)

                # Save rr trace if enabled
                # With _RR_TRACE_DIR, rr creates the standard structure:
                #   rr_trace/mariadbd-0, mariadbd-1, latest-trace, cpu_lock
                # We pack the latest trace (embeds binaries) then copy the
                # whole directory — same format as RQG.
                if server.rr_trace and server.rr_trace_dir and os.path.isdir(server.rr_trace_dir):
                    # Find latest trace to pack
                    latest = os.path.join(server.rr_trace_dir, 'latest-trace')
                    trace_to_pack = os.path.realpath(latest) if os.path.exists(latest) else None
                    if not trace_to_pack:
                        for entry in sorted(os.listdir(server.rr_trace_dir), reverse=True):
                            candidate = os.path.join(server.rr_trace_dir, entry)
                            if os.path.isdir(candidate) and 'mariadbd' in entry:
                                trace_to_pack = candidate
                                break
                    if trace_to_pack and os.path.isdir(trace_to_pack):
                        rr_dest = os.path.join(args.crash_dir, f"crash_{crash_count:04d}_rr")
                        try:
                            # 'rr pack' embeds binaries for portable replay
                            subprocess.run(
                                ['rr', 'pack', trace_to_pack],
                                capture_output=True, timeout=120)
                            # Copy the whole rr directory (mariadbd-0, latest-trace, cpu_lock)
                            shutil.copytree(server.rr_trace_dir, rr_dest,
                                            symlinks=True)
                            logger.info(f"  rr trace saved: {rr_dest}")
                            logger.info(f"  Replay with: rr replay {rr_dest}")
                        except Exception as e:
                            logger.warning(f"  Failed to save rr trace: {e}")
                    else:
                        logger.warning(f"  rr trace not found in {server.rr_trace_dir}")

                # The infile IS the reproducer — copy it directly
                crash_prefix = os.path.join(args.crash_dir, f"crash_{crash_count:04d}")
                crash_sql = crash_prefix + ".sql"
                shutil.copy2(infile, crash_sql)

                # Write .opt file
                mysqld_opts = []
                for opt in server.startup_options:
                    if opt.startswith("--") and not any(
                        x in opt for x in ["basedir", "datadir", "socket", "pid-file",
                                            "log-error", "tmpdir", "port=", "skip-grant",
                                            "skip-networking"]
                    ):
                        mysqld_opts.append(opt)
                opt_file = crash_prefix + ".opt"
                with open(opt_file, 'w') as f:
                    for opt in mysqld_opts:
                        f.write(f"{opt}\n")

                # Write .cnf file
                _write_crash_repro_script(crash_prefix, server, crash_info)

                # Extract signature
                error_log = os.path.join(crash_vardir, "error.log")
                signature, short_tag = _extract_crash_signature(
                    server.mysqld, crash_info, error_log,
                )

                # Find crash query from pquery log
                crash_query = "(unknown — check pquery log)"
                pquery_log = os.path.join(pquery_log_dir,
                    os.listdir(pquery_log_dir)[0]) if os.listdir(pquery_log_dir) else None
                if pquery_log and os.path.exists(pquery_log):
                    try:
                        with open(pquery_log, 'r', errors='replace') as plf:
                            lines = plf.readlines()
                            # Last non-empty line is likely the crash query
                            for line in reversed(lines):
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    crash_query = line[:200]
                                    break
                    except Exception:
                        pass

                crash_queries.append(crash_query)

                # Dedup
                dedup_status = _is_known_or_seen(signature, known_sigs, seen_sigs)

                if dedup_status == 'known':
                    logger.info(f"CRASH #{crash_count} is a KNOWN BUG — deleting")
                    logger.info(f"  Signature: {signature}")
                    _delete_crash_files(crash_prefix, crash_vardir)
                    dup_crash_count += 1
                    crash_details.append({
                        'num': crash_count, 'status': 'known',
                        'round': round_num,
                        'signature': signature, 'tag': short_tag,
                        'query': crash_query, 'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'prefix': crash_prefix, 'vardir': crash_vardir,
                        'signal': crash_info.get('signal_name') if crash_info else None,
                    })
                elif dedup_status == 'dup':
                    first_prefix = seen_sigs[signature]
                    logger.info(f"CRASH #{crash_count} is a DUPLICATE of {os.path.basename(first_prefix)} — deleting")
                    logger.info(f"  Signature: {signature}")
                    _delete_crash_files(crash_prefix, crash_vardir)
                    dup_crash_count += 1
                    crash_details.append({
                        'num': crash_count, 'status': 'duplicate',
                        'round': round_num,
                        'duplicate_of': os.path.basename(first_prefix),
                        'signature': signature, 'tag': short_tag,
                        'query': crash_query, 'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'prefix': crash_prefix, 'vardir': crash_vardir,
                        'signal': crash_info.get('signal_name') if crash_info else None,
                    })
                else:
                    unique_crash_count += 1
                    seen_sigs[signature] = crash_prefix

                    sig_file = crash_prefix + ".sig"
                    with open(sig_file, 'w') as sf:
                        sf.write(f"# Crash signature (pquery-compatible)\n")
                        sf.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        sf.write(f"# Tag: {short_tag}\n")
                        sf.write(f"# Basedir: {server.basedir}\n")
                        # Extract MariaDB version + source commit from mariadbd
                        try:
                            ver = subprocess.run(
                                [server.mysqld, '--version'],
                                capture_output=True, text=True, timeout=10)
                            ver_line = ver.stdout.strip().split('\n')[0]
                            if ver_line:
                                sf.write(f"# Version: {ver_line}\n")
                        except Exception:
                            pass
                        # Try to get source commit from basedir (if it's a git repo)
                        try:
                            commit = subprocess.run(
                                ['git', '-C', server.basedir, 'rev-parse', 'HEAD'],
                                capture_output=True, text=True, timeout=5)
                            if commit.returncode == 0 and commit.stdout.strip():
                                sf.write(f"# Commit: {commit.stdout.strip()}\n")
                            branch = subprocess.run(
                                ['git', '-C', server.basedir, 'rev-parse',
                                 '--abbrev-ref', 'HEAD'],
                                capture_output=True, text=True, timeout=5)
                            if branch.returncode == 0 and branch.stdout.strip():
                                sf.write(f"# Branch: {branch.stdout.strip()}\n")
                        except Exception:
                            pass
                        sf.write(f"{signature}\n")

                    # Save full GDB backtrace separately
                    core_path = crash_info.get('core_path', '') if crash_info else ''
                    if core_path and os.path.exists(core_path):
                        full_bt = _gdb_full_backtrace(server.mysqld, core_path)
                        if full_bt:
                            bt_file = crash_prefix + ".bt"
                            with open(bt_file, 'w') as bf:
                                bf.write(f"# Full GDB backtrace for crash_{crash_count:04d}\n")
                                bf.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                                bf.write(f"# Binary: {server.mysqld}\n")
                                bf.write(f"# Core:   {core_path}\n")
                                bf.write(f"# Signature: {signature}\n")
                                bf.write(f"#\n")
                                bf.write(full_bt)
                            logger.info(f"  Full backtrace saved: {bt_file}")

                    crash_details.append({
                        'num': crash_count, 'status': 'unique',
                        'round': round_num,
                        'unique_num': unique_crash_count,
                        'signature': signature, 'tag': short_tag,
                        'query': crash_query, 'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'prefix': os.path.abspath(crash_prefix),
                        'vardir': os.path.abspath(crash_vardir),
                        'signal': crash_info.get('signal_name') if crash_info else None,
                        'reproducer': os.path.abspath(crash_sql),
                        'script': os.path.abspath(crash_prefix) + '.sh',
                        'config': os.path.abspath(crash_prefix) + '.cnf',
                        'sig_file': os.path.abspath(crash_prefix) + '.sig',
                        'error_log': os.path.abspath(os.path.join(crash_vardir, 'error.log')),
                        'core_path': crash_info.get('core_path') if crash_info and crash_info.get('core_dump') else None,
                    })

                    logger.info("=" * 60)
                    logger.info(f"NEW UNIQUE CRASH #{unique_crash_count} (total #{crash_count}):")
                    logger.info(f"  Signature:  {signature}")
                    logger.info(f"  Tag:        {short_tag}")
                    logger.info(f"  Query:      {crash_query}")
                    logger.info(f"  Reproducer: {crash_sql}")
                    logger.info(f"  Script:     {crash_prefix}.sh")
                    logger.info(f"  Vardir:     {crash_vardir}")
                    logger.info(f"  Error log:  {crash_vardir}/error.log")
                    if crash_info and crash_info.get('core_dump'):
                        logger.info(f"  Core:       {crash_info.get('core_path')}")
                    logger.info(f"  To reproduce:")
                    logger.info(f"    bash {crash_prefix}.sh")
                    logger.info(f"  Or with pquery directly:")
                    logger.info(f"    {pquery_bin} --infile={crash_sql} --socket=<sock> "
                                f"--user=root --database=test --threads=1 --no-shuffle")
                    logger.info("=" * 60)
            else:
                logger.info(f"No crash this round ({generated} queries replayed)")

            # --- End of round: stop server, clean up, wait ---
            round_elapsed = time.time() - round_start
            round_qps = round_count / round_elapsed if round_elapsed > 0 else 0
            logger.info(f"Round {round_num} complete: {round_count} queries in {round_elapsed:.0f}s "
                        f"({round_qps:.0f} q/s), {crash_count} total crashes so far")

            try:
                conn.close()
            except Exception:
                pass
            conn = None

            server.stop()
            # Clean up tmpdir from this round (crash vardirs are already
            # preserved separately in crash_dir)
            if server.tmpdir and os.path.isdir(server.tmpdir):
                shutil.rmtree(server.tmpdir, ignore_errors=True)
            server = None

            # Wait between rounds (skip after the final round)
            more_rounds = (max_rounds is None or round_num < max_rounds)
            if more_rounds and args.round_delay > 0:
                logger.info(f"Waiting {args.round_delay}s before next round...")
                time.sleep(args.round_delay)

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        if server:
            logger.info("Stopping server...")
            server.stop()

    # --- Final reporting (covers all rounds) ---

    _save_results(args, crash_queries, error_queries, count, crash_count, error_count, start_time)

    if crash_count > 0:
        logger.info(f"Crash dedup summary: {unique_crash_count} unique, {dup_crash_count} duplicates deleted")
        if seen_sigs:
            logger.info(f"Unique crash signatures:")
            for sig, prefix in seen_sigs.items():
                logger.info(f"  {os.path.basename(prefix)}: {sig}")

    if seen_sigs:
        sigs_file = os.path.join(args.crash_dir, "seen_signatures.strings")
        with open(sigs_file, 'w') as f:
            f.write("# Crash signatures found during this run\n")
            f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# {round_num} rounds completed\n")
            f.write("# Copy lines to known_bugs.strings to suppress in future runs\n\n")
            for sig, prefix in seen_sigs.items():
                f.write(f"{sig}  ## {os.path.basename(prefix)}\n")
        logger.info(f"Signatures saved to {sigs_file}")

    _write_crash_summary(args.crash_dir, crash_details, count, crash_count,
                         unique_crash_count, dup_crash_count, error_count, start_time,
                         total_rounds=round_num)


def _write_crash_summary(crash_dir, crash_details, total_queries, total_crashes,
                         unique_crashes, dup_crashes, error_count, start_time,
                         total_rounds=1):
    """
    Write a crash_summary.txt file listing every crash found during the run
    with its status, signature, and file locations.
    """
    summary_path = os.path.join(crash_dir, "crash_summary.txt")
    elapsed = time.time() - start_time

    with open(summary_path, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("  MariaDB AST Fuzzer — Crash Summary Report\n")
        f.write("=" * 70 + "\n")
        f.write(f"  Generated : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Duration  : {elapsed:.1f}s\n")
        f.write(f"  Rounds    : {total_rounds}\n")
        f.write(f"  Queries   : {total_queries}\n")
        f.write(f"  Crashes   : {total_crashes} total "
                f"({unique_crashes} unique, {dup_crashes} duplicates/known)\n")
        f.write(f"  Errors    : {error_count} interesting\n")
        f.write(f"  Crash dir : {os.path.abspath(crash_dir)}\n")
        f.write("=" * 70 + "\n\n")

        if not crash_details:
            f.write("No crashes found during this run.\n")
        else:
            # --- Unique crashes section ---
            unique = [c for c in crash_details if c['status'] == 'unique']
            if unique:
                f.write(f"UNIQUE CRASHES ({len(unique)})\n")
                f.write("-" * 70 + "\n\n")
                for c in unique:
                    f.write(f"  Crash #{c['num']}  (unique #{c['unique_num']})")
                    if c.get('round'):
                        f.write(f"  [Round {c['round']}]")
                    f.write("\n")
                    f.write(f"    Time      : {c['time']}\n")
                    if c.get('signal'):
                        f.write(f"    Signal    : {c['signal']}\n")
                    f.write(f"    Signature : {c['signature']}\n")
                    f.write(f"    Tag       : {c['tag']}\n")
                    f.write(f"    Query     : {c['query']}\n")
                    f.write(f"    Reproducer: {c.get('reproducer', c['prefix'] + '.sql')}\n")
                    if c.get('script'):
                        f.write(f"    Script    : {c['script']}\n")
                    if c.get('config'):
                        f.write(f"    Config    : {c['config']}\n")
                    if c.get('sig_file'):
                        f.write(f"    Sig file  : {c['sig_file']}\n")
                    if c.get('vardir'):
                        f.write(f"    Vardir    : {c['vardir']}\n")
                    if c.get('error_log'):
                        f.write(f"    Error log : {c['error_log']}\n")
                    if c.get('core_path'):
                        f.write(f"    Core dump : {c['core_path']}\n")
                    if c.get('error_msg'):
                        f.write(f"    Error     : {c['error_msg']}\n")
                    f.write("\n")

            # --- Duplicate crashes section ---
            dups = [c for c in crash_details if c['status'] == 'duplicate']
            if dups:
                f.write(f"DUPLICATE CRASHES ({len(dups)}) — files deleted\n")
                f.write("-" * 70 + "\n\n")
                for c in dups:
                    f.write(f"  Crash #{c['num']}  (duplicate of {c.get('duplicate_of', '?')})")
                    if c.get('round'):
                        f.write(f"  [Round {c['round']}]")
                    f.write("\n")
                    f.write(f"    Time      : {c['time']}\n")
                    f.write(f"    Signature : {c['signature']}\n")
                    f.write(f"    Query     : {c['query']}\n\n")

            # --- Known bugs section ---
            known = [c for c in crash_details if c['status'] == 'known']
            if known:
                f.write(f"KNOWN BUG CRASHES ({len(known)}) — files deleted\n")
                f.write("-" * 70 + "\n\n")
                for c in known:
                    f.write(f"  Crash #{c['num']}  (known bug)")
                    if c.get('round'):
                        f.write(f"  [Round {c['round']}]")
                    f.write("\n")
                    f.write(f"    Time      : {c['time']}\n")
                    f.write(f"    Signature : {c['signature']}\n")
                    f.write(f"    Query     : {c['query']}\n\n")

    logger.info(f"Crash summary written to {summary_path}")


def _write_crash_repro_script(crash_prefix, server, crash_info):
    """
    Write an executable .sh script with exact commands to reproduce the crash.

    Just run:  bash crash_0001.sh
    """
    # Use absolute paths so the script works from any directory
    crash_prefix = os.path.abspath(crash_prefix)
    sh_file = crash_prefix + ".sh"
    sql_file = crash_prefix + ".sql"
    vardir = crash_prefix + "_repro"
    datadir = os.path.join(vardir, "data")
    error_log = os.path.join(vardir, "error.log")
    socket_path = os.path.join(vardir, "repro.sock")
    pid_file = os.path.join(vardir, "repro.pid")

    # Build the mysqld command line with all options
    mysqld_bin = server.mysqld
    # Find the mariadb client binary next to mariadbd
    bindir = os.path.dirname(mysqld_bin)
    client_bin = os.path.join(bindir, "mariadb")
    if not os.path.exists(client_bin):
        client_bin = os.path.join(bindir, "mysql")
    install_db = os.path.join(bindir, "mariadb-install-db")
    if not os.path.exists(install_db):
        install_db = os.path.join(bindir, "mysql_install_db")
        if not os.path.exists(install_db):
            # Try scripts/ directory
            install_db = os.path.join(server.basedir, "scripts", "mariadb-install-db")

    # Collect mysqld options (non-path ones that affect behavior)
    mysqld_opts = []
    bootstrap_opts = []  # Options needed during datadir init (e.g. innodb_page_size)
    for opt in server.startup_options:
        if opt.startswith("--") and not any(
            x in opt for x in ["basedir", "datadir", "socket", "pid-file",
                                "log-error", "tmpdir", "port=", "skip-grant",
                                "skip-networking"]
        ):
            mysqld_opts.append(opt)
            # innodb_page_size must match during bootstrap and runtime
            if "innodb_page_size" in opt or "innodb-page-size" in opt:
                bootstrap_opts.append(opt)

    crash_basename = os.path.basename(crash_prefix)

    with open(sh_file, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# MariaDB AST Fuzzer — crash reproducer script\n")
        f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Build: {server.basedir}\n")
        if crash_info and crash_info.get('signal_name'):
            f.write(f"# Signal: {crash_info.get('signal_name')}\n")
        f.write("#\n")
        f.write(f"# Usage: bash {os.path.basename(sh_file)} [basedir]\n")
        f.write("#\n")
        f.write("set -e\n\n")

        # Derive all paths from script location so it's portable
        f.write('SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"\n')
        f.write(f'BASEDIR="${{1:-{server.basedir}}}"\n')
        f.write(f'VARDIR="$SCRIPT_DIR/{crash_basename}_repro"\n')
        f.write(f'DATADIR="$VARDIR/data"\n')
        f.write(f'SOCKET="$VARDIR/repro.sock"\n')
        f.write(f'ERROR_LOG="$VARDIR/error.log"\n')
        f.write(f'PID_FILE="$VARDIR/repro.pid"\n')
        f.write(f'SQL_FILE="$SCRIPT_DIR/{crash_basename}.sql"\n')
        # Auto-detect binaries from BASEDIR
        f.write('MYSQLD="$BASEDIR/bin/mariadbd"\n')
        f.write('[ ! -x "$MYSQLD" ] && MYSQLD="$BASEDIR/bin/mysqld"\n')
        f.write('CLIENT="$BASEDIR/bin/mariadb"\n')
        f.write('[ ! -x "$CLIENT" ] && CLIENT="$BASEDIR/bin/mysql"\n')
        f.write('INSTALL_DB="$BASEDIR/scripts/mariadb-install-db"\n')
        f.write('[ ! -x "$INSTALL_DB" ] && INSTALL_DB="$BASEDIR/scripts/mysql_install_db"\n')
        f.write('[ ! -x "$INSTALL_DB" ] && INSTALL_DB="$BASEDIR/bin/mariadb-install-db"\n\n')

        # Step 1: Prepare vardir
        f.write("# Step 1: Prepare clean datadir\n")
        f.write('echo "=== Preparing datadir ==="\n')
        f.write('rm -rf "$VARDIR"\n')
        f.write('mkdir -p "$VARDIR"\n\n')

        # Bootstrap opts (innodb_page_size etc.) must be passed to install-db
        bootstrap_str = ' '.join(bootstrap_opts)
        f.write('if [ -x "$INSTALL_DB" ]; then\n')
        f.write(f'    "$INSTALL_DB" --basedir="$BASEDIR" --datadir="$DATADIR" \\\n')
        f.write(f'        --user="$USER" {bootstrap_str} 2>&1 | tail -3\n')
        f.write('else\n')
        f.write(f'    "$MYSQLD" --initialize-insecure --basedir="$BASEDIR" \\\n')
        f.write(f'        --datadir="$DATADIR" {bootstrap_str} 2>&1 | tail -3\n')
        f.write('fi\n\n')

        # Step 2: Start server
        f.write("# Step 2: Start server with the same options used during fuzzing\n")
        f.write('echo "=== Starting server ==="\n')
        f.write('"$MYSQLD" \\\n')
        f.write('    --basedir="$BASEDIR" \\\n')
        f.write('    --datadir="$DATADIR" \\\n')
        f.write('    --socket="$SOCKET" \\\n')
        f.write('    --pid-file="$PID_FILE" \\\n')
        f.write('    --log-error="$ERROR_LOG" \\\n')
        f.write('    --skip-grant-tables \\\n')
        f.write('    --skip-networking=0 \\\n')
        f.write('    --tmpdir="$VARDIR" \\\n')
        f.write('    --core-file \\\n')
        for opt in mysqld_opts:
            if opt == '--core-file':
                continue
            f.write(f'    {opt} \\\n')
        f.write('    &\n\n')

        f.write('SERVER_PID=$!\n')
        f.write('echo "Server PID: $SERVER_PID"\n\n')

        # Step 3: Wait for server
        f.write("# Step 3: Wait for server to be ready\n")
        f.write('echo "Waiting for server to start..."\n')
        f.write('for i in $(seq 1 30); do\n')
        f.write('    if "$CLIENT" --socket="$SOCKET" --user=root -e "SELECT 1" &>/dev/null; then\n')
        f.write('        echo "Server is ready."\n')
        f.write('        break\n')
        f.write('    fi\n')
        f.write('    if ! kill -0 "$SERVER_PID" 2>/dev/null; then\n')
        f.write('        echo "ERROR: Server failed to start. Check $ERROR_LOG"\n')
        f.write('        exit 1\n')
        f.write('    fi\n')
        f.write('    sleep 1\n')
        f.write('done\n\n')

        # Step 4: Replay SQL using mariadb client with --force
        # We use the mariadb CLI instead of pquery because pquery has a
        # hardcoded 250-consecutive-failure limit that causes it to stop
        # early on fuzzed SQL files (many invalid queries in a row).
        # --force continues on all errors until the file is fully replayed.
        f.write("# Step 4: Replay SQL\n")
        f.write(f'echo "=== Replaying $SQL_FILE ({os.path.basename(sql_file)}) ==="\n')
        f.write(f'echo "  Total lines: $(wc -l < $SQL_FILE)"\n')
        f.write('"$CLIENT" --socket="$SOCKET" --user=root --force --binary-mode test < "$SQL_FILE" 2>/dev/null || true\n\n')

        # Step 5: Check if server is still alive
        f.write("# Step 5: Check if server crashed\n")
        f.write('sleep 1\n')
        f.write('if kill -0 "$SERVER_PID" 2>/dev/null; then\n')
        f.write('    if "$CLIENT" --socket="$SOCKET" --user=root -e "SELECT 1" &>/dev/null; then\n')
        f.write('        echo ""\n')
        f.write('        echo "Server is still alive — crash did NOT reproduce."\n')
        f.write('        echo "Shutting down server..."\n')
        f.write('        "$CLIENT" --socket="$SOCKET" --user=root -e "SHUTDOWN" 2>/dev/null || \\\n')
        f.write('            kill "$SERVER_PID" 2>/dev/null\n')
        f.write('    fi\n')
        f.write('fi\n')
        f.write('wait "$SERVER_PID" 2>/dev/null\n\n')

        # Step 6: Show error log
        f.write('if [ -f "$ERROR_LOG" ]; then\n')
        f.write('    echo ""\n')
        f.write('    echo "Error log: $ERROR_LOG"\n')
        f.write('    if grep -q "got signal\\|Assertion.*failed\\|Attempting backtrace" "$ERROR_LOG"; then\n')
        f.write('        echo ""\n')
        f.write('        echo "=== CRASH CONFIRMED IN ERROR LOG ==="\n')
        f.write('        grep -A5 "got signal\\|Assertion.*failed" "$ERROR_LOG" | tail -20\n')
        f.write('    fi\n')
        f.write('fi\n')

    os.chmod(sh_file, 0o755)


def _preserve_vardir(server, dest_dir, crash_info):
    """Copy the entire server vardir (datadir, error log, core dump, etc.) to the crash directory."""

    try:
        os.makedirs(dest_dir, exist_ok=True)

        # Copy full datadir (includes core dump if core_pattern points here)
        datadir_dest = os.path.join(dest_dir, "data")
        if os.path.exists(server.datadir):
            shutil.copytree(server.datadir, datadir_dest, dirs_exist_ok=True)

        # Copy error log
        if os.path.exists(server.error_log):
            shutil.copy2(server.error_log, os.path.join(dest_dir, "error.log"))

        # If core dump landed outside the datadir, move it into the vardir
        if crash_info and crash_info.get("core_dump") and crash_info.get("core_path"):
            core_src = crash_info["core_path"]
            if not core_src.startswith("coredumpctl") and os.path.exists(core_src):
                # Check if it's already in our datadir_dest (copied above)
                core_basename = os.path.basename(core_src)
                core_in_vardir = os.path.join(datadir_dest, core_basename)
                if not os.path.exists(core_in_vardir):
                    # Core was outside datadir — copy it in
                    core_dest = os.path.join(dest_dir, core_basename)
                    shutil.copy2(core_src, core_dest)
                    logger.info(f"Core dump copied to {core_dest}")
                else:
                    logger.info(f"Core dump already in vardir: {core_in_vardir}")

        # Copy any other files from tmpdir (pid file, etc.)
        for fname in os.listdir(server.tmpdir):
            src = os.path.join(server.tmpdir, fname)
            if os.path.isfile(src) and fname != "data":
                shutil.copy2(src, os.path.join(dest_dir, fname))

        logger.info(f"Full vardir preserved at {dest_dir}")

    except Exception as e:
        logger.error(f"Failed to preserve vardir: {e}")


def _write_crash_reproducer(crash_prefix, basedir, server, crash_info,
                            errno, error, crash_sql, sql_history, setup_stmts):
    """
    Write a clean, sourceable .sql file that reproduces the crash.

    Usage: mariadb test < crash_0001.sql   → server crashes

    The file contains:
      1. Setup SQL (CREATE TABLEs, INSERT data)
      2. All SQL that ran before the crash
      3. The crash-inducing query (last line)

    No MTR directives, no --error wrappers, no comments in the way.
    Just plain SQL. Source it, server dies.
    """
    sql_file = crash_prefix + ".sql"

    # Collect mysqld options (exclude path-specific ones)
    mysqld_opts = []
    for opt in server.startup_options:
        if opt.startswith("--") and not any(
            x in opt for x in ["basedir", "datadir", "socket", "pid-file",
                                "log-error", "tmpdir", "port=", "skip-grant",
                                "skip-networking"]
        ):
            mysqld_opts.append(opt)

    def _sanitize_sql(s):
        """Remove NUL bytes and non-printable binary that break the mariadb client."""
        # Strip NUL bytes — they terminate C strings and corrupt the client
        s = s.replace('\x00', '')
        # Strip other control chars except tab/newline/carriage-return
        s = ''.join(c for c in s if c >= ' ' or c in '\t\n\r')
        return s.strip().rstrip(';')

    with open(sql_file, 'w') as f:
        # Header — just info comments, the SQL below is what matters
        f.write(f"-- MariaDB AST Fuzzer crash reproducer\n")
        f.write(f"-- {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"-- Build: {basedir}\n")
        if crash_info and crash_info.get('signal'):
            f.write(f"-- Signal: {crash_info.get('signal_name')}\n")
        f.write(f"--\n")
        f.write(f"-- Start server with options from: {crash_prefix}.opt\n")
        f.write(f"-- Then: mariadb test < {sql_file}\n")
        f.write(f"--\n\n")

        # 1. Setup: CREATE TABLEs and seed data
        seen_in_history = set(sql_history)
        for stmt in setup_stmts:
            stmt_clean = _sanitize_sql(stmt)
            if not stmt_clean:
                continue
            # Skip setup stmts that are also in history (avoid duplicates)
            if stmt_clean in seen_in_history:
                continue
            f.write(f"{stmt_clean};\n")

        f.write("\n")

        # 2. All SQL from history (these ran and changed server state)
        for hist_sql in sql_history:
            hist_clean = _sanitize_sql(hist_sql)
            if not hist_clean:
                continue
            f.write(f"{hist_clean};\n")

        # 3. Make sure the crash query is the last line
        #    (it's already in history but be explicit)
        crash_clean = crash_sql.strip().rstrip(';')
        if sql_history and sql_history[-1].strip().rstrip(';') != crash_clean:
            f.write(f"\n-- Crash query:\n")
            f.write(f"{crash_clean};\n")

    # Write .opt file — mysqld startup options, one per line
    opt_file = crash_prefix + ".opt"
    with open(opt_file, 'w') as f:
        for opt in mysqld_opts:
            f.write(f"{opt}\n")

    # Write .cnf file — proper MariaDB config for: mariadbd --defaults-file=crash_XXXX.cnf
    cnf_file = crash_prefix + ".cnf"
    with open(cnf_file, 'w') as f:
        f.write(f"# MariaDB AST Fuzzer crash reproducer config\n")
        f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Usage: mariadbd --defaults-file={cnf_file}\n")
        f.write(f"#        mariadb test < {crash_prefix}.sql\n\n")
        f.write("[mariadb]\n")
        # Include all startup options (including paths) for a self-contained cnf
        for opt in server.startup_options:
            if not opt.startswith("--"):
                continue
            # Strip leading --
            line = opt[2:]
            # Convert loose- prefix to loose_ (MariaDB cnf syntax)
            if line.startswith("loose-"):
                line = "loose_" + line[6:]
            # Convert remaining dashes to underscores in the option name
            if "=" in line:
                name, val = line.split("=", 1)
                name = name.replace("-", "_")
                f.write(f"{name} = {val}\n")
            else:
                line = line.replace("-", "_")
                f.write(f"{line}\n")


def _save_results(args, crash_queries, error_queries, count, crash_count, error_count, start_time):
    """Save summary and consolidated results."""
    elapsed = time.time() - start_time

    # Save all crash queries in one file (pquery-compatible)
    if crash_queries:
        crash_all = os.path.join(args.crash_dir, "all_crashes.sql")
        with open(crash_all, 'w') as f:
            f.write(f"-- MariaDB AST Fuzzer crash report\n")
            f.write(f"-- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"-- Total queries: {count}\n")
            f.write(f"-- Crashes found: {crash_count}\n")
            f.write(f"-- Duration: {elapsed:.1f}s\n\n")
            for sql in crash_queries:
                f.write(sql.rstrip(';') + ';\n')
        logger.info(f"All crash queries saved to {crash_all}")

    # Save all interesting error queries
    if error_queries:
        errors_all = os.path.join(args.crash_dir, "all_errors.sql")
        with open(errors_all, 'w') as f:
            f.write(f"-- MariaDB AST Fuzzer error report\n")
            f.write(f"-- Total interesting errors: {error_count}\n\n")
            for errno, msg, sql in error_queries:
                f.write(f"-- errno {errno}: {msg}\n")
                f.write(sql.rstrip(';') + ';\n\n')
        logger.info(f"All error queries saved to {errors_all}")

    # Summary
    logger.info("=" * 60)
    logger.info(f"Fuzzing complete: {count} queries in {elapsed:.1f}s")
    logger.info(f"  Crashes: {crash_count}")
    logger.info(f"  Interesting errors: {error_count}")
    logger.info(f"  Results in: {args.crash_dir}")
    logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="MariaDB AST Fuzzer — mutation-based SQL fuzzer for InnoDB testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate fuzzed SQL to a file
  %(prog)s --seed-dir seeds/ --runs 50 -o fuzzed.sql

  # Pipe to pquery
  %(prog)s --seed-dir seeds/ --runs 20 | pquery --infile=/dev/stdin --database=test

  # Live crash detection against running server
  %(prog)s --seed-dir seeds/ --runs 100 --live --user root --database test

  # Start a server from build directory and fuzz it
  %(prog)s --seed-dir seeds/ --runs 100 --basedir /path/to/mariadb-build

  # Continuous fuzzing: infinite rounds, new InnoDB options each round
  %(prog)s --seed-dir seeds/ --max-queries 500000 --basedir /path/to/mariadb-build \
      --randomize-options --rounds 0 --round-delay 5

  # Use specific seed for reproducibility
  %(prog)s --seed-dir seeds/ --runs 50 --seed 42 -o fuzzed.sql
        """,
    )

    # Seed input
    parser.add_argument(
        "--seed-dir", nargs="+", required=True,
        help="Paths to seed SQL files or directories containing .sql files",
    )

    # Grammar input (RQG .yy files)
    parser.add_argument(
        "--grammar", nargs="+", default=None,
        help="Paths to RQG grammar (.yy) files or directories. "
             "Grammars are expanded into SQL and mixed with AST mutations.",
    )

    # Gendata input (RQG .zz files)
    parser.add_argument(
        "--gendata", nargs="+", default=None,
        help="Paths to RQG gendata (.zz) files. Creates tables/data matching "
             "the schema that the .yy grammars expect.",
    )

    # Fuzzing control
    parser.add_argument("--runs", type=int, default=10, help="Mutations per seed query (default: 10)")
    parser.add_argument("--max-queries", type=int, default=None, help="Max queries per round (default: unlimited, use --duration)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Seconds to spend generating queries per round (default: 30). "
                             "Overridden by --max-queries if set.")
    parser.add_argument("--trials", type=int, default=3,
                        help="pquery replay trials per round (default: 3). "
                             "Trial 1 is sequential, rest are shuffled for "
                             "different timing/state combinations.")
    parser.add_argument("--multi-threaded", action="store_true",
                        help="Enable multi-threaded pquery replay. Each trial randomly "
                             "picks 1, 2, 3, 6, 9, or 33 threads (same as InnoDB_standard.cc). "
                             "Multi-threaded replay triggers race conditions and "
                             "concurrency bugs that single-threaded replay cannot.")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--no-transactions", action="store_true", help="Don't inject transaction statements")
    parser.add_argument("--no-alters", action="store_true", help="Don't inject ALTER TABLE statements")

    # Output
    parser.add_argument("-o", "--output", type=str, default=None, help="Output file (default: stdout)")

    # Basedir mode (start server from build directory)
    parser.add_argument("--basedir", type=str, default=None,
                        help="Path to MariaDB build/install directory. Starts a server automatically.")
    parser.add_argument("--datadir", type=str, default=None,
                        help="Custom datadir for basedir mode (default: auto tmpdir)")
    parser.add_argument("--mysqld-args", type=str, nargs="*", default=None,
                        help="Extra arguments to pass to mysqld (e.g. --innodb-page-size=4096)")
    parser.add_argument("--randomize-options", action="store_true",
                        help="Randomize InnoDB startup options (page_size, buffer_pool, etc.) "
                             "from the InnoDB_standard.cc combinations matrix")
    parser.add_argument("--rr", type=str, nargs='?', const='auto', default=None,
                        help="Run mariadbd under rr. "
                             "--rr (no value) = rr always on, randomly picks between "
                             "--wait, --chaos --wait, --chaos each round. "
                             "--rr='rr record --chaos --wait' = fixed mode for ALL rounds. "
                             "On crash, rr trace is saved to crashes/ for 'rr replay'.")
    parser.add_argument("--fast-dir", type=str, default="/dev/shm/db_killer",
                        help="Fast (tmpfs/RAM) directory for server datadir. "
                             "RAM-based = higher I/O throughput, better for finding bugs. "
                             "(default: /dev/shm/db_killer)")
    parser.add_argument("--slow-dir", type=str, default=None,
                        help="Slow (ext4/HDD/SSD) directory for server datadir. "
                             "Covers different filesystem code paths than tmpfs. "
                             "When set, rounds alternate 50/50 between fast and slow dirs "
                             "(same as InnoDB_standard.cc). "
                             "With --rr, slow dir auto-adds --innodb_flush_method=fsync.")
    parser.add_argument("--rounds", type=int, default=1,
                        help="Number of rounds to run (0 = infinite). Each round picks new "
                             "randomized InnoDB options and restarts the server. (default: 1)")
    parser.add_argument("--round-delay", type=int, default=60,
                        help="Seconds to wait between rounds (default: 60)")
    # Auto-detect pquery: look next to this script, then in common locations
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _pquery_candidates = [
        os.path.join(_script_dir, 'pquery', 'pquery2-md'),
        os.path.join(_script_dir, '..', 'mariadb-qa', 'pquery', 'pquery2-md'),
        os.path.join(os.path.expanduser('~'), 'mariadb-qa', 'pquery', 'pquery2-md'),
    ]
    _pquery_default = next((p for p in _pquery_candidates if os.path.exists(p)), 'pquery2-md')
    parser.add_argument("--pquery", type=str,
                        default=_pquery_default,
                        help="Path to pquery binary for SQL replay")

    # Live mode
    parser.add_argument("--live", action="store_true", help="Connect to running MariaDB and test queries live")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="MariaDB host")
    parser.add_argument("--port", type=int, default=3306, help="MariaDB port")
    parser.add_argument("--user", type=str, default="root", help="MariaDB user")
    parser.add_argument("--password", type=str, default="", help="MariaDB password")
    parser.add_argument("--database", type=str, default="test", help="MariaDB database")
    parser.add_argument("--timeout", type=int, default=30, help="Query timeout in seconds")
    parser.add_argument("--crash-dir", type=str, default="./crashes", help="Directory for crash reports")
    parser.add_argument("--known-bugs", type=str, default="./known_bugs.strings",
                        help="Path to known_bugs.strings file (pquery-compatible)")
    parser.add_argument("--reconnect-attempts", type=int, default=10, help="Reconnect attempts after crash")
    parser.add_argument("--reconnect-delay", type=float, default=2.0, help="Seconds between reconnect attempts")

    # General
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose debug output")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.basedir:
        run_basedir(args)
    elif args.live:
        run_live(args)
    else:
        run_generate(args)


if __name__ == "__main__":
    main()
