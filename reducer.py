#!/usr/bin/env python3
"""
SQL Testcase Reducer for MariaDB — pquery-style.

Reduces a crash-inducing SQL file to the minimal set of statements that
still reproduces the *same* crash (verified by crash signature matching).

Modeled after mariadb-qa/reducer.sh but reimplemented in Python for
maintainability.  Key pquery concepts implemented:

  - Crash signature verification (same crash, not just any crash)
  - Adaptive chunk sizing with random position (NOISSUEFLOW feedback)
  - Trial retries for sporadic crashes (NR_OF_TRIAL_REPEATS)
  - Pre-initialized datadir template (copy, don't reinit each trial)
  - SQL-aware simplification (WHERE/ORDER BY/LIMIT stripping, literal
    simplification, column elimination, identifier cleanup)
  - mysqld option reduction (binary search)
  - Verify stage with initial simplification

Usage:
    python reducer.py \\
        --basedir /path/to/mariadb-build \\
        --input crashes/crash_0001.sql \\
        --opt crashes/crash_0001.opt

    # For sporadic crashes (try each reduction 5 times):
    python reducer.py \\
        --basedir /path/to/mariadb-build \\
        --input crashes/crash_0001.sql \\
        --opt crashes/crash_0001.opt \\
        --trials 5
"""

import argparse
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time

from server import MariaDBServer

logger = logging.getLogger("reducer")

# Frames to strip from backtraces (same as main.py)
_NOISE_FRAMES = {
    '__interceptor_strcmp', 'std::terminate', 'fprintf', '__pthread_kill',
    '__GI___pthread_kill', '__GI_raise', '__GI_abort', '__assert_fail',
    '__assert_fail_base', 'memmove', 'memcpy', 'memset', '??',
    'signal handler called', '_Unwind_Resume', 'uw_update_context_1',
    'uw_init_context_1', '__restore_rt', '__pthread_kill_implementation',
    'raise', 'abort', 'my_print_stacktrace', 'handle_fatal_signal',
    '_nl_load_domain', 'clone3', 'start_thread',
}


# ===================================================================
# SQL file parsing
# ===================================================================

def parse_sql_file(path):
    """Read a SQL file and return list of statements (skipping comments)."""
    statements = []
    with open(path, 'r', errors='replace') as f:
        content = f.read()

    current = []
    in_single_quote = False
    in_double_quote = False
    in_line_comment = False
    in_block_comment = False
    i = 0

    while i < len(content):
        c = content[i]

        if in_line_comment:
            if c == '\n':
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            if c == '*' and i + 1 < len(content) and content[i + 1] == '/':
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if c == '\\' and (in_single_quote or in_double_quote):
            current.append(c)
            if i + 1 < len(content):
                current.append(content[i + 1])
                i += 2
                continue

        if c == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            current.append(c)
            i += 1
            continue

        if c == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            current.append(c)
            i += 1
            continue

        if not in_single_quote and not in_double_quote:
            if c == '-' and i + 1 < len(content) and content[i + 1] == '-':
                in_line_comment = True
                i += 1
                continue
            if c == '#':
                in_line_comment = True
                i += 1
                continue
            if c == '/' and i + 1 < len(content) and content[i + 1] == '*':
                in_block_comment = True
                i += 2
                continue

            if c == ';':
                stmt = ''.join(current).strip()
                if stmt:
                    statements.append(stmt)
                current = []
                i += 1
                continue

        current.append(c)
        i += 1

    stmt = ''.join(current).strip()
    if stmt:
        statements.append(stmt)

    return statements


def parse_opt_file(path):
    """Read an .opt file and return list of mysqld arguments."""
    if not path or not os.path.exists(path):
        return []
    args = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                args.extend(line.split())
    return args


# ===================================================================
# Crash signature extraction (from error log + GDB)
# ===================================================================

def extract_signature_from_errorlog(error_log_path):
    """
    Extract crash signature from a MariaDB error log.
    Returns (signature_string, assertion_text) or (None, None).

    Mirrors new_text_string.sh logic:
      1. Extract assertion text
      2. Extract backtrace frames from error log
      3. Build signature: assertion|signal|frame1|frame2|frame3|frame4
    """
    if not error_log_path or not os.path.exists(error_log_path):
        return None, None

    assertion = ''
    signal_name = ''
    frames = []

    try:
        with open(error_log_path, 'r', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return None, None

    # --- Extract assertion ---
    for line in lines:
        m = re.search(r"Assertion\s+[`'](.+?)[`']\s+failed", line)
        if m:
            assertion = m.group(1).strip()
            break
        m = re.search(r"Failing assertion:\s*(.+)", line)
        if m:
            assertion = m.group(1).strip()
            break

    # --- Extract signal ---
    for line in lines:
        if 'got signal' in line.lower():
            m = re.search(r'got signal (\d+)', line, re.IGNORECASE)
            if m:
                sig_num = int(m.group(1))
                sig_names = {6: 'SIGABRT', 11: 'SIGSEGV', 7: 'SIGBUS',
                             8: 'SIGFPE', 4: 'SIGILL'}
                signal_name = sig_names.get(sig_num, f'SIG{sig_num}')
                break

    # --- Extract backtrace frames from error log ---
    in_bt = False
    for line in lines:
        if 'Attempting backtrace' in line:
            in_bt = True
            frames.clear()
            continue
        if not in_bt:
            continue
        stripped = line.strip()
        if stripped.startswith(('Connection ID', 'Optimizer switch',
                                'Status:', 'Query (')):
            if frames:
                break
            continue
        if stripped.startswith(('Thread pointer', 'stack_bottom',
                                '(note:', 'The manual page')) or not stripped:
            continue
        # MariaDB error log format: path/file.cc:LINE(func_name(args...))[0xADDR]
        m = re.match(r'.*\.\w+:\d+\((\w[\w:~]*)', stripped)
        if m:
            func_name = m.group(1)
            if func_name not in _NOISE_FRAMES and \
               not any(func_name.startswith(n) for n in ('__GI_', '__interceptor_', '__libc_')):
                frames.append(func_name)

    # Trim dispatcher frames (same as main.py)
    dispatcher = {'do_command', 'do_handle_one_connection',
                  'handle_one_connection', 'mysql_parse',
                  'dispatch_command', 'mysql_execute_command'}
    if len(frames) > 4:
        trimmed = []
        for f in frames:
            base_name = f.split('::')[-1] if '::' in f else f
            if base_name in dispatcher:
                break
            trimmed.append(f)
        if len(trimmed) >= 3:
            frames = trimmed

    # --- Build signature ---
    parts = []
    if assertion:
        parts.append(assertion)
    if signal_name:
        parts.append(signal_name)
    parts.extend(frames[:4])

    if not parts:
        return None, assertion

    signature = '|'.join(parts)
    return signature, assertion


def extract_signature_gdb(mysqld_binary, core_path):
    """Try GDB backtrace on a core dump for more accurate signature."""
    if not core_path or not os.path.exists(core_path):
        return []
    try:
        result = subprocess.run(
            ['gdb', '-batch', '-n',
             '-ex', 'set print demangle on',
             '-ex', 'set print asm-demangle on',
             '-ex', 'set print frame-arguments none',
             '-ex', 'bt'],
            stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=30,
        )
        text = result.stdout + '\n' + result.stderr
        frames = []
        for line in text.split('\n'):
            line = line.strip()
            m = re.match(r'#\d+\s+(?:0x[0-9a-f]+\s+in\s+)?(.+)', line)
            if not m:
                continue
            rest = m.group(1).strip()
            if 'signal handler called' in rest:
                frames.clear()
                continue
            func_m = re.match(r'([a-zA-Z_][\w:~<>]*)', rest)
            if not func_m:
                continue
            func_name = func_m.group(1).strip()
            if func_name and func_name not in _NOISE_FRAMES and \
               not any(func_name.startswith(n) for n in ('__GI_', '__interceptor_', '__libc_')):
                frames.append(func_name)
        return frames[:6]
    except Exception:
        return []


def signatures_match(sig1, sig2):
    """
    Check if two crash signatures match (same bug).
    Uses substring matching in both directions (like pquery's grep -F).
    """
    if not sig1 or not sig2:
        return False
    s1 = sig1.lower()
    s2 = sig2.lower()
    return s1 in s2 or s2 in s1


# ===================================================================
# Datadir template management (copy instead of reinit for speed)
# ===================================================================

class DatadirTemplate:
    """
    Pre-initialized datadir that gets copied for each trial.
    pquery's key optimization: init once, copy many times.
    """

    def __init__(self, basedir, mysqld_args=None):
        self.basedir = basedir
        self.template_dir = tempfile.mkdtemp(prefix="reducer_template_")
        self.data_template = os.path.join(self.template_dir, "data.init")
        self._init(mysqld_args or [])

    def _init(self, mysqld_args):
        """Initialize a clean datadir template."""
        server = MariaDBServer(basedir=self.basedir, tmpdir=self.template_dir)

        # Extract bootstrap args (innodb_page_size etc.)
        bootstrap_args = []
        for arg in mysqld_args:
            if 'innodb_page_size' in arg or 'innodb-page-size' in arg:
                bootstrap_args.append(arg)

        server.initialize(bootstrap_args=bootstrap_args)

        # Rename datadir to data.init (our template)
        if os.path.exists(server.datadir):
            os.rename(server.datadir, self.data_template)

        # Create test database directory
        test_dir = os.path.join(self.data_template, 'test')
        os.makedirs(test_dir, exist_ok=True)

        logger.info(f"Datadir template ready at {self.data_template}")

    def copy_to(self, dest):
        """Copy the template datadir to dest (fast: shutil.copytree)."""
        if os.path.exists(dest):
            shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(self.data_template, dest)

    def cleanup(self):
        shutil.rmtree(self.template_dir, ignore_errors=True)


# ===================================================================
# Trial execution (start server, replay SQL, check crash)
# ===================================================================

def run_trial(basedir, statements, mysqld_args, template, target_signature,
              timeout=60, mode='signature'):
    """
    Start a fresh server, replay statements, check for the target crash.

    mode:
      'signature' — verify crash matches target_signature (MODE=3)
      'any_crash' — any crash counts (MODE=4)

    Returns:
      (crashed, matched, signature) where:
        crashed:  server died
        matched:  crash signature matches the target
        signature: the signature found (or None)
    """
    tmpdir = tempfile.mkdtemp(prefix="reducer_trial_")
    datadir = os.path.join(tmpdir, "data")
    error_log = os.path.join(tmpdir, "error.log")
    socket_path = os.path.join(tmpdir, "reducer.sock")
    pid_file = os.path.join(tmpdir, "reducer.pid")

    try:
        # Copy clean datadir from template
        template.copy_to(datadir)

        # Find mysqld binary
        mysqld = os.path.join(basedir, "bin", "mariadbd")
        if not os.path.exists(mysqld):
            mysqld = os.path.join(basedir, "bin", "mysqld")

        # Build server command
        cmd = [
            mysqld,
            f"--basedir={basedir}",
            f"--datadir={datadir}",
            f"--socket={socket_path}",
            f"--pid-file={pid_file}",
            f"--log-error={error_log}",
            "--skip-grant-tables",
            "--skip-networking",
            f"--tmpdir={tmpdir}",
            "--core-file",
            "--log-output=none",
            "--loose-max-statement-time=30",
        ]
        cmd.extend(mysqld_args or [])

        # Start server
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=datadir,
        )

        # Wait for server to be ready (poll socket)
        import socket as sock_mod
        deadline = time.time() + 30
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            try:
                s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
                s.connect(socket_path)
                s.close()
                time.sleep(0.3)
                ready = True
                break
            except (sock_mod.error, FileNotFoundError):
                time.sleep(0.3)

        if not ready:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            return False, False, None

        # Connect and replay SQL
        try:
            import mysql.connector
            conn = mysql.connector.connect(
                unix_socket=socket_path,
                user="root",
                database="test",
                connection_timeout=timeout,
            )
        except Exception:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            return False, False, None

        crashed = False
        for stmt in statements:
            try:
                cursor = conn.cursor()
                cursor.execute(stmt)
                try:
                    cursor.fetchall()
                except Exception:
                    pass
                cursor.close()
            except Exception:
                if proc.poll() is not None:
                    crashed = True
                    break
                try:
                    conn.ping(reconnect=True)
                except Exception:
                    if proc.poll() is not None:
                        crashed = True
                        break

        # Check if server is still alive after all statements
        if not crashed:
            time.sleep(0.5)
            crashed = (proc.poll() is not None)

        try:
            conn.close()
        except Exception:
            pass

        # Shut down server if still alive
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

        if not crashed:
            return False, False, None

        # --- Crash occurred — extract signature ---
        signature, assertion = extract_signature_from_errorlog(error_log)

        if mode == 'any_crash':
            return True, True, signature

        # Signature matching
        if signature and target_signature:
            matched = signatures_match(signature, target_signature)
        elif assertion and target_signature and assertion in target_signature:
            matched = True
        else:
            # Fallback: if we have no signature but server crashed, accept
            # (better than rejecting a valid reduction)
            matched = (signature is None and target_signature is None)

        return True, matched, signature

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_crash(basedir, statements, mysqld_args, template, target_signature,
               timeout=60, trials=1, mode='signature'):
    """
    Test if statements reproduce the target crash. Retries up to `trials`
    times for sporadic crashes (pquery's NR_OF_TRIAL_REPEATS).

    Returns True if the crash reproduced and signature matched.
    """
    for attempt in range(trials):
        crashed, matched, sig = run_trial(
            basedir, statements, mysqld_args, template,
            target_signature, timeout, mode,
        )
        if crashed and matched:
            return True
    return False


# ===================================================================
# Stage V: Verify + initial simplification
# ===================================================================

def verify_and_simplify(statements, basedir, mysqld_args, template,
                        timeout, trials):
    """
    pquery verify stage: confirm crash reproduces and try initial
    simplification (strip comments, normalize whitespace, etc.).

    Returns (statements, target_signature, mode).
    """
    logger.info("=== Stage V: Verify crash reproduces ===")

    # First, verify with full file and get the crash signature
    target_signature = None
    for attempt in range(max(trials, 3)):
        crashed, matched, sig = run_trial(
            basedir, statements, mysqld_args, template,
            None, timeout, mode='any_crash',
        )
        if crashed:
            target_signature = sig
            break

    if target_signature is None:
        # Try once more with extra trials
        for attempt in range(5):
            crashed, matched, sig = run_trial(
                basedir, statements, mysqld_args, template,
                None, timeout, mode='any_crash',
            )
            if crashed:
                target_signature = sig
                break

    if target_signature is None:
        logger.error("Cannot reproduce crash! Try increasing --trials.")
        return statements, None, 'any_crash'

    logger.info(f"Crash confirmed. Signature: {target_signature}")

    # Determine mode: if we have a signature, use it; otherwise any_crash
    if target_signature and '|' in target_signature:
        mode = 'signature'
        logger.info("Using signature matching (same crash verification)")
    else:
        mode = 'any_crash'
        logger.info("No detailed signature — using any-crash mode")

    # --- Try initial simplification (pquery verify attempts 1-5) ---

    # Attempt 1: Strip pure comment lines and empty lines
    simplified = [s for s in statements if s.strip()]
    if len(simplified) < len(statements):
        if test_crash(basedir, simplified, mysqld_args, template,
                      target_signature, timeout, trials, mode):
            logger.info(f"  Simplified: removed empty statements "
                        f"({len(statements)} -> {len(simplified)})")
            statements = simplified

    # Attempt 2: Normalize whitespace in each statement
    simplified = [re.sub(r'\s+', ' ', s).strip() for s in statements]
    simplified = [s for s in simplified if s]
    if test_crash(basedir, simplified, mysqld_args, template,
                  target_signature, timeout, trials, mode):
        statements = simplified

    # Attempt 3: Remove SET statements that aren't critical
    non_critical_sets = re.compile(
        r'^SET\s+(GLOBAL\s+)?(innodb_fatal_semaphore|'
        r'idle_.*timeout|connect_timeout|log_output|'
        r'max_statement_time|debug_assert_on_not_freed|'
        r'log_bin_trust_function|innodb_fast_shutdown|'
        r'innodb_evict_tables)', re.IGNORECASE)
    simplified = [s for s in statements if not non_critical_sets.match(s)]
    if len(simplified) < len(statements):
        if test_crash(basedir, simplified, mysqld_args, template,
                      target_signature, timeout, trials, mode):
            logger.info(f"  Simplified: removed non-critical SETs "
                        f"({len(statements)} -> {len(simplified)})")
            statements = simplified

    logger.info(f"Verify complete: {len(statements)} statements, "
                f"signature: {target_signature}\n")
    return statements, target_signature, mode


# ===================================================================
# Stage 1: Adaptive chunk removal (pquery-style)
# ===================================================================

def determine_chunk_size(total_lines, noissueflow):
    """
    Adaptive chunk sizing based on consecutive failures (NOISSUEFLOW).
    Mirrors pquery's determine_chunk() logic.

    Start very aggressively (remove 80% of the file) and back off
    as consecutive failures accumulate.
    """
    if total_lines >= 1000:
        pcts = [0.80, 0.65, 0.50, 0.33, 0.25, 0.20, 0.15, 0.10,
                0.07, 0.05, 0.04, 0.03, 0.02, 0.015, 0.01,
                0.008, 0.005, 0.003, 0.002]
    else:
        pcts = [0.25, 0.20, 0.15, 0.12, 0.10, 0.08, 0.06, 0.05,
                0.04, 0.03, 0.02, 0.015, 0.01, 0.005, 0.002]

    idx = min(noissueflow, len(pcts) - 1)
    chunk = max(int(total_lines * pcts[idx]), 1)
    return chunk


def stage1_chunk_removal(statements, basedir, mysqld_args, template,
                         target_signature, timeout, trials, mode,
                         stage1_lines=90):
    """
    Stage 1: Adaptive chunk removal with random position.

    Removes random chunks of adaptive size. Chunk size shrinks as
    consecutive failures accumulate, grows back on success.
    Continues until file is below stage1_lines.
    """
    logger.info(f"=== Stage 1: Chunk removal ({len(statements)} statements) ===")

    noissueflow = 0
    max_noissueflow = 25  # Give up on Stage 1 after this many consecutive failures
    total_attempts = 0
    max_attempts = len(statements) * 5  # Safety limit

    while len(statements) > stage1_lines and total_attempts < max_attempts:
        chunk_size = determine_chunk_size(len(statements), noissueflow)

        if chunk_size < 1 or noissueflow >= max_noissueflow:
            break

        # Random start position (never remove the last statement — crash query)
        max_start = len(statements) - 1 - chunk_size
        if max_start < 0:
            max_start = 0
            chunk_size = max(len(statements) - 2, 1)

        start = random.randint(0, max(max_start, 0))
        end = min(start + chunk_size, len(statements) - 1)  # Protect last stmt

        candidate = statements[:start] + statements[end:]
        if not candidate:
            noissueflow += 1
            total_attempts += 1
            continue

        total_attempts += 1

        if test_crash(basedir, candidate, mysqld_args, template,
                      target_signature, timeout, trials, mode):
            removed = len(statements) - len(candidate)
            statements = candidate
            # Partial rollback of noissueflow (pquery's control_backtrack_flow)
            noissueflow = max(noissueflow - 3, 0)
            logger.info(f"  [{total_attempts}] Removed {removed} stmts at "
                        f"line {start+1} ({len(statements)} left, "
                        f"chunk={chunk_size})")
        else:
            noissueflow += 1

    logger.info(f"Stage 1 done: {len(statements)} statements\n")
    return statements


# ===================================================================
# Stage 2: Single statement removal
# ===================================================================

def stage2_single_removal(statements, basedir, mysqld_args, template,
                          target_signature, timeout, trials, mode):
    """Stage 2: Try removing each statement one at a time."""
    logger.info(f"=== Stage 2: Single statement removal "
                f"({len(statements)} statements) ===")

    i = 0
    while i < len(statements) - 1:  # Never remove the last statement
        candidate = statements[:i] + statements[i + 1:]

        if test_crash(basedir, candidate, mysqld_args, template,
                      target_signature, timeout, trials, mode):
            logger.info(f"  Removed stmt {i+1}/{len(statements)}: "
                        f"{statements[i][:60]}...")
            statements = candidate
            # Don't advance — try removing the next one at same position
        else:
            i += 1

    logger.info(f"Stage 2 done: {len(statements)} statements\n")
    return statements


# ===================================================================
# Stage 3: SQL-aware simplification (pquery Stages 3-4)
# ===================================================================

def _try_transform(statements, transform_fn, basedir, mysqld_args, template,
                   target_signature, timeout, trials, mode, desc=""):
    """Apply a transform to all statements, keep if still crashes."""
    new_stmts = [transform_fn(s) for s in statements]
    new_stmts = [s for s in new_stmts if s and s.strip()]
    if new_stmts == statements or len(new_stmts) == 0:
        return statements, False
    if test_crash(basedir, new_stmts, mysqld_args, template,
                  target_signature, timeout, trials, mode):
        if desc:
            logger.info(f"  {desc}: {len(statements)} -> {len(new_stmts)}")
        return new_stmts, True
    return statements, False


def stage3_sql_simplification(statements, basedir, mysqld_args, template,
                              target_signature, timeout, trials, mode):
    """
    Stage 3: SQL-aware simplification transforms.
    Mirrors pquery Stages 3-4: strip clauses, simplify literals, etc.
    """
    logger.info(f"=== Stage 3: SQL simplification "
                f"({len(statements)} statements) ===")

    transforms = [
        # Strip trailing clauses
        (lambda s: re.sub(r'\s+ORDER\s+BY\s+.*$', '', s, flags=re.IGNORECASE),
         "Strip ORDER BY"),
        (lambda s: re.sub(r'\s+LIMIT\s+\d+.*$', '', s, flags=re.IGNORECASE),
         "Strip LIMIT"),
        (lambda s: re.sub(r'\s+HAVING\s+.*$', '', s, flags=re.IGNORECASE)
         if 'GROUP BY' not in s.upper() else s,
         "Strip HAVING"),
        (lambda s: re.sub(r'\s+GROUP\s+BY\s+[^;]*$', '', s, flags=re.IGNORECASE),
         "Strip GROUP BY"),
        # Strip locking clauses
        (lambda s: re.sub(r'\s+(FOR\s+UPDATE|LOCK\s+IN\s+SHARE\s+MODE)\s*$', '',
                          s, flags=re.IGNORECASE),
         "Strip FOR UPDATE/LOCK"),
        # Simplify WHERE to tautology
        (lambda s: re.sub(r'\s+WHERE\s+.+$', ' WHERE 1=1', s, flags=re.IGNORECASE)
         if s.strip().upper().startswith(('SELECT', 'UPDATE', 'DELETE')) else s,
         "Simplify WHERE to 1=1"),
        # Strip WHERE entirely
        (lambda s: re.sub(r'\s+WHERE\s+.*$', '', s, flags=re.IGNORECASE)
         if s.strip().upper().startswith(('SELECT', 'UPDATE', 'DELETE')) else s,
         "Strip WHERE"),
        # Strip DISTINCT
        (lambda s: re.sub(r'\bDISTINCT\b', '', s, flags=re.IGNORECASE),
         "Strip DISTINCT"),
        # Strip IF NOT EXISTS / IF EXISTS
        (lambda s: re.sub(r'\s+IF\s+(NOT\s+)?EXISTS', '', s, flags=re.IGNORECASE),
         "Strip IF [NOT] EXISTS"),
        # Simplify string literals to 'a'
        (lambda s: re.sub(r"'[^']{2,}'", "'a'", s),
         "Simplify strings to 'a'"),
        # Simplify string literals to ''
        (lambda s: re.sub(r"'[^']*'", "''", s),
         "Simplify strings to ''"),
        # Simplify large numbers to small ones
        (lambda s: re.sub(r'\b\d{6,}\b', '1', s),
         "Simplify large numbers"),
        # Remove backticks
        (lambda s: s.replace('`', ''),
         "Remove backticks"),
        # Simplify ALGORITHM/LOCK clauses
        (lambda s: re.sub(r',\s*ALGORITHM\s*=\s*\w+', '', s, flags=re.IGNORECASE),
         "Strip ALGORITHM"),
        (lambda s: re.sub(r',\s*LOCK\s*=\s*\w+', '', s, flags=re.IGNORECASE),
         "Strip LOCK"),
        # Strip CHARACTER SET / COLLATE
        (lambda s: re.sub(r'\s+CHARACTER\s+SET\s+\w+', '', s, flags=re.IGNORECASE),
         "Strip CHARACTER SET"),
        (lambda s: re.sub(r'\s+COLLATE\s+\w+', '', s, flags=re.IGNORECASE),
         "Strip COLLATE"),
        # Strip DEFAULT values
        (lambda s: re.sub(r'\s+DEFAULT\s+[^\s,)]+', '', s, flags=re.IGNORECASE)
         if s.strip().upper().startswith(('CREATE', 'ALTER')) else s,
         "Strip DEFAULT"),
        # Strip NOT NULL
        (lambda s: re.sub(r'\s+NOT\s+NULL', '', s, flags=re.IGNORECASE)
         if s.strip().upper().startswith(('CREATE', 'ALTER')) else s,
         "Strip NOT NULL"),
        # Strip AUTO_INCREMENT
        (lambda s: re.sub(r'\s+AUTO_INCREMENT', '', s, flags=re.IGNORECASE),
         "Strip AUTO_INCREMENT"),
        # Strip ROW_FORMAT
        (lambda s: re.sub(r'\s+ROW_FORMAT\s*=\s*\w+', '', s, flags=re.IGNORECASE),
         "Strip ROW_FORMAT"),
        # Strip PAGE_COMPRESSED
        (lambda s: re.sub(r'\s+PAGE_COMPRESSED\s*=\s*\d+', '', s, flags=re.IGNORECASE),
         "Strip PAGE_COMPRESSED"),
        # Strip ENGINE (try — may be needed)
        (lambda s: re.sub(r'\s+ENGINE\s*=\s*\w+', '', s, flags=re.IGNORECASE),
         "Strip ENGINE"),
        # Normalize ENGINE to InnoDB
        (lambda s: re.sub(r'ENGINE\s*=\s*\w+', 'ENGINE=InnoDB', s, flags=re.IGNORECASE),
         "Normalize ENGINE to InnoDB"),
        # Strip index hints
        (lambda s: re.sub(r'\s+(USE|FORCE|IGNORE)\s+(INDEX|KEY)\s*\([^)]*\)', '',
                          s, flags=re.IGNORECASE),
         "Strip index hints"),
        # Strip WITH SYSTEM VERSIONING
        (lambda s: re.sub(r'\s+WITH\s+SYSTEM\s+VERSIONING', '', s, flags=re.IGNORECASE),
         "Strip WITH SYSTEM VERSIONING"),
        # Strip PARTITION BY ...
        (lambda s: re.sub(r'\s+PARTITION\s+BY\s+.*$', '', s, flags=re.IGNORECASE)
         if s.strip().upper().startswith('CREATE') else s,
         "Strip PARTITION BY"),
    ]

    for transform_fn, desc in transforms:
        statements, changed = _try_transform(
            statements, transform_fn, basedir, mysqld_args, template,
            target_signature, timeout, trials, mode, desc,
        )

    logger.info(f"Stage 3 done: {len(statements)} statements\n")
    return statements


# ===================================================================
# Stage 4: mysqld option reduction (pquery Stage 8 — binary search)
# ===================================================================

def stage4_option_reduction(statements, basedir, mysqld_args, template,
                            target_signature, timeout, trials, mode):
    """
    Stage 4: Reduce mysqld startup options using binary search.
    Mirrors pquery Stage 8.
    """
    if not mysqld_args:
        return mysqld_args

    logger.info(f"=== Stage 4: mysqld option reduction "
                f"({len(mysqld_args)} options) ===")

    # Filter out options that are always needed
    always_keep = set()
    for i, arg in enumerate(mysqld_args):
        if any(x in arg for x in ['basedir', 'datadir', 'socket', 'pid-file',
                                    'log-error', 'tmpdir', 'skip-grant',
                                    'no-defaults', 'core-file']):
            always_keep.add(i)

    reducible = [(i, arg) for i, arg in enumerate(mysqld_args)
                 if i not in always_keep]

    if not reducible:
        logger.info("No reducible options. Skipping.")
        return mysqld_args

    # Try removing each option one by one
    removed = set()
    for idx, opt in reducible:
        candidate = [a for i, a in enumerate(mysqld_args)
                     if i != idx and i not in removed]
        if test_crash(basedir, statements, candidate, template,
                      target_signature, timeout, trials, mode):
            removed.add(idx)
            logger.info(f"  Removed option: {opt}")

    new_args = [a for i, a in enumerate(mysqld_args) if i not in removed]
    logger.info(f"Stage 4 done: {len(mysqld_args)} -> {len(new_args)} options\n")
    return new_args


# ===================================================================
# Main reduction orchestrator
# ===================================================================

def reduce(statements, basedir, mysqld_args, template, timeout=60,
           trials=1, max_rounds=10):
    """
    Main reduction pipeline.
    Stages: V (verify) -> 1 (chunks) -> 2 (single) -> 3 (SQL simplify)
            -> 2 again -> 4 (options)
    """
    original_count = len(statements)

    # Stage V: Verify and initial simplification
    statements, target_signature, mode = verify_and_simplify(
        statements, basedir, mysqld_args, template, timeout, trials,
    )

    if target_signature is None and mode != 'any_crash':
        logger.error("Cannot reproduce crash.")
        return statements, mysqld_args

    for round_num in range(1, max_rounds + 1):
        start_count = len(statements)

        # Stage 1: Adaptive chunk removal
        if len(statements) > 30:
            statements = stage1_chunk_removal(
                statements, basedir, mysqld_args, template,
                target_signature, timeout, trials, mode,
                stage1_lines=max(30, len(statements) // 10),
            )

        # Stage 2: Single statement removal
        statements = stage2_single_removal(
            statements, basedir, mysqld_args, template,
            target_signature, timeout, trials, mode,
        )

        # Stage 3: SQL-aware simplification (first round only)
        if round_num == 1:
            statements = stage3_sql_simplification(
                statements, basedir, mysqld_args, template,
                target_signature, timeout, trials, mode,
            )

            # Stage 2 again after simplification (may unlock more removals)
            statements = stage2_single_removal(
                statements, basedir, mysqld_args, template,
                target_signature, timeout, trials, mode,
            )

        logger.info(f"Round {round_num}: {start_count} -> {len(statements)} "
                     f"statements")

        if len(statements) >= start_count:
            logger.info("No further reduction possible.")
            break

    # Stage 4: mysqld option reduction
    mysqld_args = stage4_option_reduction(
        statements, basedir, mysqld_args, template,
        target_signature, timeout, trials, mode,
    )

    logger.info(f"\nReduction complete: {original_count} -> {len(statements)} "
                f"statements")
    return statements, mysqld_args


# ===================================================================
# Output
# ===================================================================

def write_reduced(statements, output_path, basedir, mysqld_args,
                  target_signature=None):
    """Write the reduced testcase."""
    with open(output_path, 'w') as f:
        f.write(f"-- Reduced crash reproducer ({len(statements)} statements)\n")
        f.write(f"-- {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"-- Build: {basedir}\n")
        if target_signature:
            f.write(f"-- Signature: {target_signature}\n")
        f.write(f"-- Options: {output_path.rsplit('.', 1)[0]}.opt\n")
        f.write(f"-- Reproduce: mariadb test < {output_path}\n")
        f.write(f"--\n\n")

        for stmt in statements:
            f.write(f"{stmt};\n")

    # Write .opt file
    opt_path = output_path.rsplit('.', 1)[0] + '.opt'
    with open(opt_path, 'w') as f:
        for opt in (mysqld_args or []):
            f.write(f"{opt}\n")

    logger.info(f"Reduced: {output_path}  ({len(statements)} statements)")
    logger.info(f"Options: {opt_path}")


# ===================================================================
# CLI entry point
# ===================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SQL Testcase Reducer — pquery-style crash reduction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Reduction stages (modeled after pquery reducer.sh):
  V: Verify crash + initial simplification
  1: Adaptive chunk removal (random position, dynamic sizing)
  2: Single statement removal
  3: SQL-aware simplification (strip WHERE/ORDER BY/LIMIT, simplify
     literals, remove unnecessary clauses)
  4: mysqld option reduction

Examples:
  # Reduce a crash from the fuzzer
  %(prog)s --basedir /path/to/mariadb-build \\
           --input crashes/crash_0001.sql \\
           --opt crashes/crash_0001.opt

  # Sporadic crash (retry each reduction 5 times)
  %(prog)s --basedir /path/to/mariadb-build \\
           --input crashes/crash_0001.sql \\
           --opt crashes/crash_0001.opt \\
           --trials 5

  # Force any-crash mode (don't match signature)
  %(prog)s --basedir /path/to/mariadb-build \\
           --input crashes/crash_0001.sql \\
           --any-crash
        """,
    )

    parser.add_argument("--basedir", required=True,
                        help="Path to MariaDB build directory")
    parser.add_argument("--input", required=True,
                        help="Input SQL file with crash-inducing statements")
    parser.add_argument("--output", default=None,
                        help="Output file (default: <input>_reduced.sql)")
    parser.add_argument("--opt", default=None,
                        help="Path to .opt file with mysqld startup arguments")
    parser.add_argument("--mysqld-args", nargs="*", default=None,
                        help="Extra mysqld arguments (alternative to --opt)")
    parser.add_argument("--trials", type=int, default=1,
                        help="Retries per reduction attempt for sporadic "
                             "crashes (pquery NR_OF_TRIAL_REPEATS, default: 1)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Query timeout in seconds (default: 60)")
    parser.add_argument("--max-rounds", type=int, default=10,
                        help="Maximum reduction rounds (default: 10)")
    parser.add_argument("--any-crash", action="store_true",
                        help="Accept any crash (don't match signature)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("sqlglot").setLevel(logging.ERROR)

    # Parse input
    statements = parse_sql_file(args.input)
    if not statements:
        logger.error(f"No SQL statements found in {args.input}")
        sys.exit(1)

    logger.info(f"Loaded {len(statements)} statements from {args.input}")

    # Parse mysqld args
    mysqld_args = parse_opt_file(args.opt)
    if args.mysqld_args:
        mysqld_args.extend(args.mysqld_args)

    if mysqld_args:
        logger.info(f"Using {len(mysqld_args)} mysqld options")

    # Create datadir template (once — copied for each trial)
    logger.info("Initializing datadir template...")
    template = DatadirTemplate(args.basedir, mysqld_args)

    try:
        # Run reduction
        reduced, reduced_args = reduce(
            statements, args.basedir, mysqld_args, template,
            timeout=args.timeout, trials=args.trials,
            max_rounds=args.max_rounds,
        )

        # Write output
        if args.output is None:
            base = args.input.rsplit('.', 1)[0]
            args.output = f"{base}_reduced.sql"

        # Get signature for output header
        _, target_sig, _ = verify_and_simplify(
            reduced, args.basedir, reduced_args, template,
            args.timeout, args.trials,
        )

        write_reduced(reduced, args.output, args.basedir, reduced_args,
                      target_sig)

        logger.info("=" * 60)
        logger.info(f"Reduction: {len(statements)} -> {len(reduced)} statements")
        ratio = (1 - len(reduced) / len(statements)) * 100 if statements else 0
        logger.info(f"Ratio: {ratio:.0f}%")
        if len(mysqld_args) != len(reduced_args):
            logger.info(f"Options: {len(mysqld_args)} -> {len(reduced_args)}")
        logger.info("=" * 60)

    finally:
        template.cleanup()


if __name__ == "__main__":
    main()
