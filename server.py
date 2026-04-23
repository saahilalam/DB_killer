"""
MariaDB server lifecycle manager.
Handles init, start, stop, crash detection, and auto-restart
when given a --basedir pointing to a MariaDB build directory.
"""

import atexit
import logging
import os
import random
import shutil
import signal
import socket
import subprocess
import tempfile
import time

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# InnoDB startup option combinations from InnoDB_standard.cc
# Each list is an "axis" — one option is picked randomly per axis.
# Empty strings mean "use default". --loose- prefix ensures unknown
# variables in older versions don't crash the server on startup.
# -------------------------------------------------------------------------
INNODB_COMBINATIONS = [
    # innodb_page_size + innodb_buffer_pool_size (must match)
    [
        "--loose-innodb_page_size=4K  --loose-innodb-buffer-pool-size=5M",
        "--loose-innodb_page_size=4K  --loose-innodb-buffer-pool-size=6M",
        "--loose-innodb_page_size=4K  --loose-innodb-buffer-pool-size=256M",
        "--loose-innodb_page_size=8K  --loose-innodb-buffer-pool-size=8M",
        "--loose-innodb_page_size=8K  --loose-innodb-buffer-pool-size=256M",
        "--loose-innodb_page_size=16K --loose-innodb-buffer-pool-size=8M",
        "--loose-innodb_page_size=16K --loose-innodb-buffer-pool-size=10M",
        "--loose-innodb_page_size=16K --loose-innodb-buffer-pool-size=256M",
        "--loose-innodb_page_size=32K --loose-innodb-buffer-pool-size=24M",
        "--loose-innodb_page_size=32K --loose-innodb-buffer-pool-size=256M",
        "--loose-innodb_page_size=64K --loose-innodb-buffer-pool-size=24M",
        "--loose-innodb_page_size=64K --loose-innodb-buffer-pool-size=29M",
        "--loose-innodb_page_size=64K --loose-innodb-buffer-pool-size=256M",
    ],
    # lock_wait_timeout + innodb_lock_wait_timeout
    [
        "--lock-wait-timeout=15 --loose-innodb-lock-wait-timeout=10",
        "--lock-wait-timeout=86400 --loose-innodb-lock-wait-timeout=50",
    ],
    # innodb_fast_shutdown
    [
        "--loose-innodb_fast_shutdown=1",
        "",
        "",
        "",
        "--loose-innodb_fast_shutdown=0",
    ],
    # sql_mode
    [
        "--sql_mode=STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION",
        "--sql_mode=traditional",
    ],
    # innodb_file_per_table
    [
        "",
        "--loose-innodb_file_per_table=0",
        "--loose-innodb_file_per_table=1",
    ],
    # innodb_sync_debug
    [
        "--loose-innodb-sync-debug",
        "",
    ],
    # innodb_stats_persistent
    [
        "--loose-innodb_stats_persistent=off",
        "--loose-innodb_stats_persistent=on",
    ],
    # innodb_adaptive_hash_index
    [
        "--loose-innodb_adaptive_hash_index=off",
        "--loose-innodb_adaptive_hash_index=on",
    ],
    # innodb_sort_buffer_size
    [
        "--loose-innodb_sort_buffer_size=65536",
        "",
        "",
        "",
    ],
    # innodb_random_read_ahead
    [
        "--loose-innodb_random_read_ahead=OFF",
        "--loose-innodb_random_read_ahead=OFF",
        "--loose-innodb_random_read_ahead=ON --loose-innodb_read_ahead_threshold=0",
        "--loose-innodb_random_read_ahead=ON",
    ],
    # innodb_open_files (small value stresses file management)
    [
        "--loose-innodb-open-files=10",
        "",
        "",
        "",
        "",
    ],
    # innodb_log_buffer_size
    [
        "--loose-innodb_log_buffer_size=2M",
        "",
        "",
        "",
    ],
    # binary logging
    [
        "--log-bin --sync-binlog=1",
        "--log-bin --sync-binlog=1",
        "",
    ],
    # innodb_evict_tables_on_commit_debug
    [
        "--loose-innodb_evict_tables_on_commit_debug=off",
        "--loose-innodb_evict_tables_on_commit_debug=on",
    ],
    # innodb_undo_log_truncate
    [
        "--loose-innodb_undo_log_truncate=OFF",
        "--loose-innodb_undo_log_truncate=OFF",
        "--loose-innodb_undo_log_truncate=OFF",
        "--loose-innodb_undo_log_truncate=ON",
    ],
    # innodb_undo_tablespaces
    [
        "",
        "",
        "--loose-innodb_undo_tablespaces=0",
        "--loose-innodb_undo_tablespaces=3",
        "--loose-innodb_undo_tablespaces=16",
    ],
    # innodb_rollback_on_timeout
    [
        "--loose-innodb_rollback_on_timeout=ON",
        "--loose-innodb_rollback_on_timeout=OFF",
        "--loose-innodb_rollback_on_timeout=OFF",
        "--loose-innodb_rollback_on_timeout=OFF",
    ],
    # innodb_data_file_path with autoshrink (since 11.2, skip for older)
    # Commented out — causes startup failure on 10.x
    # [
    #     "--loose-innodb_data_file_path=ibdata1:1M:autoextend:autoshrink",
    #     "",
    #     "",
    #     "",
    # ],
    # encryption — requires file_key_management plugin
    [
        "--loose-plugin-load-add=file_key_management "
        "--loose-file-key-management-filename=/dev/urandom "
        "--loose-innodb_encrypt_tables=ON "
        "--loose-innodb_encryption_threads=2",
        "--loose-plugin-load-add=file_key_management "
        "--loose-file-key-management-filename=/dev/urandom "
        "--loose-innodb_encrypt_tables=FORCE "
        "--loose-innodb_encryption_threads=4",
        "",
        "",
        "",
    ],
    # innodb_force_recovery — recovery modes hit unique code paths
    [
        "",
        "",
        "",
        "",
        "--loose-innodb_force_recovery=1",
        "--loose-innodb_force_recovery=2",
    ],
]


# rr tracing options — matches InnoDB_standard.cc:
#   ~2/3 of runs use rr (trace analysis is faster than core dumps)
#   ~1/3 without rr (covers libaio/liburing code paths)
#   When rr is off, use native-aio=1 to cover that path.
RR_COMBINATIONS = [
    # rr record --wait (standard)
    "rr record --wait",
    # rr record --chaos --wait (randomized thread scheduling — better for races)
    "rr record --chaos --wait",
    # No rr — cover native-aio path
    "",
]


def pick_innodb_combination():
    """
    Pick one random option from each axis of the combinations matrix.
    Returns a list of mysqld arguments.
    """
    args = []
    for axis in INNODB_COMBINATIONS:
        choice = random.choice(axis)
        if choice.strip():
            # Split multi-arg strings into individual args
            args.extend(choice.strip().split())
    return args


def pick_rr_mode():
    """Pick a random rr mode from RR_COMBINATIONS.

    Returns the rr command string (e.g. 'rr record --wait') or empty
    string for no-rr runs.  When rr is off, returns
    '--innodb_use_native_aio=1' as an extra mysqld option to cover
    the libaio/liburing path.
    """
    return random.choice(RR_COMBINATIONS)


class MariaDBServer:
    """Manages a MariaDB server instance from a build directory."""

    def __init__(self, basedir, datadir=None, port=None, tmpdir=None,
                 rr_trace=False, dbdir_type='fast'):
        self.basedir = os.path.abspath(basedir)
        self.port = port or self._find_free_port()
        self.tmpdir = tmpdir or tempfile.mkdtemp(prefix="ast_fuzzer_")
        self.datadir = datadir or os.path.join(self.tmpdir, "data")
        self.socket_path = os.path.join(self.tmpdir, "mariadb.sock")
        self.pid_file = os.path.join(self.tmpdir, "mariadb.pid")
        self.error_log = os.path.join(self.tmpdir, "error.log")
        self.process = None
        self._initialized = False
        # rr_trace: False/None = disabled, or a string like 'rr record' / 'rr record --chaos --wait'
        self.rr_trace = rr_trace
        # dbdir_type: 'fast' (tmpfs/RAM) or 'slow' (ext4/HDD/SSD)
        # Affects rr options — ext4 needs --innodb_flush_method=fsync
        self.dbdir_type = dbdir_type
        self.rr_trace_dir = os.path.join(self.tmpdir, "rr_trace") if rr_trace else None

        # Binaries
        self.mysqld = os.path.join(basedir, "bin", "mariadbd")
        if not os.path.exists(self.mysqld):
            self.mysqld = os.path.join(basedir, "bin", "mysqld")

        self.mysql_install_db = os.path.join(basedir, "scripts", "mariadb-install-db")
        if not os.path.exists(self.mysql_install_db):
            self.mysql_install_db = os.path.join(basedir, "scripts", "mysql_install_db")
        if not os.path.exists(self.mysql_install_db):
            self.mysql_install_db = os.path.join(basedir, "bin", "mariadb-install-db")
        if not os.path.exists(self.mysql_install_db):
            self.mysql_install_db = os.path.join(basedir, "bin", "mysql_install_db")

        self.mysql_client = os.path.join(basedir, "bin", "mariadb")
        if not os.path.exists(self.mysql_client):
            self.mysql_client = os.path.join(basedir, "bin", "mysql")

        self.startup_options = []  # Tracks the full set of mysqld args used

        # Validate
        if not os.path.exists(self.mysqld):
            raise FileNotFoundError(f"mariadbd/mysqld not found in {basedir}/bin/")

        # Cleanup on exit
        atexit.register(self._cleanup)

    def _find_free_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]

    def initialize(self, bootstrap_args=None):
        """Initialize the data directory (mysql_install_db)."""
        if os.path.exists(self.datadir) and os.listdir(self.datadir):
            logger.info(f"Datadir already exists: {self.datadir}")
            self._initialized = True
            return

        os.makedirs(self.datadir, exist_ok=True)

        logger.info(f"Initializing datadir at {self.datadir}")

        cmd = [
            self.mysql_install_db,
            f"--basedir={self.basedir}",
            f"--datadir={self.datadir}",
            "--user=" + os.environ.get("USER", "root"),
            "--auth-root-authentication-method=normal",
        ]

        # Pass bootstrap-time options (e.g. innodb_page_size) directly to mysql_install_db.
        # Per the help: "All other options are passed to the mariadbd program"
        if bootstrap_args:
            cmd.extend(bootstrap_args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
                env={**os.environ, "MYSQL_HOME": self.basedir},
            )
            if result.returncode != 0:
                logger.error(f"mysql_install_db failed:\n{result.stderr}")
                raise RuntimeError(f"Failed to initialize datadir: {result.stderr[:500]}")
            logger.info("Datadir initialized successfully")
            self._initialized = True
        except FileNotFoundError:
            raise FileNotFoundError(
                f"mysql_install_db not found. Searched:\n"
                f"  {self.basedir}/scripts/mariadb-install-db\n"
                f"  {self.basedir}/scripts/mysql_install_db\n"
                f"  {self.basedir}/bin/mariadb-install-db\n"
                f"  {self.basedir}/bin/mysql_install_db"
            )

    def start(self, extra_args=None):
        """Start the MariaDB server."""
        # innodb_page_size is a bootstrap-time option — if it's in extra_args,
        # we must initialize the datadir with that page size
        bootstrap_args = []
        if extra_args:
            for arg in extra_args:
                if "innodb_page_size" in arg or "innodb-page-size" in arg:
                    bootstrap_args.append(arg)

        if not self._initialized:
            self.initialize(bootstrap_args=bootstrap_args)

        # Check core dump configuration
        self._check_core_dump_config()

        logger.info(f"Starting MariaDB on port {self.port}")

        cmd = [
            self.mysqld,
            f"--basedir={self.basedir}",
            f"--datadir={self.datadir}",
            f"--port={self.port}",
            f"--socket={self.socket_path}",
            f"--pid-file={self.pid_file}",
            f"--log-error={self.error_log}",
            "--skip-grant-tables",
            "--skip-networking=0",
            f"--tmpdir={self.tmpdir}",
            # Use --loose- for variables that may not exist in all versions
            "--loose-innodb-buffer-pool-size=128M",
            "--loose-innodb-log-file-size=48M",
            "--max-connections=50",
            "--loose-innodb-flush-log-at-trx-commit=0",
            "--loose-sync-binlog=0",
            "--core-file",
            # InnoDB defaults matching InnoDB_standard.cc
            "--loose-innodb_lock_schedule_algorithm=fcfs",
            "--loose-idle_write_transaction_timeout=0",
            "--loose-idle_transaction_timeout=0",
            "--loose-idle_readonly_transaction_timeout=0",
            "--connect_timeout=60",
            "--loose-innodb_fatal_semaphore_wait_threshold=300",
            "--log_output=none",
            "--log_bin_trust_function_creators=1",
            "--loose-debug_assert_on_not_freed_memory=0",
            "--loose-innodb_read_only_compressed=OFF",
            "--loose-max-statement-time=30",
        ]

        if extra_args:
            cmd.extend(extra_args)

        # Save the full startup options for testcase reproducibility
        self.startup_options = cmd[1:]  # skip the binary path
        logger.info("mysqld startup options:")
        for opt in cmd[1:]:
            if opt.startswith("--") and "basedir" not in opt and "datadir" not in opt \
               and "socket" not in opt and "pid-file" not in opt and "log-error" not in opt \
               and "tmpdir" not in opt and "port" not in opt:
                logger.info(f"  {opt}")

        # Set working directory to datadir so core dumps land there
        # Also try to set core_pattern to write into datadir (needs root)
        self._setup_core_to_vardir()

        # Wrap with rr if enabled (e.g. 'rr record', 'rr record --chaos --wait')
        # Following InnoDB_standard.cc + local.cfg conventions:
        #   - rr has trouble with libaio/liburing → force native-aio=0
        #   - tracing can cause fake hangs → limit write/read-io-threads
        #   - rr+InnoDB on ext4 (slow dir) needs innodb_flush_method=fsync
        #   - set --loose-gdb --loose-debug-gdb for rr compatibility
        if self.rr_trace:
            # Use _RR_TRACE_DIR env variable (same as RQG) instead of -o.
            # This creates the standard rr directory structure:
            #   rr_trace/mariadbd-0, rr_trace/mariadbd-1, rr_trace/latest-trace
            os.makedirs(self.rr_trace_dir, exist_ok=True)
            rr_cmd = self.rr_trace.split()
            cmd = rr_cmd + cmd
            # Base rr-required mysqld options (from local.cfg $rqg_rr_add)
            rr_mysqld_opts = [
                "--loose-innodb-use-native-aio=0",
                "--loose-innodb-write-io-threads=2",
                "--loose-innodb-read-io-threads=1",
                "--loose-gdb",
                "--loose-debug-gdb",
            ]
            # Slow dir (ext4/HDD/SSD) needs fsync (from local.cfg $rqg_slow_dbdir_rr_add)
            if self.dbdir_type == 'slow':
                rr_mysqld_opts.append("--loose-innodb_flush_method=fsync")
            for opt in rr_mysqld_opts:
                if opt not in cmd:
                    cmd.append(opt)
            logger.info(f"rr tracing ({self.dbdir_type} dir): {' '.join(rr_cmd)} → {self.rr_trace_dir}")

        # Capture stderr to a file so we can diagnose rr/server startup failures
        self._stderr_log = os.path.join(self.tmpdir, "startup_stderr.log")
        stderr_fh = open(self._stderr_log, 'w')

        # Set _RR_TRACE_DIR so rr creates traces in our directory
        # (same as RQG — produces mariadbd-0, mariadbd-1, latest-trace)
        proc_env = os.environ.copy()
        if self.rr_trace and self.rr_trace_dir:
            proc_env['_RR_TRACE_DIR'] = self.rr_trace_dir

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=stderr_fh,
            cwd=self.datadir,  # cores written to cwd by default
            env=proc_env,
        )

        # Wait for server to be ready
        rr_timeout = 120 if self.rr_trace else 60  # rr startup is slower
        if not self._wait_for_server(timeout=rr_timeout):
            stderr_fh.close()
            # Check if process died
            if self.process.poll() is not None:
                logger.error(f"Server exited with code {self.process.returncode}")
                if os.path.exists(self.error_log):
                    with open(self.error_log, 'r') as f:
                        lines = f.readlines()
                        logger.error("Last error log lines:\n" + "".join(lines[-20:]))
                # Show stderr (often has rr error messages)
                if os.path.exists(self._stderr_log):
                    with open(self._stderr_log, 'r') as f:
                        stderr_text = f.read().strip()
                    if stderr_text:
                        logger.error(f"Stderr output:\n{stderr_text[:500]}")
                raise RuntimeError("MariaDB server failed to start")
            raise RuntimeError("Timeout waiting for server to start")
        stderr_fh.close()

        logger.info(f"MariaDB started (pid={self.process.pid}, port={self.port}, socket={self.socket_path})")

        # Create the test database
        self._create_test_db()

    def _setup_core_to_vardir(self):
        """Try to configure core dumps to land in the datadir."""
        core_path = os.path.join(self.datadir, "core")

        # Method 1: Set kernel.core_pattern (needs root)
        try:
            pattern = f"{self.datadir}/core.%e.%p.%t"
            subprocess.run(
                ["sysctl", "-w", f"kernel.core_pattern={pattern}"],
                capture_output=True, timeout=5,
            )
            logger.info(f"Set core_pattern to {pattern}")
            return
        except Exception:
            pass

        # Method 2: If core_pattern is just "core" (no path), cwd handles it
        # since we set cwd=datadir on Popen. Nothing more to do.

        # Method 3: Suggest manual fix if apport is in the way
        try:
            with open("/proc/sys/kernel/core_pattern", "r") as f:
                pattern = f.read().strip()
            if pattern.startswith("|"):
                logger.warning(
                    f"Core dumps go through a pipe handler ({pattern[:40]}...). "
                    f"To save cores in vardir, run:\n"
                    f"  sudo sysctl -w kernel.core_pattern={self.datadir}/core.%e.%p.%t"
                )
        except Exception:
            pass

    def _check_core_dump_config(self):
        """Check OS core dump settings and warn if cores might not be saved."""
        try:
            with open("/proc/sys/kernel/core_pattern", "r") as f:
                pattern = f.read().strip()

            if pattern.startswith("|"):
                # Piped to a program (apport, systemd-coredump, etc.)
                if "apport" in pattern:
                    logger.warning(
                        "Core dumps are handled by apport — cores may not be saved as files. "
                        "To get core files directly, run:\n"
                        "  sudo sysctl -w kernel.core_pattern=%s/core.%%e.%%p.%%t\n"
                        "  (or disable apport: sudo systemctl stop apport)" % self.tmpdir
                    )
                    self._core_pattern = "apport"
                elif "systemd-coredump" in pattern:
                    logger.info("Core dumps handled by systemd-coredump. Use 'coredumpctl' to retrieve them.")
                    self._core_pattern = "systemd"
                else:
                    logger.warning(f"Core dumps piped to: {pattern}")
                    self._core_pattern = "piped"
            else:
                self._core_pattern = pattern
                logger.info(f"Core pattern: {pattern}")

            with open("/proc/sys/fs/suid_dumpable", "r") as f:
                dumpable = f.read().strip()
            if dumpable == "0":
                logger.warning("suid_dumpable=0 — setuid processes won't dump cores. "
                               "Run: sudo sysctl -w fs.suid_dumpable=2")
        except Exception as e:
            logger.debug(f"Could not check core dump config: {e}")
            self._core_pattern = "unknown"

    def _wait_for_server(self, timeout=60):
        """Wait for the server to accept connections."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process.poll() is not None:
                return False
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(self.socket_path)
                s.close()
                # Give it a moment after socket is available
                time.sleep(0.5)
                return True
            except (socket.error, FileNotFoundError):
                time.sleep(0.5)
        return False

    def _create_test_db(self):
        """Create the 'test' database if it doesn't exist."""
        try:
            cmd = [self.mysql_client, f"--socket={self.socket_path}",
                   "-u", "root", "-e", "CREATE DATABASE IF NOT EXISTS test"]
            subprocess.run(cmd, capture_output=True, timeout=10)
        except Exception as e:
            logger.warning(f"Could not create test database: {e}")

    def stop(self):
        """Stop the server gracefully."""
        if self.process and self.process.poll() is None:
            logger.info("Stopping MariaDB server...")
            self.process.terminate()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                logger.warning("Server didn't stop gracefully, killing...")
                self.process.kill()
                self.process.wait(timeout=10)
            logger.info("MariaDB server stopped")

    def is_alive(self):
        """Check if the server process is still running."""
        if self.process is None:
            return False
        return self.process.poll() is None

    def restart(self, extra_args=None):
        """Restart server after a crash. Reinitializes datadir if recovery fails."""
        self.stop()
        time.sleep(1)

        # First try: start on existing datadir (InnoDB crash recovery)
        try:
            self.start(extra_args)
            return
        except Exception as e:
            logger.warning(f"Server failed to start on existing datadir (crash recovery failed): {e}")

        # Second try: wipe datadir and reinitialize
        logger.info("Reinitializing datadir for fresh start...")
        if os.path.exists(self.datadir):
            shutil.rmtree(self.datadir)
        self._initialized = False
        # Also remove old error log to start fresh
        if os.path.exists(self.error_log):
            os.remove(self.error_log)
        self.start(extra_args)

    def get_connection_args(self):
        """Return connection parameters for mysql.connector."""
        return {
            "host": "127.0.0.1",
            "port": self.port,
            "user": "root",
            "password": "",
            "database": "test",
            "unix_socket": self.socket_path,
            "connection_timeout": 30,
        }

    def check_crash(self):
        """
        Check if the server crashed. Returns crash info dict or None.
        """
        if self.is_alive():
            return None

        exit_code = self.process.returncode
        crash_info = {
            "exit_code": exit_code,
            "signal": None,
            "signal_name": None,
            "error_log_tail": "",
            "core_dump": False,
            "pid": self.process.pid,
        }

        # Negative exit code = killed by signal
        if exit_code < 0:
            crash_info["signal"] = -exit_code
            sig_names = {
                6: "SIGABRT (assertion failure)",
                7: "SIGBUS",
                8: "SIGFPE",
                11: "SIGSEGV (segmentation fault)",
                15: "SIGTERM",
            }
            crash_info["signal_name"] = sig_names.get(-exit_code, f"signal {-exit_code}")

        # Read error log tail
        if os.path.exists(self.error_log):
            with open(self.error_log, 'r') as f:
                lines = f.readlines()
                crash_info["error_log_tail"] = "".join(lines[-50:])

        # Check for core dump in multiple locations
        import glob as g
        pid = self.process.pid
        core_search_patterns = [
            os.path.join(self.datadir, "core"),
            os.path.join(self.datadir, f"core.*"),
            os.path.join(self.datadir, f"core.{pid}"),
            os.path.join(self.tmpdir, "core"),
            os.path.join(self.tmpdir, f"core.*"),
            f"/tmp/core.{pid}",
            f"/tmp/cores/core.*{pid}*",
            # Common core_pattern locations
            f"/var/crash/*mariadbd*",
            f"/var/lib/apport/coredump/*mariadbd*",
            f"/var/lib/systemd/coredump/*mariadbd*",
        ]
        for pattern in core_search_patterns:
            matches = g.glob(pattern)
            if matches:
                crash_info["core_dump"] = True
                crash_info["core_path"] = matches[0]
                logger.info(f"Core dump found: {matches[0]}")
                break

        # If systemd-coredump, try coredumpctl
        if not crash_info["core_dump"] and getattr(self, '_core_pattern', '') == 'systemd':
            try:
                result = subprocess.run(
                    ["coredumpctl", "info", str(pid)],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    crash_info["core_dump"] = True
                    crash_info["core_path"] = f"coredumpctl (pid {pid})"
                    crash_info["coredumpctl_info"] = result.stdout
                    logger.info(f"Core dump found via coredumpctl for pid {pid}")
            except Exception:
                pass

        if not crash_info["core_dump"] and crash_info.get("signal") in (6, 11):
            logger.warning(
                f"Server crashed with {crash_info.get('signal_name')} but no core dump found. "
                f"Check core_pattern: cat /proc/sys/kernel/core_pattern"
            )

        return crash_info

    def get_error_log_path(self):
        return self.error_log

    def _cleanup(self):
        """Cleanup on process exit."""
        try:
            self.stop()
        except Exception:
            pass
