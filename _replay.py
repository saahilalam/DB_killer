#!/usr/bin/env python3
"""
Replay a SQL file through mysql.connector — same as the fuzzer does.
Used by reduce.sh and crash_NNNN.sh to reproduce crashes the same way
they were found.

Key: uses the Python mysql.connector (same driver as the fuzzer), not
the mariadb CLI client.  This matters because the CLI handles NUL bytes,
multi-statements, and reconnection differently.

Usage: python3 _replay.py <socket_path> <sql_file>
"""

import sys
import time
import mysql.connector


def parse_statements(content):
    """Parse SQL content into individual statements, handling quotes."""
    statements = []
    current = []
    in_single_quote = False
    in_double_quote = False
    in_line_comment = False

    i = 0
    while i < len(content):
        c = content[i]

        if in_line_comment:
            if c == '\n':
                in_line_comment = False
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


def main():
    socket_path = sys.argv[1]
    sql_file = sys.argv[2]

    with open(sql_file, 'r', errors='replace') as f:
        content = f.read()

    # Strip NUL bytes that may be in the file
    content = content.replace('\x00', '')

    statements = parse_statements(content)

    def connect():
        return mysql.connector.connect(
            unix_socket=socket_path,
            user='root',
            database='test',
            connection_timeout=30,
        )

    try:
        conn = connect()
    except Exception as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    total = errors = reconnects = 0
    for stmt in statements:
        total += 1
        try:
            cursor = conn.cursor()
            cursor.execute(stmt)
            try:
                cursor.fetchall()
            except Exception:
                pass
            cursor.close()
        except mysql.connector.Error as e:
            errno = e.errno if hasattr(e, 'errno') else 0
            errors += 1
            if errno in (2006, 2013, 2055):
                # Server gone — try to reconnect
                for attempt in range(10):
                    time.sleep(1)
                    try:
                        conn = connect()
                        reconnects += 1
                        break
                    except Exception:
                        pass
                else:
                    print(f"SERVER CRASHED at query {total}: {stmt[:120]}")
                    print(f"  Executed {total} queries, {errors} errors, "
                          f"{reconnects} reconnects")
                    sys.exit(0)
        except Exception:
            errors += 1
            try:
                conn.ping(reconnect=True)
            except Exception:
                try:
                    conn = connect()
                    reconnects += 1
                except Exception:
                    print(f"SERVER CRASHED at query {total}: {stmt[:120]}")
                    sys.exit(0)

        if total % 5000 == 0:
            print(f"  {total} queries executed...")

    print(f"Completed: {total} queries, {errors} errors, "
          f"{reconnects} reconnects")

    try:
        conn.close()
    except Exception:
        pass


if __name__ == '__main__':
    main()
