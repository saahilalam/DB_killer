"""
Schema-aware SQL generator for MariaDB/InnoDB fuzzing.

Generates valid, runnable SQL that references real tables and columns.
Handles statements sqlglot can't parse (ALTER TABLE with ALGORITHM/LOCK,
OPTIMIZE, LOCK TABLES, RENAME, partitions, etc.) as raw SQL.

Each generator function takes a SchemaTracker and returns a SQL string.
"""

import random
from config import (
    pick, chance,
    BAD_INTEGERS, BAD_FLOATS, BAD_STRINGS, BAD_DATES, BAD_DATETIMES,
    ALL_COLUMN_TYPES, INTEGER_TYPES, FLOAT_TYPES, STRING_TYPES,
    INNODB_ROW_FORMATS, INNODB_KEY_BLOCK_SIZES, STORAGE_ENGINES, CHARSETS,
    COLLATIONS, ISOLATION_LEVELS,
    FUNCTION_SWAP_GROUPS, AGGREGATE_SWAP_MAP,
)


# ===================================================================
# Value generators (schema-aware)
# ===================================================================

def gen_value(col):
    """Generate a random value appropriate for the column's data type."""
    if chance(15):
        return 'NULL'

    dt = col.data_type.upper()

    if 'BIT' in dt:
        return f"b'{random.randint(0, 255):08b}'"

    # Float/double/decimal BEFORE is_numeric — is_numeric matches these too
    if any(t in dt for t in ['FLOAT', 'DOUBLE', 'DECIMAL']):
        if chance(4):
            return str(pick(BAD_FLOATS))
        return str(round(random.uniform(-1000, 1000), 4))

    if col.is_numeric:
        if chance(4):
            # Use smaller bad integers to avoid overflow on TINYINT/SMALLINT
            safe_bad = [v for v in BAD_INTEGERS if -2147483648 <= v <= 2147483647]
            return str(pick(safe_bad))
        return str(random.randint(-1000, 1000))

    if 'ENUM' in dt:
        return f"'{pick(['a','b','c','d','e'])}'"

    if 'SET' in dt:
        vals = random.sample(['x','y','z'], random.randint(1,3))
        return f"'{','.join(vals)}'"

    if 'JSON' in dt:
        jsons = ['{}', '{"k":"v"}', '[1,2,3]', 'null',
                 '{"nested":{"deep":1}}', '[]', '[{"a":1}]']
        return f"'{pick(jsons)}'"

    if 'DATE' in dt and 'TIME' not in dt:
        if chance(4):
            return f"'{pick(BAD_DATES)}'"
        return f"'{2000+random.randint(0,25)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}'"

    if 'DATETIME' in dt or 'TIMESTAMP' in dt:
        if chance(4):
            return f"'{pick(BAD_DATETIMES)}'"
        return (f"'{2000+random.randint(0,25)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
                f" {random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}'")

    if 'TIME' in dt:
        return f"'{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}'"

    if 'BLOB' in dt or 'BINARY' in dt:
        return f"UNHEX('{random.randint(0,0xFFFFFFFF):08X}')"

    # String types (CHAR, VARCHAR, TEXT)
    if chance(5):
        return f"'{pick(BAD_STRINGS)}'"
    length = random.randint(1, 50)
    chars = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789 _-', k=length))
    # Escape single quotes
    chars = chars.replace("'", "''")
    return f"'{chars}'"


def gen_literal():
    """Generate a random literal value (not schema-aware)."""
    kind = random.randint(0, 4)
    if kind == 0:
        return str(pick(BAD_INTEGERS))
    elif kind == 1:
        return str(round(random.uniform(-1000, 1000), 2))
    elif kind == 2:
        s = ''.join(random.choices('abcdefghijklmnop', k=random.randint(1, 20)))
        return f"'{s}'"
    elif kind == 3:
        return 'NULL'
    else:
        return f"'{pick(BAD_DATES)}'"


# ===================================================================
# SELECT generators
# ===================================================================

def gen_select(schema):
    """Generate a valid SELECT statement."""
    tbl = schema.random_table()
    if not tbl:
        return "SELECT 1"

    # Pick columns to select
    action = random.randint(0, 6)

    if action == 0:
        # SELECT *
        sql = f"SELECT * FROM {tbl.name}"
    elif action == 1:
        # SELECT specific columns
        cols = tbl.random_columns(random.randint(1, min(5, len(tbl.columns))))
        col_list = ', '.join(c.name for c in cols)
        sql = f"SELECT {col_list} FROM {tbl.name}"
    elif action == 2:
        # SELECT with aggregate
        col = tbl.random_column()
        agg = pick(['COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'GROUP_CONCAT'])
        arg = col.name if col else '*'
        if agg == 'COUNT' and chance(2):
            arg = '*'
        sql = f"SELECT {agg}({arg}) FROM {tbl.name}"
    elif action == 3:
        # SELECT with GROUP BY
        col = tbl.random_column()
        agg_col = tbl.random_column()
        if col and agg_col:
            agg = pick(['COUNT', 'SUM', 'AVG', 'MIN', 'MAX'])
            sql = (f"SELECT {col.name}, {agg}({agg_col.name}) "
                   f"FROM {tbl.name} GROUP BY {col.name}")
        else:
            sql = f"SELECT * FROM {tbl.name}"
    elif action == 4:
        # SELECT with JOIN
        tbl2 = schema.random_table()
        if tbl2 and tbl2.name != tbl.name:
            col1 = tbl.random_column()
            col2 = tbl2.random_column()
            join_type = pick(['JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'INNER JOIN', 'CROSS JOIN'])
            if col1 and col2:
                sql = (f"SELECT a.{col1.name}, b.{col2.name} "
                       f"FROM {tbl.name} a {join_type} {tbl2.name} b "
                       f"ON a.{col1.name} = b.{col2.name}")
            else:
                sql = f"SELECT * FROM {tbl.name} a {join_type} {tbl2.name} b"
        else:
            # Self join — always use aliases to avoid ambiguity
            col = tbl.random_column()
            col2 = tbl.random_column()
            if col and col2:
                sql = (f"SELECT a.{col.name}, b.{col2.name} "
                       f"FROM {tbl.name} a JOIN {tbl.name} b "
                       f"ON a.{col.name} = b.{col.name} "
                       f"WHERE a.{col2.name} IS NOT NULL")
            else:
                sql = f"SELECT * FROM {tbl.name}"
    elif action == 5:
        # SELECT with subquery
        col = tbl.random_column()
        tbl2 = schema.random_table()
        if col and tbl2:
            sub_col = tbl2.random_column()
            if sub_col:
                sql = (f"SELECT * FROM {tbl.name} WHERE {col.name} IN "
                       f"(SELECT {sub_col.name} FROM {tbl2.name})")
            else:
                sql = f"SELECT * FROM {tbl.name}"
        else:
            sql = f"SELECT * FROM {tbl.name}"
    else:
        # SELECT DISTINCT
        col = tbl.random_column()
        sql = f"SELECT DISTINCT {col.name if col else '*'} FROM {tbl.name}"

    # Add WHERE (only if not already present — subquery/JOIN selects may have one)
    if 'WHERE' not in sql.upper() and chance(2):
        sql += f" WHERE {_gen_where(tbl)}"

    # Add ORDER BY (use table alias if JOIN, to avoid ambiguity)
    if chance(3):
        col = tbl.random_column()
        if col:
            direction = pick(['ASC', 'DESC'])
            if ' a ' in sql and ' b ' in sql:
                # JOIN query — qualify column with alias
                sql += f" ORDER BY a.{col.name} {direction}"
            else:
                sql += f" ORDER BY {col.name} {direction}"

    # Add LIMIT
    if chance(3):
        sql += f" LIMIT {pick([1, 5, 10, 100, 1000])}"

    # Add locking
    if chance(10):
        sql += pick([' FOR UPDATE', ' LOCK IN SHARE MODE'])

    return sql


def _gen_where(tbl):
    """Generate a WHERE clause using real columns."""
    col = tbl.random_column()
    if not col:
        return "1=1"

    action = random.randint(0, 9)

    if action == 0:
        return f"{col.name} IS NULL"
    elif action == 1:
        return f"{col.name} IS NOT NULL"
    elif action == 2:
        return f"{col.name} = {gen_value(col)}"
    elif action == 3:
        return f"{col.name} != {gen_value(col)}"
    elif action == 4:
        return f"{col.name} > {gen_value(col)}"
    elif action == 5:
        return f"{col.name} < {gen_value(col)}"
    elif action == 6:
        return f"{col.name} BETWEEN {gen_value(col)} AND {gen_value(col)}"
    elif action == 7:
        vals = ', '.join(gen_value(col) for _ in range(random.randint(1, 5)))
        return f"{col.name} IN ({vals})"
    elif action == 8:
        if col.is_string:
            return f"{col.name} LIKE '{pick(['%test%', '_%', 'a%', '%'])}'"
        return f"{col.name} = {gen_value(col)}"
    else:
        # Compound
        col2 = tbl.random_column()
        op = pick(['AND', 'OR', 'XOR'])
        if col2:
            return f"{col.name} = {gen_value(col)} {op} {col2.name} IS NOT NULL"
        return f"{col.name} = {gen_value(col)}"


# ===================================================================
# INSERT generators
# ===================================================================

def gen_insert(schema):
    """Generate a valid INSERT statement."""
    tbl = schema.random_table()
    if not tbl:
        return None

    insertable = tbl.insertable_columns()
    if not insertable:
        return None

    action = random.randint(0, 4)

    if action == 0:
        # INSERT INTO t (cols) VALUES (vals)
        cols = insertable
        col_names = ', '.join(c.name for c in cols)
        vals = ', '.join(gen_value(c) for c in cols)
        sql = f"INSERT INTO {tbl.name} ({col_names}) VALUES ({vals})"

    elif action == 1:
        # INSERT IGNORE (subset of columns)
        n = random.randint(1, len(insertable))
        cols = random.sample(insertable, n)
        col_names = ', '.join(c.name for c in cols)
        vals = ', '.join(gen_value(c) for c in cols)
        sql = f"INSERT IGNORE INTO {tbl.name} ({col_names}) VALUES ({vals})"

    elif action == 2:
        # Multi-row INSERT
        cols = insertable
        col_names = ', '.join(c.name for c in cols)
        rows = []
        for _ in range(random.randint(2, 10)):
            vals = ', '.join(gen_value(c) for c in cols)
            rows.append(f"({vals})")
        sql = f"INSERT INTO {tbl.name} ({col_names}) VALUES {', '.join(rows)}"

    elif action == 3:
        # INSERT ... ON DUPLICATE KEY UPDATE
        cols = insertable
        col_names = ', '.join(c.name for c in cols)
        vals = ', '.join(gen_value(c) for c in cols)
        # Pick a non-PK, non-auto-inc column to update
        updatable = [c for c in cols if not c.is_auto_inc]
        if updatable:
            upd_col = pick(updatable)
            update_expr = f"{upd_col.name} = VALUES({upd_col.name})"
        else:
            update_expr = f"{cols[0].name} = {cols[0].name}"
        sql = (f"INSERT INTO {tbl.name} ({col_names}) VALUES ({vals}) "
               f"ON DUPLICATE KEY UPDATE {update_expr}")

    else:
        # REPLACE INTO
        cols = insertable
        col_names = ', '.join(c.name for c in cols)
        vals = ', '.join(gen_value(c) for c in cols)
        sql = f"REPLACE INTO {tbl.name} ({col_names}) VALUES ({vals})"

    return sql


# ===================================================================
# UPDATE generators
# ===================================================================

def gen_update(schema):
    """Generate a valid UPDATE statement."""
    tbl = schema.random_table()
    if not tbl:
        return None

    # Pick columns to update (not auto_inc, not virtual/persistent)
    updatable = [c for c in tbl.columns
                 if not c.is_auto_inc and not c.is_virtual and not c.is_persistent]
    if not updatable:
        return None

    n = random.randint(1, min(3, len(updatable)))
    cols = random.sample(updatable, n)

    set_clauses = []
    for c in cols:
        if c.is_numeric and chance(3):
            # Self-referencing: col = col + 1
            op = pick(['+', '-', '*'])
            val = pick([1, -1, 2, 10, 0])
            set_clauses.append(f"{c.name} = {c.name} {op} {val}")
        else:
            set_clauses.append(f"{c.name} = {gen_value(c)}")

    sql = f"UPDATE {tbl.name} SET {', '.join(set_clauses)}"

    # WHERE (almost always — avoid full table update)
    if chance(20):
        # Rare: no WHERE (interesting for InnoDB locking)
        pass
    else:
        sql += f" WHERE {_gen_where(tbl)}"

    # ORDER BY + LIMIT
    if chance(5):
        col = tbl.random_column()
        if col:
            sql += f" ORDER BY {col.name} {pick(['ASC','DESC'])} LIMIT {pick([1,5,10,100])}"

    return sql


# ===================================================================
# DELETE generators
# ===================================================================

def gen_delete(schema):
    """Generate a valid DELETE statement."""
    tbl = schema.random_table()
    if not tbl:
        return None

    sql = f"DELETE FROM {tbl.name}"

    if chance(30):
        # Rare: DELETE without WHERE (truncate-like)
        pass
    else:
        sql += f" WHERE {_gen_where(tbl)}"

    if chance(5):
        col = tbl.random_column()
        if col:
            sql += f" ORDER BY {col.name} LIMIT {pick([1, 5, 10])}"

    return sql


# ===================================================================
# ALTER TABLE generators (native SQL — bypasses sqlglot)
# ===================================================================

def gen_alter_table(schema):
    """Generate a valid ALTER TABLE statement using real table/column names."""
    tbl = schema.random_table()
    if not tbl:
        return None

    action = random.randint(0, 19)

    if action == 0:
        # ADD COLUMN
        new_name = f"fz_col_{random.randint(0,999)}"
        new_type = pick(ALL_COLUMN_TYPES)
        size = ''
        if new_type in ('VARCHAR', 'CHAR', 'VARBINARY'):
            size = f"({pick([10, 50, 100, 255])})"
        elif new_type == 'DECIMAL':
            size = f"({pick([5,10,20])},{pick([0,2,5])})"
        return f"ALTER TABLE {tbl.name} ADD COLUMN {new_name} {new_type}{size}"

    elif action == 1:
        # DROP COLUMN (not PK, not last column)
        droppable = [c for c in tbl.columns
                     if not c.is_auto_inc and len(tbl.columns) > 2]
        if droppable:
            col = pick(droppable)
            return f"ALTER TABLE {tbl.name} DROP COLUMN IF EXISTS {col.name}"
        return None

    elif action == 2:
        # MODIFY COLUMN (change type)
        col = tbl.random_column()
        if col and not col.is_auto_inc:
            new_type = pick(ALL_COLUMN_TYPES)
            size = ''
            if new_type in ('VARCHAR', 'CHAR'):
                size = f"({pick([10, 50, 200, 500])})"
            algo = pick(['DEFAULT', 'INSTANT', 'NOCOPY', 'INPLACE', 'COPY'])
            lock = pick(['DEFAULT', 'NONE', 'SHARED', 'EXCLUSIVE'])
            return (f"ALTER TABLE {tbl.name} MODIFY COLUMN {col.name} {new_type}{size}, "
                    f"ALGORITHM={algo}, LOCK={lock}")
        return None

    elif action == 3:
        # ADD INDEX
        col = tbl.random_column()
        if col:
            idx_name = f"idx_fz_{random.randint(0,999)}"
            prefix = ''
            if col.is_string:
                prefix = f"({pick([10, 20, 50])})"
            return f"ALTER TABLE {tbl.name} ADD INDEX IF NOT EXISTS {idx_name} ({col.name}{prefix})"
        return None

    elif action == 4:
        # DROP INDEX
        droppable_idx = [i for i in tbl.indexes if not i.is_primary]
        if droppable_idx:
            idx = pick(droppable_idx)
            return f"ALTER TABLE {tbl.name} DROP INDEX IF EXISTS {idx.name}"
        return None

    elif action == 5:
        # ADD UNIQUE INDEX
        col = tbl.random_column()
        if col:
            idx_name = f"uidx_fz_{random.randint(0,999)}"
            return f"ALTER TABLE {tbl.name} ADD UNIQUE INDEX IF NOT EXISTS {idx_name} ({col.name})"
        return None

    elif action == 6:
        # ENGINE change
        return f"ALTER TABLE {tbl.name} ENGINE={pick(STORAGE_ENGINES)}"

    elif action == 7:
        # ROW_FORMAT change
        return f"ALTER TABLE {tbl.name} ROW_FORMAT={pick(INNODB_ROW_FORMATS)}"

    elif action == 8:
        # ALGORITHM / LOCK only (FORCE rebuild)
        algo = pick(['DEFAULT', 'INPLACE', 'COPY'])
        lock = pick(['DEFAULT', 'NONE', 'SHARED', 'EXCLUSIVE'])
        return f"ALTER TABLE {tbl.name} FORCE, ALGORITHM={algo}, LOCK={lock}"

    elif action == 9:
        # CHARACTER SET change
        charset = pick(CHARSETS)
        return f"ALTER TABLE {tbl.name} CONVERT TO CHARACTER SET {charset}"

    elif action == 10:
        # MODIFY COLUMN position
        col = tbl.random_column()
        if col and not col.is_auto_inc:
            position = pick(['FIRST'] + [f'AFTER {c.name}' for c in tbl.columns[:5]])
            return (f"ALTER TABLE {tbl.name} MODIFY COLUMN IF EXISTS {col.name} "
                    f"{col.data_type} {position}")
        return None

    elif action == 11:
        # ADD FULLTEXT INDEX (text columns only)
        text_cols = [c for c in tbl.columns if any(t in c.data_type.upper()
                     for t in ['TEXT', 'VARCHAR', 'CHAR'])]
        if text_cols:
            col = pick(text_cols)
            idx_name = f"ft_fz_{random.randint(0,999)}"
            return f"ALTER TABLE {tbl.name} ADD FULLTEXT INDEX IF NOT EXISTS {idx_name} ({col.name})"
        return None

    elif action == 12:
        # ENABLE / DISABLE KEYS
        return f"ALTER TABLE {tbl.name} {pick(['ENABLE', 'DISABLE'])} KEYS"

    elif action == 13:
        # ADD generated column
        num_cols = tbl.numeric_columns()
        if num_cols:
            src = pick(num_cols)
            kind = pick(['VIRTUAL', 'PERSISTENT'])
            new_name = f"gc_fz_{random.randint(0,999)}"
            expr = pick([f'{src.name} + 1', f'{src.name} * 2', f'ABS({src.name})',
                         f'{src.name} DIV 10', f'IF({src.name} > 0, 1, 0)'])
            return f"ALTER TABLE {tbl.name} ADD COLUMN {new_name} INT AS ({expr}) {kind}"
        return None

    elif action == 14:
        # KEY_BLOCK_SIZE
        return f"ALTER TABLE {tbl.name} KEY_BLOCK_SIZE={pick(INNODB_KEY_BLOCK_SIZES)}"

    elif action == 15:
        # COMMENT
        return f"ALTER TABLE {tbl.name} COMMENT = 'fuzz_{random.randint(0,9999)}'"

    elif action == 16:
        # CHANGE COLUMN (rename)
        col = tbl.random_column()
        if col and not col.is_auto_inc:
            new_name = f"ren_{col.name}"
            return (f"ALTER TABLE {tbl.name} CHANGE COLUMN IF EXISTS {col.name} "
                    f"{new_name} {col.data_type}")
        return None

    elif action == 17:
        # Auto increment
        return f"ALTER TABLE {tbl.name} AUTO_INCREMENT={pick(BAD_INTEGERS)}"

    elif action == 18:
        # ALTER IGNORE TABLE
        col = tbl.random_column()
        if col:
            return f"ALTER IGNORE TABLE {tbl.name} MODIFY COLUMN {col.name} INT NOT NULL"
        return None

    else:
        # PAGE_COMPRESSED toggle
        return f"ALTER TABLE {tbl.name} PAGE_COMPRESSED={pick([0, 1])}"


# ===================================================================
# Table maintenance statements (native SQL)
# ===================================================================

def gen_table_maintenance(schema):
    """Generate OPTIMIZE / ANALYZE / CHECK / CHECKSUM / REPAIR TABLE."""
    tbl = schema.random_table()
    if not tbl:
        return None

    cmd = pick(['OPTIMIZE', 'ANALYZE', 'CHECK', 'CHECKSUM', 'REPAIR'])
    return f"{cmd} TABLE {tbl.name}"


# ===================================================================
# LOCK / UNLOCK statements
# ===================================================================

def gen_lock_tables(schema):
    """Generate LOCK TABLES + work + UNLOCK TABLES as a sequence."""
    tbl = schema.random_table()
    if not tbl:
        return "SELECT 1"

    lock_type = pick(['READ', 'WRITE'])
    # Return lock + unlock together so we don't leave tables locked
    return f"LOCK TABLES {tbl.name} {lock_type}; SELECT COUNT(*) FROM {tbl.name}; UNLOCK TABLES"


# ===================================================================
# RENAME TABLE
# ===================================================================

def gen_rename_table(schema):
    """Generate RENAME TABLE (rename and rename back)."""
    tbl = schema.random_table()
    if not tbl:
        return None
    new_name = f"{tbl.name}_tmp_{random.randint(0,99)}"
    # Return both rename and rename-back so schema stays consistent
    return f"RENAME TABLE {tbl.name} TO {new_name}"


# ===================================================================
# Transaction statements
# ===================================================================

def gen_transaction(schema):
    """Generate transaction-related statements."""
    action = random.randint(0, 9)

    if action == 0:
        return "BEGIN"
    elif action == 1:
        return "START TRANSACTION"
    elif action == 2:
        return "COMMIT"
    elif action == 3:
        return "ROLLBACK"
    elif action == 4:
        return f"SAVEPOINT sp_{random.randint(0,99)}"
    elif action == 5:
        return f"ROLLBACK TO SAVEPOINT sp_{random.randint(0,99)}"
    elif action == 6:
        return f"RELEASE SAVEPOINT sp_{random.randint(0,99)}"
    elif action == 7:
        return f"SET TRANSACTION ISOLATION LEVEL {pick(ISOLATION_LEVELS)}"
    elif action == 8:
        return f"SET autocommit = {random.choice([0, 1])}"
    else:
        return f"SET innodb_lock_wait_timeout = {pick([1, 5, 10, 50, 100])}"


# ===================================================================
# TRUNCATE / DROP / CREATE (schema DDL)
# ===================================================================

def gen_truncate(schema):
    tbl = schema.random_table()
    if not tbl:
        return None
    return f"TRUNCATE TABLE {tbl.name}"


# ===================================================================
# ===================================================================
# BACKUP STAGE (MariaDB specific)
# ===================================================================

def gen_backup_stage(schema):
    """Generate BACKUP STAGE sequence (must follow correct order)."""
    return ("BACKUP STAGE START; BACKUP STAGE FLUSH; "
            "BACKUP STAGE BLOCK_DDL; BACKUP STAGE BLOCK_COMMIT; BACKUP STAGE END")


# ===================================================================
# Partition operations
# ===================================================================

def gen_partition_op(schema):
    """Generate partition-related operations on partitioned tables."""
    # Find a partitioned table
    part_tables = [t for t in schema.tables.values()
                   if 'part' in t.name or 'phash' in t.name]
    if not part_tables:
        tbl = schema.random_table()
    else:
        tbl = pick(part_tables)
    if not tbl:
        return "SELECT 1"

    ops = [
        f"ALTER TABLE {tbl.name} ANALYZE PARTITION ALL",
        f"ALTER TABLE {tbl.name} CHECK PARTITION ALL",
        f"ALTER TABLE {tbl.name} OPTIMIZE PARTITION ALL",
        f"ALTER TABLE {tbl.name} REBUILD PARTITION ALL",
        f"ALTER TABLE {tbl.name} REPAIR PARTITION ALL",
        f"ALTER TABLE {tbl.name} TRUNCATE PARTITION p0",
        f"ALTER TABLE {tbl.name} COALESCE PARTITION 1",
        f"ALTER TABLE {tbl.name} ADD PARTITION (PARTITION pnew VALUES LESS THAN ({random.randint(2000,9999)}))",
        f"ALTER TABLE {tbl.name} DROP PARTITION IF EXISTS p0",
        f"ALTER TABLE {tbl.name} REORGANIZE PARTITION p0, p1 INTO (PARTITION p0_new VALUES LESS THAN ({random.randint(200,800)}))",
        f"ALTER TABLE {tbl.name} REMOVE PARTITIONING",
        f"ALTER TABLE {tbl.name} PARTITION BY HASH(id) PARTITIONS {random.randint(2,8)}",
        f"ALTER TABLE {tbl.name} PARTITION BY KEY(id) PARTITIONS {random.randint(2,6)}",
    ]
    return pick(ops)


# ===================================================================
# System versioning operations
# ===================================================================

def gen_versioning_op(schema):
    """Generate system versioning operations."""
    tbl = schema.random_table()
    if not tbl:
        return "SELECT 1"

    ops = [
        f"ALTER TABLE {tbl.name} ADD SYSTEM VERSIONING",
        f"ALTER TABLE {tbl.name} DROP SYSTEM VERSIONING",
        f"SELECT * FROM {tbl.name} FOR SYSTEM_TIME AS OF TIMESTAMP '2020-01-01 00:00:00'",
        f"SELECT * FROM {tbl.name} FOR SYSTEM_TIME BETWEEN '2020-01-01' AND '2030-01-01'",
        f"SELECT * FROM {tbl.name} FOR SYSTEM_TIME ALL",
        f"DELETE HISTORY FROM {tbl.name}",
        f"DELETE HISTORY FROM {tbl.name} BEFORE SYSTEM_TIME '2030-01-01 00:00:00'",
    ]
    return pick(ops)


# ===================================================================
# CREATE / DROP / RECREATE tables (schema churn)
# ===================================================================

def gen_create_drop(schema):
    """Generate CREATE TABLE / DROP TABLE to churn schema."""
    action = random.randint(0, 5)
    tname = f"fz_tmp_{random.randint(0, 99)}"

    if action <= 2:
        # Create a random table
        cols = ['id INT AUTO_INCREMENT PRIMARY KEY']
        ncols = random.randint(2, 8)
        for i in range(ncols):
            ctype = pick(ALL_COLUMN_TYPES)
            size = ''
            if ctype in ('VARCHAR', 'CHAR'):
                size = f"({pick([10, 50, 200])})"
            elif ctype == 'DECIMAL':
                size = f"({pick([5,10,20])},{pick([0,2,5])})"
            cols.append(f"c{i} {ctype}{size}")
        row_format = pick(INNODB_ROW_FORMATS)
        extra = ''
        if row_format == 'COMPRESSED':
            extra = f" KEY_BLOCK_SIZE={pick([4,8])}"
        if chance(5):
            extra += " PAGE_COMPRESSED=1"
        if chance(5):
            extra += " WITH SYSTEM VERSIONING"
        return (f"CREATE TABLE IF NOT EXISTS {tname} ({', '.join(cols)}) "
                f"ENGINE=InnoDB ROW_FORMAT={row_format}{extra}")
    elif action == 3:
        # Drop a random table (not our core tables)
        tbl = schema.random_table()
        if tbl and ('fz_tmp' in tbl.name or 'empty' in tbl.name):
            return f"DROP TABLE IF EXISTS {tbl.name}"
        return f"DROP TABLE IF EXISTS {tname}"
    elif action == 4:
        # CREATE TABLE LIKE
        tbl = schema.random_table()
        if tbl:
            return f"CREATE TABLE IF NOT EXISTS {tname} LIKE {tbl.name}"
        return "SELECT 1"
    else:
        # CREATE TABLE AS SELECT
        tbl = schema.random_table()
        if tbl:
            return f"CREATE TABLE IF NOT EXISTS {tname} ENGINE=InnoDB AS SELECT * FROM {tbl.name} LIMIT {pick([10, 100, 1000])}"
        return "SELECT 1"


# ===================================================================
# IMPORT / EXPORT tablespace
# ===================================================================

def gen_import_export(schema):
    """Generate FLUSH FOR EXPORT / DISCARD / IMPORT TABLESPACE."""
    tbl = schema.random_table()
    if not tbl:
        return "SELECT 1"

    ops = [
        f"FLUSH TABLES {tbl.name} FOR EXPORT; UNLOCK TABLES",
        f"ALTER TABLE {tbl.name} DISCARD TABLESPACE",
        f"ALTER TABLE {tbl.name} IMPORT TABLESPACE",
    ]
    return pick(ops)


# ===================================================================
# Complex multi-table operations
# ===================================================================

def gen_multi_table_op(schema):
    """Generate multi-table UPDATE, DELETE, INSERT...SELECT."""
    if not schema.has_tables():
        return "SELECT 1"

    tbl1 = schema.random_table()
    tbl2 = schema.random_table()
    if not tbl1 or not tbl2:
        return "SELECT 1"

    action = random.randint(0, 4)

    if action == 0:
        # Multi-table UPDATE
        col1 = tbl1.random_column()
        col2 = tbl2.random_column()
        if col1 and col2 and not col1.is_auto_inc and tbl1.name != tbl2.name:
            return (f"UPDATE {tbl1.name} a JOIN {tbl2.name} b ON a.id = b.id "
                    f"SET a.{col1.name} = b.{col2.name}")
    elif action == 1:
        # Multi-table DELETE
        if tbl1.name != tbl2.name:
            return (f"DELETE a FROM {tbl1.name} a JOIN {tbl2.name} b "
                    f"ON a.id = b.id WHERE b.id > {random.randint(0, 1000)}")
    elif action == 2:
        # INSERT ... SELECT
        col = tbl1.random_column()
        if col:
            return (f"INSERT IGNORE INTO {tbl1.name} ({col.name}) "
                    f"SELECT {col.name} FROM {tbl2.name} LIMIT {pick([1, 10, 100])}")
    elif action == 3:
        # REPLACE ... SELECT
        col = tbl1.random_column()
        if col:
            return (f"REPLACE INTO {tbl1.name} ({col.name}) "
                    f"SELECT {col.name} FROM {tbl2.name} LIMIT {pick([1, 10])}")
    else:
        # INSERT with subquery in VALUES
        col = tbl1.random_column()
        if col and not col.is_auto_inc:
            return (f"UPDATE {tbl1.name} SET {col.name} = "
                    f"(SELECT {col.name} FROM {tbl2.name} ORDER BY RAND() LIMIT 1) "
                    f"WHERE id = {random.randint(1, 100)}")

    return gen_select(schema)


# ===================================================================
# Exotic DDL — things that stress unusual code paths
# ===================================================================

def gen_exotic_ddl(schema):
    """Generate unusual DDL that hits less-tested code paths."""
    tbl = schema.random_table()
    if not tbl:
        return "SELECT 1"

    ops = [
        # FORCE rebuild
        f"ALTER TABLE {tbl.name} FORCE",
        f"ALTER TABLE {tbl.name} FORCE, ALGORITHM=INPLACE",
        f"ALTER TABLE {tbl.name} FORCE, ALGORITHM=COPY",
        # Engine swap
        f"ALTER TABLE {tbl.name} ENGINE=InnoDB",
        f"ALTER TABLE {tbl.name} ENGINE=InnoDB ROW_FORMAT={pick(INNODB_ROW_FORMATS)}",
        # RENAME
        f"RENAME TABLE {tbl.name} TO {tbl.name}_ren; RENAME TABLE {tbl.name}_ren TO {tbl.name}",
        # CONVERT charset
        f"ALTER TABLE {tbl.name} CONVERT TO CHARACTER SET {pick(CHARSETS)}",
        f"ALTER TABLE {tbl.name} DEFAULT CHARACTER SET {pick(CHARSETS)}",
        # Instant ADD/DROP (10.3+/10.4+)
        f"ALTER TABLE {tbl.name} ADD COLUMN IF NOT EXISTS inst_col INT DEFAULT {random.randint(0,100)}, ALGORITHM=INSTANT",
        f"ALTER TABLE {tbl.name} DROP COLUMN IF EXISTS inst_col",
        # NOCOPY
        f"ALTER TABLE {tbl.name} ADD COLUMN IF NOT EXISTS nc_col INT, ALGORITHM=NOCOPY",
        # ENABLE/DISABLE KEYS
        f"ALTER TABLE {tbl.name} DISABLE KEYS; ALTER TABLE {tbl.name} ENABLE KEYS",
        # CHECKSUM
        f"CHECKSUM TABLE {tbl.name}",
        f"CHECKSUM TABLE {tbl.name} EXTENDED",
        f"CHECKSUM TABLE {tbl.name} QUICK",
        # Table maintenance
        f"REPAIR TABLE {tbl.name}",
        f"REPAIR TABLE {tbl.name} EXTENDED",
        f"CHECK TABLE {tbl.name} FOR UPGRADE",
        f"CHECK TABLE {tbl.name} EXTENDED",
        # Spatial (will fail but exercises parser)
        f"ALTER TABLE {tbl.name} ADD COLUMN IF NOT EXISTS geo_col POINT",
        # Multiple operations in one ALTER
        f"ALTER TABLE {tbl.name} ADD COLUMN IF NOT EXISTS x1 INT, ADD COLUMN IF NOT EXISTS x2 VARCHAR(100), ADD INDEX IF NOT EXISTS idx_x1 (x1)",
        f"ALTER TABLE {tbl.name} DROP COLUMN IF EXISTS x1, DROP COLUMN IF EXISTS x2, DROP INDEX IF EXISTS idx_x1",
        # COMMENT
        f"ALTER TABLE {tbl.name} COMMENT='fuzz_{random.randint(0,9999)}'",
        # AUTO_INCREMENT
        f"ALTER TABLE {tbl.name} AUTO_INCREMENT={pick([1, 100, 2147483647, 0])}",
    ]
    return pick(ops)


# ===================================================================
# InnoDB debug / stress SET commands
# ===================================================================

def gen_innodb_set(schema):
    """Generate SET statements for InnoDB variables — more variety."""
    stmts = [
        f"SET GLOBAL innodb_buffer_pool_size = {pick([5*1024*1024, 8*1024*1024, 16*1024*1024, 64*1024*1024, 256*1024*1024])}",
        f"SET GLOBAL innodb_adaptive_hash_index = {pick(['ON', 'OFF'])}",
        f"SET GLOBAL innodb_stats_persistent = {pick(['ON', 'OFF'])}",
        f"SET SESSION innodb_lock_wait_timeout = {pick([1, 5, 10, 50, 100])}",
        f"SET SESSION lock_wait_timeout = {pick([1, 10, 30, 86400])}",
        "FLUSH TABLES",
        "FLUSH TABLES WITH READ LOCK; UNLOCK TABLES",
        f"SET GLOBAL innodb_file_per_table = {pick([0, 1])}",
        f"SET GLOBAL innodb_stats_auto_recalc = {pick(['ON', 'OFF'])}",
        f"SET GLOBAL innodb_max_purge_lag = {pick([0, 100, 10000])}",
        f"SET GLOBAL innodb_change_buffer_max_size = {pick([0, 10, 25, 50])}",
        f"SET GLOBAL innodb_io_capacity = {pick([100, 200, 1000, 10000])}",
        f"SET SESSION sql_mode = '{pick(['', 'STRICT_TRANS_TABLES', 'TRADITIONAL', 'NO_ENGINE_SUBSTITUTION'])}'",
        f"SET SESSION foreign_key_checks = {pick([0, 1])}",
        f"SET SESSION unique_checks = {pick([0, 1])}",
        f"SET SESSION autocommit = {pick([0, 1])}",
        "FLUSH STATUS",
        "FLUSH BINARY LOGS",
        f"SET GLOBAL innodb_fast_shutdown = {pick([0, 1, 2])}",
        "SHOW ENGINE INNODB STATUS",
        "SHOW ENGINE INNODB MUTEX",
        "SELECT * FROM INFORMATION_SCHEMA.INNODB_BUFFER_POOL_STATS",
        "SELECT * FROM INFORMATION_SCHEMA.INNODB_METRICS LIMIT 10",
        f"ANALYZE TABLE {schema.random_table_name() or 't1'}",
    ]
    return pick(stmts)


# ===================================================================
# Master generator — picks a random statement type
# ===================================================================

STATEMENT_GENERATORS = [
    (gen_select,            25),   # SELECT
    (gen_insert,            20),   # INSERT
    (gen_update,            12),   # UPDATE
    (gen_delete,             8),   # DELETE
    (gen_alter_table,       10),   # ALTER TABLE (standard)
    (gen_exotic_ddl,         8),   # FORCE, CHECKSUM, REPAIR, multi-ALTER
    (gen_partition_op,       5),   # Partition operations
    (gen_versioning_op,      3),   # System versioning
    (gen_create_drop,        4),   # CREATE/DROP table churn
    (gen_multi_table_op,     5),   # Multi-table UPDATE/DELETE/INSERT..SELECT
    (gen_table_maintenance,  3),   # OPTIMIZE / ANALYZE / CHECK
    (gen_transaction,        5),   # BEGIN / COMMIT / ROLLBACK
    (gen_lock_tables,        1),   # LOCK TABLES
    (gen_truncate,           1),   # TRUNCATE
    (gen_innodb_set,         4),   # SET innodb variables, FLUSH, SHOW ENGINE
    (gen_backup_stage,       1),   # BACKUP STAGE
    (gen_rename_table,       1),   # RENAME TABLE
    (gen_import_export,      1),   # IMPORT/EXPORT tablespace
]

_TOTAL_WEIGHT = sum(w for _, w in STATEMENT_GENERATORS)


def generate_statement(schema):
    """Generate a random valid SQL statement based on the current schema."""
    r = random.randint(1, _TOTAL_WEIGHT)
    cumulative = 0
    for gen_func, weight in STATEMENT_GENERATORS:
        cumulative += weight
        if r <= cumulative:
            result = gen_func(schema)
            if result:
                return result
            # If generator returned None, fall through to next
            break

    # Fallback: always-valid SELECT
    tbl = schema.random_table()
    if tbl:
        return f"SELECT * FROM {tbl.name} LIMIT 10"
    return "SELECT 1"
