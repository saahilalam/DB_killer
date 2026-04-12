"""
Schema tracker for the MariaDB AST Fuzzer.

Maintains a live picture of which tables/columns/indexes exist so the
fuzzer only generates SQL that references real objects.

Two modes:
  - Offline: populated from seed CREATE TABLE statements
  - Live: queries INFORMATION_SCHEMA on a running server
"""

import random
import logging

from config import (
    pick, chance,
    INTEGER_TYPES, FLOAT_TYPES, STRING_TYPES, BINARY_TYPES, DATE_TYPES,
    ALL_COLUMN_TYPES, INNODB_ROW_FORMATS, STORAGE_ENGINES, CHARSETS,
)

logger = logging.getLogger(__name__)


class Column:
    __slots__ = ('name', 'data_type', 'nullable', 'has_default', 'is_auto_inc',
                 'is_virtual', 'is_persistent')

    def __init__(self, name, data_type='INT', nullable=True, has_default=False,
                 is_auto_inc=False, is_virtual=False, is_persistent=False):
        self.name = name
        self.data_type = data_type.upper()
        self.nullable = nullable
        self.has_default = has_default
        self.is_auto_inc = is_auto_inc
        self.is_virtual = is_virtual
        self.is_persistent = is_persistent

    @property
    def is_numeric(self):
        return any(t in self.data_type for t in
                   ['INT', 'DECIMAL', 'FLOAT', 'DOUBLE', 'BIT', 'BOOL'])

    @property
    def is_string(self):
        return any(t in self.data_type for t in
                   ['CHAR', 'VARCHAR', 'TEXT', 'BLOB', 'BINARY', 'ENUM', 'SET', 'JSON'])

    @property
    def is_date(self):
        return any(t in self.data_type for t in
                   ['DATE', 'TIME', 'TIMESTAMP', 'YEAR'])

    @property
    def is_insertable(self):
        """Can this column appear in an INSERT values list?"""
        return not self.is_virtual and not self.is_persistent


class Index:
    __slots__ = ('name', 'columns', 'unique', 'fulltext', 'is_primary')

    def __init__(self, name, columns, unique=False, fulltext=False, is_primary=False):
        self.name = name
        self.columns = columns  # list of column names
        self.unique = unique
        self.fulltext = fulltext
        self.is_primary = is_primary


class Table:
    __slots__ = ('name', 'columns', 'indexes', 'engine', 'row_format',
                 'has_auto_inc', 'is_partitioned')

    def __init__(self, name, engine='InnoDB', row_format='DYNAMIC'):
        self.name = name
        self.columns = []       # list of Column
        self.indexes = []       # list of Index
        self.engine = engine
        self.row_format = row_format
        self.has_auto_inc = False
        self.is_partitioned = False

    def add_column(self, col):
        self.columns.append(col)
        if col.is_auto_inc:
            self.has_auto_inc = True

    def add_index(self, idx):
        self.indexes.append(idx)

    def drop_column(self, name):
        self.columns = [c for c in self.columns if c.name != name]

    def drop_index(self, name):
        self.indexes = [i for i in self.indexes if i.name != name]

    def get_column(self, name):
        for c in self.columns:
            if c.name == name:
                return c
        return None

    def column_names(self):
        return [c.name for c in self.columns]

    def insertable_columns(self):
        return [c for c in self.columns if c.is_insertable]

    def numeric_columns(self):
        return [c for c in self.columns if c.is_numeric]

    def string_columns(self):
        return [c for c in self.columns if c.is_string]

    def random_column(self):
        if not self.columns:
            return None
        return random.choice(self.columns)

    def random_columns(self, n=None):
        if not self.columns:
            return []
        if n is None:
            n = random.randint(1, len(self.columns))
        n = min(n, len(self.columns))
        return random.sample(self.columns, n)

    def has_index(self, name):
        return any(i.name == name for i in self.indexes)


class SchemaTracker:
    """Tracks the current database schema state."""

    def __init__(self):
        self.tables = {}    # name -> Table
        self.database = 'test'

    def add_table(self, table):
        self.tables[table.name] = table

    def drop_table(self, name):
        self.tables.pop(name, None)

    def get_table(self, name):
        return self.tables.get(name)

    def table_names(self):
        return list(self.tables.keys())

    def random_table(self):
        if not self.tables:
            return None
        return random.choice(list(self.tables.values()))

    def random_table_name(self):
        if not self.tables:
            return None
        return random.choice(list(self.tables.keys()))

    def has_tables(self):
        return len(self.tables) > 0

    def populate_from_server(self, conn):
        """Query INFORMATION_SCHEMA to get the current schema state."""
        self.tables.clear()
        try:
            cursor = conn.cursor()

            # Get tables
            cursor.execute(
                "SELECT TABLE_NAME, ENGINE, ROW_FORMAT "
                "FROM INFORMATION_SCHEMA.TABLES "
                "WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'BASE TABLE'",
                (self.database,)
            )
            for row in cursor.fetchall():
                tbl_name, engine, row_fmt = row
                tbl = Table(tbl_name, engine=engine or 'InnoDB',
                            row_format=row_fmt or 'DYNAMIC')
                self.tables[tbl_name] = tbl

            # Get columns
            cursor.execute(
                "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, "
                "COLUMN_DEFAULT, EXTRA, GENERATION_EXPRESSION "
                "FROM INFORMATION_SCHEMA.COLUMNS "
                "WHERE TABLE_SCHEMA = %s ORDER BY TABLE_NAME, ORDINAL_POSITION",
                (self.database,)
            )
            for row in cursor.fetchall():
                tbl_name, col_name, col_type, nullable, default, extra, gen_expr = row
                tbl = self.tables.get(tbl_name)
                if not tbl:
                    continue
                col = Column(
                    name=col_name,
                    data_type=col_type,
                    nullable=(nullable == 'YES'),
                    has_default=(default is not None),
                    is_auto_inc=('auto_increment' in (extra or '')),
                    is_virtual=('VIRTUAL' in (gen_expr or '').upper() if gen_expr else False),
                    is_persistent=('STORED' in (extra or '').upper() or
                                   'PERSISTENT' in (extra or '').upper()),
                )
                tbl.add_column(col)

            # Get indexes
            cursor.execute(
                "SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, INDEX_TYPE, "
                "GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) "
                "FROM INFORMATION_SCHEMA.STATISTICS "
                "WHERE TABLE_SCHEMA = %s "
                "GROUP BY TABLE_NAME, INDEX_NAME, NON_UNIQUE, INDEX_TYPE",
                (self.database,)
            )
            for row in cursor.fetchall():
                tbl_name, idx_name, non_unique, idx_type, cols_str = row
                tbl = self.tables.get(tbl_name)
                if not tbl:
                    continue
                idx = Index(
                    name=idx_name,
                    columns=(cols_str or '').split(','),
                    unique=(non_unique == 0),
                    fulltext=(idx_type == 'FULLTEXT'),
                    is_primary=(idx_name == 'PRIMARY'),
                )
                tbl.add_index(idx)

            cursor.close()
            logger.info(f"Schema loaded: {len(self.tables)} tables")
            for tbl in self.tables.values():
                logger.debug(f"  {tbl.name}: {len(tbl.columns)} cols, "
                             f"{len(tbl.indexes)} indexes, engine={tbl.engine}")

        except Exception as e:
            logger.error(f"Failed to load schema: {e}")

    def track_ddl(self, sql):
        """
        Parse a DDL statement and update the schema tracker.
        Called after a DDL executes successfully.
        """
        sql_upper = sql.strip().upper()

        if sql_upper.startswith('DROP TABLE'):
            # DROP TABLE [IF EXISTS] name [, name2, ...]
            parts = sql.strip().split()
            for part in parts:
                clean = part.strip('`,;').lower()
                if clean in self.tables:
                    self.drop_table(clean)

        elif sql_upper.startswith('TRUNCATE'):
            pass  # Table still exists, just empty

        elif sql_upper.startswith('RENAME TABLE'):
            # RENAME TABLE old TO new
            parts = sql.strip().split()
            # Simple case: RENAME TABLE a TO b
            try:
                idx_to = next(i for i, p in enumerate(parts) if p.upper() == 'TO')
                old_name = parts[idx_to - 1].strip('`,;').lower()
                new_name = parts[idx_to + 1].strip('`,;').lower()
                tbl = self.tables.pop(old_name, None)
                if tbl:
                    tbl.name = new_name
                    self.tables[new_name] = tbl
            except (StopIteration, IndexError):
                pass

        # For ALTER TABLE we rely on periodic populate_from_server() refreshes
        # rather than trying to parse every ALTER variant


# ===================================================================
# Setup phase: creates the initial schema
# ===================================================================

SETUP_TABLES = [
    # t1: Dynamic — all data types, composite indexes
    {
        'name': 't1',
        'row_format': 'DYNAMIC',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'),
            ('col_int', 'INT'), ('col_int2', 'INT'), ('col_bigint', 'BIGINT'),
            ('col_decimal', 'DECIMAL(10,2)'), ('col_float', 'FLOAT'), ('col_double', 'DOUBLE'),
            ('col_char', 'CHAR(20)'), ('col_varchar', 'VARCHAR(500)'), ('col_text', 'TEXT'),
            ('col_blob', 'BLOB'), ('col_date', 'DATE'), ('col_datetime', 'DATETIME'),
            ('col_timestamp', 'TIMESTAMP NULL DEFAULT NULL'),
            ('col_enum', "ENUM('a','b','c','d','e')"),
            ('col_set', "SET('x','y','z')"), ('col_json', 'JSON'),
        ],
        'indexes': [
            'INDEX idx_col_int (col_int)', 'INDEX idx_col_varchar (col_varchar(50))',
            'INDEX idx_composite (col_int, col_int2)',
        ],
    },
    # t2: Compact
    {
        'name': 't2',
        'row_format': 'COMPACT',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'),
            ('col_int', 'INT NOT NULL DEFAULT 0'), ('col_int2', 'INT'),
            ('col_varchar', 'VARCHAR(255) NOT NULL'), ('col_text', 'TEXT'),
            ('col_date', 'DATE'), ('col_double', 'DOUBLE'),
        ],
        'indexes': [
            'INDEX idx_col_int (col_int)', 'FULLTEXT INDEX ft_text (col_text)',
        ],
    },
    # t3: Redundant + UNIQUE
    {
        'name': 't3',
        'row_format': 'REDUNDANT',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'),
            ('col_int', 'INT'), ('col_int2', 'INT'),
            ('col_char', 'CHAR(50)'), ('col_varchar', 'VARCHAR(200)'),
            ('col_binary', 'VARBINARY(500)'),
        ],
        'indexes': ['UNIQUE INDEX uidx_col_int (col_int)'],
    },
    # t4: PAGE_COMPRESSED
    {
        'name': 't4',
        'row_format': 'DYNAMIC',
        'extra': 'PAGE_COMPRESSED=1',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'),
            ('col_int', 'INT'), ('col_int2', 'INT'),
            ('col_varchar', 'VARCHAR(500)'), ('col_text', 'TEXT'),
            ('col_longtext', 'LONGTEXT'), ('col_blob', 'BLOB'),
        ],
        'indexes': ['INDEX idx_col_int (col_int)'],
    },
    # t5: Foreign key child of t1
    {
        'name': 't5_fk',
        'row_format': 'DYNAMIC',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'),
            ('parent_id', 'INT'), ('col_int', 'INT'), ('col_varchar', 'VARCHAR(200)'),
        ],
        'indexes': ['INDEX idx_parent_id (parent_id)'],
        'fk': 'FOREIGN KEY (parent_id) REFERENCES t1(id) ON DELETE CASCADE ON UPDATE CASCADE',
    },
    # t6: Wide table (40+ columns)
    {
        'name': 't6_wide',
        'row_format': 'DYNAMIC',
        'columns': [('id', 'INT AUTO_INCREMENT PRIMARY KEY')]
            + [(f'c{i}', 'INT') for i in range(1, 31)]
            + [(f'v{i}', 'VARCHAR(100)') for i in range(1, 11)],
        'indexes': ['INDEX idx_c1 (c1)', 'INDEX idx_c1_c2_c3 (c1, c2, c3)'],
    },
    # t7: Partitioned by RANGE
    {
        'name': 't7_part',
        'row_format': 'DYNAMIC',
        'columns': [
            ('id', 'INT AUTO_INCREMENT'), ('col_int', 'INT'), ('col_int2', 'INT'),
            ('col_varchar', 'VARCHAR(200)'), ('col_date', 'DATE'),
            ('PRIMARY KEY', '(id, col_int)'),
        ],
        'indexes': ['INDEX idx_col_date (col_date)'],
        'extra': ("PARTITION BY RANGE (col_int) ("
                  "PARTITION p0 VALUES LESS THAN (100), "
                  "PARTITION p1 VALUES LESS THAN (500), "
                  "PARTITION p2 VALUES LESS THAN (1000), "
                  "PARTITION p3 VALUES LESS THAN MAXVALUE)"),
    },
    # t8: Partitioned by HASH
    {
        'name': 't8_phash',
        'row_format': 'DYNAMIC',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'), ('col_int', 'INT'),
            ('col_varchar', 'VARCHAR(200)'), ('col_text', 'TEXT'),
        ],
        'indexes': ['INDEX idx_col_int (col_int)'],
        'extra': 'PARTITION BY HASH(id) PARTITIONS 4',
    },
    # t9: System versioned table
    {
        'name': 't9_vers',
        'row_format': 'DYNAMIC',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'),
            ('col_int', 'INT'), ('col_int2', 'INT'),
            ('col_varchar', 'VARCHAR(200)'), ('col_text', 'TEXT'),
        ],
        'indexes': ['INDEX idx_col_int (col_int)'],
        'extra': 'WITH SYSTEM VERSIONING',
    },
    # t10: Sequence-like table (heavily updated single rows)
    {
        'name': 't10_seq',
        'row_format': 'DYNAMIC',
        'columns': [
            ('id', 'INT PRIMARY KEY'),
            ('val', 'BIGINT NOT NULL DEFAULT 0'),
            ('updated_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'),
        ],
        'indexes': [],
    },
    # t11: Generated columns — multiple expressions
    {
        'name': 't11_gcol',
        'row_format': 'DYNAMIC',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'),
            ('a', 'INT'), ('b', 'INT'), ('c', 'VARCHAR(100)'),
            ('d', 'DATETIME DEFAULT CURRENT_TIMESTAMP'),
            ('ab_sum', 'INT AS (a + b) VIRTUAL'),
            ('ab_mul', 'INT AS (a * b) PERSISTENT'),
            ('c_upper', 'VARCHAR(100) AS (UPPER(c)) VIRTUAL'),
            ('c_len', 'INT AS (LENGTH(c)) PERSISTENT'),
        ],
        'indexes': ['INDEX idx_a (a)', 'INDEX idx_ab_sum (ab_sum)'],
    },
    # t12: Multiple secondary indexes (index stress)
    {
        'name': 't12_idx',
        'row_format': 'DYNAMIC',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'),
            ('a', 'INT'), ('b', 'INT'), ('c', 'INT'), ('d', 'INT'),
            ('e', 'VARCHAR(100)'), ('f', 'VARCHAR(100)'),
        ],
        'indexes': [
            'INDEX idx_a (a)', 'INDEX idx_b (b)', 'INDEX idx_c (c)',
            'INDEX idx_ab (a, b)', 'INDEX idx_bc (b, c)', 'INDEX idx_cd (c, d)',
            'INDEX idx_abc (a, b, c)', 'UNIQUE INDEX uidx_d (d)',
            'INDEX idx_e (e(50))', 'INDEX idx_ef (e(30), f(30))',
        ],
    },
    # t13: Empty table (DDL target — CREATE/DROP/ALTER cycle)
    {
        'name': 't13_empty',
        'row_format': 'DYNAMIC',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'),
            ('col_int', 'INT'), ('col_varchar', 'VARCHAR(200)'),
        ],
        'indexes': [],
    },
    # t14: Table for IMPORT/EXPORT tablespace testing
    {
        'name': 't14_import',
        'row_format': 'DYNAMIC',
        'columns': [
            ('id', 'INT AUTO_INCREMENT PRIMARY KEY'),
            ('col_int', 'INT'), ('col_varchar', 'VARCHAR(500)'),
            ('col_blob', 'BLOB'),
        ],
        'indexes': ['INDEX idx_col_int (col_int)'],
    },
]


def generate_setup_sql():
    """Generate the CREATE TABLE statements for the setup phase."""
    stmts = []
    stmts.append("SET GLOBAL innodb_file_per_table = 1")

    for tdef in SETUP_TABLES:
        cols = ', '.join(f'{name} {typedef}' for name, typedef in tdef['columns'])
        idxs = ', '.join(tdef.get('indexes', []))
        fk = tdef.get('fk', '')

        parts = [cols]
        if idxs:
            parts.append(idxs)
        if fk:
            parts.append(fk)

        body = ', '.join(parts)
        engine_clause = f"ENGINE=InnoDB ROW_FORMAT={tdef['row_format']}"
        extra = tdef.get('extra', '')
        if extra:
            engine_clause += f' {extra}'

        stmt = f"CREATE TABLE IF NOT EXISTS {tdef['name']} ({body}) {engine_clause}"
        stmts.append(stmt)

    # Seed data into each table
    for tdef in SETUP_TABLES:
        tname = tdef['name']
        insertable = [(n, t) for n, t in tdef['columns']
                      if 'AUTO_INCREMENT' not in t.upper()
                      and 'VIRTUAL' not in t.upper()
                      and 'PERSISTENT' not in t.upper()
                      and ' AS ' not in t.upper()]

        if not insertable:
            continue

        col_names = [n for n, _ in insertable]
        for row_num in range(10):
            vals = []
            for col_name, col_type in insertable:
                vals.append(_gen_value_for_type(col_type, row_num))
            stmts.append(
                f"INSERT IGNORE INTO {tname} ({', '.join(col_names)}) "
                f"VALUES ({', '.join(vals)})"
            )

    return stmts


def build_schema_from_setup():
    """Build a SchemaTracker from the SETUP_TABLES definition."""
    tracker = SchemaTracker()

    for tdef in SETUP_TABLES:
        tbl = Table(tdef['name'], engine='InnoDB', row_format=tdef['row_format'])

        for col_name, col_typedef in tdef['columns']:
            upper = col_typedef.upper()
            # Parse basic type from typedef
            base_type = col_typedef.split('(')[0].split(' ')[0].upper()
            if base_type in ('INT', 'INTEGER'):
                base_type = 'INT'

            col = Column(
                name=col_name,
                data_type=base_type,
                nullable='NOT NULL' not in upper,
                has_default='DEFAULT' in upper,
                is_auto_inc='AUTO_INCREMENT' in upper,
                is_virtual='VIRTUAL' in upper,
                is_persistent='PERSISTENT' in upper or 'STORED' in upper,
            )
            tbl.add_column(col)

        for idx_def in tdef.get('indexes', []):
            upper = idx_def.upper()
            # Parse index name and columns
            # e.g. "INDEX idx_col_int (col_int)"
            #      "UNIQUE INDEX uidx_col_int (col_int)"
            #      "FULLTEXT INDEX ft_text (col_text)"
            parts = idx_def.split('(')
            if len(parts) >= 2:
                name_part = parts[0].strip().split()
                idx_name = name_part[-1] if name_part else f'idx_{random.randint(0,999)}'
                cols_str = parts[1].rstrip(')')
                cols = [c.strip().split('(')[0] for c in cols_str.split(',')]
                idx = Index(
                    name=idx_name,
                    columns=cols,
                    unique='UNIQUE' in upper,
                    fulltext='FULLTEXT' in upper,
                    is_primary='PRIMARY' in upper,
                )
                tbl.add_index(idx)

        # PRIMARY KEY from column definition
        for col_name, col_typedef in tdef['columns']:
            if 'PRIMARY KEY' in col_typedef.upper():
                if not any(i.is_primary for i in tbl.indexes):
                    tbl.add_index(Index('PRIMARY', [col_name], unique=True, is_primary=True))

        tracker.add_table(tbl)

    return tracker


def _gen_value_for_type(col_type, seed=0):
    """Generate a plausible literal value for a column type."""
    upper = col_type.upper()
    if any(t in upper for t in ['INT', 'BIGINT', 'SMALLINT', 'TINYINT', 'MEDIUMINT']):
        return str(seed * 10 + random.randint(-100, 100))
    elif 'DECIMAL' in upper or 'FLOAT' in upper or 'DOUBLE' in upper:
        return str(round(seed * 1.5 + random.uniform(-100, 100), 2))
    elif 'BIT' in upper:
        return f"b'{random.randint(0, 255):08b}'"
    elif 'ENUM' in upper:
        # Extract values from ENUM('a','b','c')
        try:
            vals = upper.split('(')[1].rstrip(')').replace("'", "").split(',')
            return f"'{random.choice(vals).strip()}'"
        except Exception:
            return "'a'"
    elif 'SET' in upper:
        try:
            vals = upper.split('(')[1].rstrip(')').replace("'", "").split(',')
            n = random.randint(1, len(vals))
            chosen = random.sample(vals, n)
            return f"'{','.join(v.strip() for v in chosen)}'"
        except Exception:
            return "'x'"
    elif 'JSON' in upper:
        jsons = ['\'{}\'', '\'{"k":"v"}\'', '\'[1,2,3]\'', '\'null\'',
                 '\'{"a":1,"b":"test"}\'']
        return random.choice(jsons)
    elif 'DATE' in upper and 'TIME' not in upper:
        y = 2000 + seed
        return f"'{ y }-{random.randint(1,12):02d}-{random.randint(1,28):02d}'"
    elif 'DATETIME' in upper or 'TIMESTAMP' in upper:
        y = 2000 + seed
        return (f"'{y}-{random.randint(1,12):02d}-{random.randint(1,28):02d} "
                f"{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}'")
    elif 'TIME' in upper:
        return f"'{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}'"
    elif 'YEAR' in upper:
        return str(2000 + seed)
    elif 'BLOB' in upper or 'BINARY' in upper:
        return f"UNHEX('{random.randint(0, 0xFFFFFFFF):08X}')"
    elif 'TEXT' in upper or 'CHAR' in upper or 'VARCHAR' in upper:
        length = min(random.randint(1, 50), 200)
        chars = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789 ', k=length))
        return f"'{chars}'"
    elif 'BOOL' in upper:
        return str(random.randint(0, 1))
    else:
        return 'NULL'
