"""
RQG .zz (gendata) file parser.

Parses RQG data generation files (.zz) to create table schemas.
These files define table names, column types, row counts, and data patterns
that the grammars (.yy) expect to operate on.

Format example (Perl hash):
    $tables = {
        names => ['t1', 't2'],
        rows  => [100, 1000],
        pk    => ['int auto_increment']
    };
    $fields = {
        types   => ['int', 'varchar(64)', 'decimal', 'float', 'blob'],
        indexes => [undef],
        sqls    => ["`id` int NOT NULL auto_increment", ...]
    };
"""

import os
import re
import random
import logging

logger = logging.getLogger(__name__)


def parse_zz_file(path):
    """
    Parse a .zz file and return structured table/field/data definitions.
    Returns dict with keys: tables, fields, data
    """
    with open(path, 'r', errors='replace') as f:
        content = f.read()

    # Strip comments
    lines = []
    for line in content.split('\n'):
        stripped = line.split('#')[0] if '#' in line and "'" not in line.split('#')[0] else line
        lines.append(stripped)
    content = '\n'.join(lines)

    result = {
        'tables': {},
        'fields': {},
        'data': {},
    }

    # Extract $tables = { ... };
    tables_match = re.search(r'\$tables\s*=\s*\{(.*?)\}\s*;', content, re.DOTALL)
    if tables_match:
        result['tables'] = _parse_perl_hash(tables_match.group(1))

    # Extract $fields = { ... };
    fields_match = re.search(r'\$fields\s*=\s*\{(.*?)\}\s*;', content, re.DOTALL)
    if fields_match:
        result['fields'] = _parse_perl_hash(fields_match.group(1))

    # Extract $data = { ... }
    data_match = re.search(r'\$data\s*=\s*\{(.*?)\}', content, re.DOTALL)
    if data_match:
        result['data'] = _parse_perl_hash(data_match.group(1))

    return result


def _parse_perl_hash(text):
    """Parse Perl hash content into a Python dict."""
    result = {}

    # Find key => value pairs
    # key => [ list ]  or  key => 'scalar'  or  key => number
    pattern = r"['\"]?(\w+)['\"]?\s*=>\s*(\[.*?\]|'[^']*'|\"[^\"]*\"|\d+|undef)"

    for match in re.finditer(pattern, text, re.DOTALL):
        key = match.group(1)
        value_str = match.group(2).strip()

        if value_str.startswith('['):
            # Parse array
            result[key] = _parse_perl_array(value_str)
        elif value_str in ('undef', 'NULL'):
            result[key] = None
        elif value_str.startswith(("'", '"')):
            result[key] = value_str.strip("'\"")
        else:
            try:
                result[key] = int(value_str)
            except ValueError:
                result[key] = value_str

    return result


def _parse_perl_array(text):
    """Parse a Perl array [...] into a Python list."""
    # Remove brackets
    inner = text.strip('[]').strip()
    if not inner:
        return []

    items = []
    # Split by comma, respecting quotes
    current = []
    in_quote = False
    quote_char = None

    for c in inner:
        if c in ("'", '"') and not in_quote:
            in_quote = True
            quote_char = c
            current.append(c)
        elif c == quote_char and in_quote:
            in_quote = False
            current.append(c)
        elif c == ',' and not in_quote:
            item = ''.join(current).strip()
            if item:
                items.append(_parse_perl_value(item))
            current = []
        else:
            current.append(c)

    item = ''.join(current).strip()
    if item:
        items.append(_parse_perl_value(item))

    return items


def _parse_perl_value(text):
    """Parse a single Perl value."""
    text = text.strip()
    if text == 'undef':
        return None
    if text.startswith(("'", '"')):
        return text.strip("'\"")
    try:
        return int(text)
    except ValueError:
        return text


def generate_create_tables_from_zz(zz_data, engine='InnoDB'):
    """
    Generate CREATE TABLE SQL statements from parsed .zz data.
    Returns list of (table_name, create_sql, row_count) tuples.
    """
    tables_def = zz_data.get('tables', {})
    fields_def = zz_data.get('fields', {})

    # Get table names
    names = tables_def.get('names', [])
    if not names:
        # Auto-generate names: table100_innodb, table200_innodb, etc.
        count = 5
        names = [f'table{i}' for i in range(1, count + 1)]

    # Get row counts
    rows_list = tables_def.get('rows', [100])
    if not isinstance(rows_list, list):
        rows_list = [rows_list]

    # Get PK types
    pk_types = tables_def.get('pk', ['int auto_increment'])
    if not isinstance(pk_types, list):
        pk_types = [pk_types]

    # Get field definitions
    field_sqls = fields_def.get('sqls', [])
    index_sqls = fields_def.get('index_sqls', [])
    field_types = fields_def.get('types', [])

    results = []

    for i, tbl_name in enumerate(names):
        if tbl_name is None:
            continue

        row_count = rows_list[i % len(rows_list)] if rows_list else 100

        # Build column definitions
        col_defs = []

        # Primary key
        pk = pk_types[i % len(pk_types)] if pk_types else 'int auto_increment'
        if pk and pk != 'undef':
            pk_upper = pk.upper()
            if 'AUTO_INCREMENT' in pk_upper:
                col_defs.append(f"`pk` {pk} PRIMARY KEY")
            else:
                col_defs.append(f"`pk` {pk} PRIMARY KEY")

        if field_sqls:
            # Explicit SQL column definitions (like oltp.zz)
            for sql in field_sqls:
                if sql and not sql.startswith('PRIMARY'):
                    col_defs.append(sql)
        elif field_types:
            # Auto-generate columns from types
            col_num = 0
            for ft in field_types:
                if ft is None:
                    continue
                ft_upper = ft.upper() if ft else ''

                if 'INT' in ft_upper:
                    col_defs.append(f"`col_int_{col_num}` {ft}")
                elif 'VARCHAR' in ft_upper or 'CHAR' in ft_upper:
                    col_defs.append(f"`col_char_{col_num}` {ft}")
                elif 'TEXT' in ft_upper:
                    col_defs.append(f"`col_text_{col_num}` {ft}")
                elif 'BLOB' in ft_upper:
                    col_defs.append(f"`col_blob_{col_num}` {ft}")
                elif 'DECIMAL' in ft_upper:
                    col_defs.append(f"`col_decimal_{col_num}` {ft}")
                elif 'FLOAT' in ft_upper or 'DOUBLE' in ft_upper:
                    col_defs.append(f"`col_float_{col_num}` {ft}")
                elif 'DATE' in ft_upper or 'TIME' in ft_upper:
                    col_defs.append(f"`col_date_{col_num}` {ft}")
                else:
                    col_defs.append(f"`col_{col_num}` {ft}")
                col_num += 1

        # Add indexes
        idx_defs = []
        if index_sqls:
            for idx in index_sqls:
                if idx and 'PRIMARY' not in idx.upper():
                    idx_defs.append(idx)

        # Build CREATE TABLE
        all_defs = col_defs + idx_defs
        if not all_defs:
            # Minimal table
            all_defs = ["`pk` int auto_increment PRIMARY KEY", "`col1` int"]

        create_sql = (f"CREATE TABLE IF NOT EXISTS `{tbl_name}` "
                      f"({', '.join(all_defs)}) ENGINE={engine}")

        results.append((tbl_name, create_sql, row_count))

    return results


def generate_insert_data(tbl_name, columns_sql, row_count, data_def=None):
    """Generate INSERT statements to populate a table."""
    if row_count <= 0:
        return []

    # Parse column names from the CREATE TABLE columns
    col_names = []
    for col_sql in columns_sql:
        match = re.match(r'`?(\w+)`?', col_sql.strip())
        if match:
            name = match.group(1)
            if 'auto_increment' not in col_sql.lower():
                col_names.append((name, col_sql))

    if not col_names:
        return []

    stmts = []
    batch_size = min(row_count, 50)

    for batch_start in range(0, min(row_count, 500), batch_size):
        rows = []
        for row_num in range(batch_size):
            vals = []
            for col_name, col_sql in col_names:
                vals.append(_gen_data_value(col_sql, row_num + batch_start))
            rows.append(f"({', '.join(vals)})")

        names = ', '.join(f'`{n}`' for n, _ in col_names)
        stmts.append(
            f"INSERT IGNORE INTO `{tbl_name}` ({names}) VALUES {', '.join(rows)}"
        )

    return stmts


def _gen_data_value(col_sql, seed):
    """Generate a value based on column definition."""
    upper = col_sql.upper()

    if 'AUTO_INCREMENT' in upper:
        return 'NULL'
    elif 'INT' in upper:
        return str(seed * 7 + random.randint(-100, 100))
    elif 'DECIMAL' in upper or 'FLOAT' in upper or 'DOUBLE' in upper:
        return str(round(seed * 1.5 + random.uniform(-50, 50), 2))
    elif 'CHAR' in upper or 'VARCHAR' in upper:
        length = 12
        m = re.search(r'\((\d+)\)', col_sql)
        if m:
            length = min(int(m.group(1)), 50)
        s = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=length))
        return f"'{s}'"
    elif 'TEXT' in upper:
        s = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz ', k=random.randint(10, 100)))
        return f"'{s}'"
    elif 'BLOB' in upper:
        return f"UNHEX('{random.randint(0, 0xFFFFFFFF):08X}')"
    elif 'DATE' in upper:
        return f"'{2000+random.randint(0,25)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}'"
    elif 'TIME' in upper:
        return f"'{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}'"
    else:
        return str(random.randint(0, 1000))


def load_zz_and_generate_setup(zz_paths, engine='InnoDB'):
    """
    Load .zz files and generate all CREATE TABLE + INSERT statements.
    Returns (setup_sqls, table_info) where table_info is list of (name, col_count, row_count).
    """
    all_stmts = []
    table_info = []

    for path in zz_paths:
        if not os.path.exists(path):
            continue

        zz_data = parse_zz_file(path)
        tables = generate_create_tables_from_zz(zz_data, engine)

        for tbl_name, create_sql, row_count in tables:
            all_stmts.append(create_sql)

            # Parse columns for INSERT generation
            fields_def = zz_data.get('fields', {})
            field_sqls = fields_def.get('sqls', [])
            if not field_sqls:
                # Build from types
                field_types = fields_def.get('types', [])
                field_sqls = []
                for j, ft in enumerate(field_types):
                    if ft:
                        field_sqls.append(f"col_{j} {ft}")

            inserts = generate_insert_data(tbl_name, field_sqls, row_count, zz_data.get('data'))
            all_stmts.extend(inserts)

            table_info.append((tbl_name, len(field_sqls), row_count))

        logger.info(f"Loaded .zz: {path} ({len(tables)} tables)")

    return all_stmts, table_info
