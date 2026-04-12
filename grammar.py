"""
RQG Grammar (.yy) parser and SQL expander.

Parses RQG grammar files, expands rules into concrete SQL statements,
and feeds them into the AST fuzzer as live seeds.

Grammar format:
    rule_name:
        alternative1 |
        alternative2 |
        alternative3 ;

Special variables expanded:
    _table       → random table name from schema
    _field       → random column name
    _field_int   → random integer column
    _field_char  → random char/varchar column
    _field_pk    → primary key column (usually 'id')
    _field_int_indexed → random indexed integer column
    _digit       → 0-9
    _tinyint_unsigned  → 0-255
    _smallint_unsigned → 0-65535
    _int / _int_unsigned → random int
    _bigint      → random bigint
    _string      → random quoted string
    _varchar(N)  → random string up to N chars
    _thread_id   → always 1 (single threaded)
    { perl_code } → stripped out (we don't eval perl)
"""

import os
import re
import random
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

MAX_EXPANSION_DEPTH = 30
MAX_EXPANSIONS_PER_CALL = 50

# Fallback expansions for Perl-only rules that we can't execute.
# These rules are defined entirely as { perl_code } in grammars like
# range_access.yy and optimizer_basic.yy, so they never get added to
# self.rules.  Instead of returning the rule name as a literal string,
# we return a sensible SQL fragment.
#
# Values are CALLABLES: each returns a fresh random expansion so that
# the fuzzer produces diverse SQL, matching the behaviour of the Perl
# $prng calls in the original RQG grammars.  The returned strings may
# contain RQG special variables (_table, _field_int, …) which are
# expanded later by _expand_tokens → _expand_special_vars.

def _rand_alias():
    """Random alias like alias1..alias4 (Perl uses ++$tables counter)."""
    return f'alias{random.randint(1, 4)}'

def _rand_field_ref():
    """Random alias.column reference."""
    return f'{_rand_alias()}._field'

def _rand_int_field_ref():
    return f'{_rand_alias()}._field_int'

def _rand_char_field_ref():
    return f'{_rand_alias()}._field_char'

def _rand_table_alias():
    """Random table AS alias (Perl picks from executor tables + increments alias)."""
    return f'_table AS {_rand_alias()}'


_PERL_RULE_FALLBACKS = {
    # --- Table / alias references (Perl tracks alias counters) ---
    'existing_table_item':   _rand_alias,
    'current_table_item':    _rand_alias,
    'previous_table_item':   _rand_alias,
    'table_one_two':         _rand_alias,
    'smart_table':           lambda: '_table',
    # 'table' in range_access.yy is Perl-only (picks a table + alias)
    'table':                 _rand_table_alias,
    'idx_table_for_join':    _rand_table_alias,

    # --- SELECT-item references (Perl tracks field counters) ---
    'existing_select_item':           _rand_field_ref,
    'existing_int_select_item':       _rand_int_field_ref,
    'existing_char_select_item':      _rand_char_field_ref,
    'range_access_existing_select_item': _rand_field_ref,

    # --- Subquery table/field references ---
    'existing_subquery_table_item':       _rand_alias,
    'existing_child_subquery_table_item': _rand_alias,
    'subquery_current_table_item':        _rand_alias,
    'subquery_previous_table_item':       _rand_alias,
    'child_subquery_current_table_item':  _rand_alias,
    'child_subquery_previous_table_item': _rand_alias,
    'existing_subquery_int_select_item':  _rand_int_field_ref,
    'existing_subquery_char_select_item': _rand_char_field_ref,
    'existing_child_subquery_int_select_item':  _rand_int_field_ref,
    'existing_child_subquery_char_select_item': _rand_char_field_ref,

    # --- Subquery references (Perl tracks subquery_idx counters) ---
    'subquery_table_one_two':               _rand_alias,
    'child_subquery_table_one_two':         _rand_alias,

    # --- ORDER BY / GROUP BY (Perl builds these from tracked fields) ---
    'total_order_by':              _rand_field_ref,
    'range_access_total_order_by': _rand_field_ref,
    'partial_order_by':            _rand_field_ref,
    'group_by_clause':             lambda: '',   # Perl decides; safe to omit
    'order_by_anon':               lambda: '',   # all alternatives commented out
    # aggregate_order_by_fields: Perl generates "ORDER BY 1,3,2" (column positions)
    'aggregate_order_by_fields':   lambda: f'ORDER BY {random.randint(1, 4)}',

    # --- JOIN conditions (Perl reads the stack for left/right tables) ---
    'int_condition':  lambda: f'{_rand_alias()}._field_int = {_rand_alias()}._field_int',
    'char_condition': lambda: f'{_rand_alias()}._field_char = {_rand_alias()}._field_char',

    # --- Indexed field references (Perl tracks $last_idx_field) ---
    'int_idx_field':  _rand_int_field_ref,
    'char_idx_field': _rand_char_field_ref,
    'int_indexed':    lambda: '_field_int',
    'char_indexed':   lambda: '_field_char',

    # --- Index creation helpers ---
    'unique_field_for_index': lambda: '_field',

    # --- Misc Perl-only rules ---
    'digit':          lambda: str(random.randint(0, 9)),
    'increment':      lambda: str(random.randint(1, 5)),
    'greater_than':   lambda: random.choice(['>', '>=']),
    'less_than':      lambda: random.choice(['<', '<=']),

    # --- concurrency.yy / concurrency_innodb.yy ---
    # 'field' is Perl-only in concurrency grammars (picks from pk, col_int, etc.)
    'field':          lambda: random.choice(['`pk`', 'col_int', 'col_varchar',
                                              'col_float', 'col_blob', 'col_decimal']),
    'ifield_dir':     lambda: random.choice(['col_int ASC', 'col_int DESC',
                                              'col_float ASC', 'col_float DESC']),
}


class Grammar:
    """Parsed RQG grammar with rule expansion."""

    def __init__(self):
        self.rules = defaultdict(list)  # rule_name -> [alternative, ...]
        self._depth = 0

    def load_file(self, path):
        """Parse a .yy grammar file."""
        with open(path, 'r', errors='replace') as f:
            content = f.read()

        self._parse(content)
        logger.info(f"Grammar loaded: {path} ({len(self.rules)} rules)")

    def load_files(self, paths):
        """Load multiple grammar files (later files can redefine rules)."""
        for path in paths:
            if os.path.exists(path):
                self.load_file(path)

    def _parse(self, content):
        """Parse grammar content into rules."""
        # Strip comments
        lines = []
        for line in content.split('\n'):
            # Remove # comments (but not inside quotes)
            stripped = self._strip_comment(line)
            lines.append(stripped)
        content = '\n'.join(lines)

        # Split into rule blocks: "rule_name:\n  body ;"
        # Pattern: word followed by colon at start-ish of line, then body until ;
        current_rule = None
        current_body = []

        for line in content.split('\n'):
            line_stripped = line.strip()

            # Check for rule definition: "rule_name:"
            match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*$', line_stripped)
            if match:
                # Save previous rule
                if current_rule and current_body:
                    self._add_rule(current_rule, '\n'.join(current_body))
                current_rule = match.group(1)
                current_body = []
                continue

            # Also handle "rule_name: body" on same line
            match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+)$', line_stripped)
            if match and not line_stripped.startswith(('SELECT', 'INSERT', 'UPDATE',
                    'DELETE', 'ALTER', 'CREATE', 'DROP', 'SET', 'COMMIT', 'ROLLBACK',
                    'BEGIN', 'REPLACE', 'TRUNCATE', 'RENAME', 'LOCK', 'UNLOCK',
                    'BACKUP', 'FLUSH', 'OPTIMIZE', 'ANALYZE', 'CHECK', 'REPAIR',
                    'KILL', 'GRANT', 'REVOKE', 'LOAD', 'CALL', 'PREPARE', 'EXECUTE')):
                if current_rule and current_body:
                    self._add_rule(current_rule, '\n'.join(current_body))
                current_rule = match.group(1)
                current_body = [match.group(2)]
                continue

            if current_rule:
                current_body.append(line)

        # Save last rule
        if current_rule and current_body:
            self._add_rule(current_rule, '\n'.join(current_body))

    def _strip_comment(self, line):
        """Strip # comments, but not inside quotes."""
        in_single = False
        in_double = False
        in_perl = 0  # { } nesting depth
        for i, c in enumerate(line):
            if c == "'" and not in_double:
                in_single = not in_single
            elif c == '"' and not in_single:
                in_double = not in_double
            elif c == '{' and not in_single and not in_double:
                in_perl += 1
            elif c == '}' and not in_single and not in_double:
                in_perl = max(0, in_perl - 1)
            elif c == '#' and not in_single and not in_double and in_perl == 0:
                return line[:i]
        return line

    def _add_rule(self, name, body):
        """Parse a rule body into alternatives and store."""
        # Remove trailing semicolons and split by |
        body = body.strip().rstrip(';').strip()
        if not body:
            return

        # Split by | but not inside quotes, parens, or braces
        alternatives = self._split_alternatives(body)

        for alt in alternatives:
            alt = alt.strip()
            if alt:
                # Skip perl-only alternatives
                if alt.startswith('{') and alt.endswith('}'):
                    continue
                self.rules[name].append(alt)

    def _split_alternatives(self, body):
        """Split by | respecting quotes and braces (but NOT parens).

        RQG grammars routinely have unbalanced parens within a single
        rule — the opening '(' lives in one alternative and the closing
        ')' comes from a different rule.  e.g.:
            aggregate:
                COUNT( distinct | SUM( distinct | MIN( distinct ;
        Only braces { } (perl blocks) genuinely nest alternatives.
        """
        parts = []
        current = []
        depth_brace = 0
        in_single = False
        in_double = False

        for c in body:
            if c == "'" and not in_double:
                in_single = not in_single
            elif c == '"' and not in_single:
                in_double = not in_double
            elif not in_single and not in_double:
                if c == '{':
                    depth_brace += 1
                elif c == '}':
                    depth_brace = max(0, depth_brace - 1)
                elif c == '|' and depth_brace == 0:
                    parts.append(''.join(current))
                    current = []
                    continue

            current.append(c)

        parts.append(''.join(current))
        return parts

    def expand(self, rule_name, schema=None):
        """Expand a rule into a concrete SQL string."""
        self._depth = 0
        result = self._expand_rule(rule_name, schema)
        # Clean up: collapse whitespace, strip perl blocks, remove trailing ;
        result = self._cleanup(result)
        return result

    def _expand_rule(self, rule_name, schema):
        """Recursively expand a rule."""
        self._depth += 1
        if self._depth > MAX_EXPANSION_DEPTH:
            return ''

        alternatives = self.rules.get(rule_name)
        if not alternatives:
            # Not a rule — check Perl-only fallbacks before treating as literal
            fallback_fn = _PERL_RULE_FALLBACKS.get(rule_name)
            if fallback_fn:
                # Call the fallback to get a randomised expansion, then
                # expand any special vars (_table, _field_int, …) it contains
                result = self._expand_tokens(fallback_fn(), schema)
                self._depth -= 1
                return result
            self._depth -= 1
            return rule_name

        alt = random.choice(alternatives)
        result = self._expand_tokens(alt, schema)
        self._depth -= 1
        return result

    @staticmethod
    def _strip_perl_blocks(text):
        """Remove { ... } perl blocks, handling nested braces."""
        result = []
        depth = 0
        for c in text:
            if c == '{':
                depth += 1
            elif c == '}':
                depth = max(0, depth - 1)
            elif depth == 0:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def _fix_update_parens(text):
        """Strip outer parens from UPDATE table list without touching subqueries.

        UPDATE ( t1 AS a INNER JOIN t1 AS b ON (...) ) SET ...
        →  UPDATE t1 AS a INNER JOIN t1 AS b ON (...) SET ...
        """
        m = re.match(r'(UPDATE\s*)\(\s*', text, re.IGNORECASE)
        if not m:
            return text
        start = m.end()  # position right after the opening (
        # Walk forward to find the matching )
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
            i += 1
        if depth == 0:
            # i now points right after the matching )
            return m.group(1) + text[start:i - 1] + text[i:]
        return text  # unbalanced — leave as-is

    def _expand_tokens(self, text, schema):
        """Expand all tokens (rule references and special variables) in text."""
        # Remove perl code blocks { ... } (handles nested braces)
        text = self._strip_perl_blocks(text)

        # Strip RQG annotations like [invariant], [length], etc.
        text = re.sub(r'\[\w+\]', '', text)

        # Ensure commas are space-separated so token splitting works.
        # Grammar bodies often have "rule1,rule2" without spaces.
        text = re.sub(r',', ' , ', text)

        # Expand special RQG variables first
        text = self._expand_special_vars(text, schema)

        # Now expand rule references — words that match rule names
        tokens = text.split()
        result = []
        for token in tokens:
            # Strip punctuation for rule lookup
            clean = token.strip(',;()')
            prefix = token[:len(token) - len(token.lstrip(',;()'))]
            suffix = token[len(clean) + len(prefix):]

            # Handle dot-separated references like table_one_two._field_int
            # where the left side is a rule name and the right is a column ref
            if '.' in clean and self._depth < MAX_EXPANSION_DEPTH:
                parts = clean.split('.', 1)
                left, right = parts[0], parts[1]
                if left in self.rules or left in _PERL_RULE_FALLBACKS:
                    exp_left = self._expand_rule(left, schema)
                    # Right side may also be a special var or rule
                    exp_right = self._expand_special_vars(right, schema)
                    if exp_right in self.rules or exp_right in _PERL_RULE_FALLBACKS:
                        exp_right = self._expand_rule(exp_right, schema)
                    result.append(prefix + exp_left + '.' + exp_right + suffix)
                    continue

            if (clean in self.rules or clean in _PERL_RULE_FALLBACKS) and self._depth < MAX_EXPANSION_DEPTH:
                expanded = self._expand_rule(clean, schema)
                result.append(prefix + expanded + suffix)
            elif clean.startswith('$'):
                # Perl variable — substitute with a plausible value
                result.append(prefix + self._expand_perl_var(clean, schema) + suffix)
            else:
                result.append(token)

        return ' '.join(result)

    def _expand_special_vars(self, text, schema):
        """Replace RQG special variables with concrete values."""
        tbl = schema.random_table() if schema and schema.has_tables() else None
        tbl_name = tbl.name if tbl else 't1'

        # Table / view references
        text = re.sub(r'\b_table\b', tbl_name, text)
        text = re.sub(r'\b_basetable\b', tbl_name, text)
        text = re.sub(r'\b_view\b', tbl_name, text)

        # --- Field references (most specific first) ---
        def _field_repl(match):
            if not tbl:
                return 'col_int'
            col = tbl.random_column()
            return col.name if col else 'col_int'

        def _field_int_repl(match):
            if not tbl:
                return 'col_int'
            int_cols = tbl.numeric_columns()
            if int_cols:
                return random.choice(int_cols).name
            return 'col_int'

        def _field_char_repl(match):
            if not tbl:
                return 'col_varchar'
            str_cols = tbl.string_columns()
            if str_cols:
                return random.choice(str_cols).name
            return 'col_varchar'

        def _field_pk_repl(match):
            return 'id'

        def _field_no_pk_repl(match):
            if not tbl:
                return 'col_int'
            non_pk = [c for c in tbl.columns if c.name != 'id']
            if non_pk:
                return random.choice(non_pk).name
            return 'col_int'

        def _field_key_repl(match):
            """Resolve to an actual index name from the table."""
            if tbl and tbl.indexes:
                idx = random.choice(tbl.indexes)
                return f'`{idx.name}`'
            return '`PRIMARY`'

        def _field_indexed_repl(match):
            """Resolve to a column that is part of an index."""
            if tbl and tbl.indexes:
                idx = random.choice(tbl.indexes)
                if idx.columns:
                    return random.choice(idx.columns)
            return _field_repl(match)

        text = re.sub(r'\b_field_pk\b', _field_pk_repl, text)
        text = re.sub(r'\b_field_no_pk\b', _field_no_pk_repl, text)
        text = re.sub(r'\b_field_int_indexed\b', _field_int_repl, text)
        text = re.sub(r'\b_field_char_indexed\b', _field_char_repl, text)
        text = re.sub(r'\b_field_indexed\b', _field_indexed_repl, text)
        text = re.sub(r'\b_field_key\b', _field_key_repl, text)
        text = re.sub(r'\b_field_int\b', _field_int_repl, text)
        text = re.sub(r'\b_field_char\b', _field_char_repl, text)
        text = re.sub(r'\b_field_list\b', _field_repl, text)
        text = re.sub(r'\b_field\b', _field_repl, text)
        # Aliases used in some grammars (optimizer_basic.yy)
        text = re.sub(r'\b_ifield\b', _field_int_repl, text)
        text = re.sub(r'\b_cfield\b', _field_char_repl, text)

        # --- Numeric literals (most specific first) ---
        text = re.sub(r'\b_positive_digit\b', lambda m: str(random.randint(1, 9)), text)
        text = re.sub(r'\b_digit\b', lambda m: str(random.randint(0, 9)), text)
        text = re.sub(r'\b_tinyint_positive\b', lambda m: str(random.randint(1, 127)), text)
        text = re.sub(r'\b_tinyint_unsigned\b', lambda m: str(random.randint(0, 255)), text)
        text = re.sub(r'\b_tinyint\b', lambda m: str(random.randint(-128, 127)), text)
        text = re.sub(r'\b_smallint_positive\b', lambda m: str(random.randint(1, 32767)), text)
        text = re.sub(r'\b_smallint_unsigned\b', lambda m: str(random.randint(0, 65535)), text)
        text = re.sub(r'\b_smallint\b', lambda m: str(random.randint(-32768, 32767)), text)
        text = re.sub(r'\b_mediumint_unsigned\b', lambda m: str(random.randint(0, 16777215)), text)
        text = re.sub(r'\b_mediumint\b', lambda m: str(random.randint(-8388608, 8388607)), text)
        text = re.sub(r'\b_int_unsigned\b', lambda m: str(random.randint(0, 2147483647)), text)
        # _int_usigned — typo in some RQG grammars, must handle
        text = re.sub(r'\b_int_usigned\b', lambda m: str(random.randint(0, 2147483647)), text)
        text = re.sub(r'\b_int\b', lambda m: str(random.randint(-2147483648, 2147483647)), text)
        text = re.sub(r'\b_bigint_unsigned\b', lambda m: str(random.randint(0, 2**63-1)), text)
        text = re.sub(r'\b_bigint\b', lambda m: str(random.randint(-2**63, 2**63-1)), text)
        text = re.sub(r'\b_bool\b', lambda m: str(random.randint(0, 1)), text)
        text = re.sub(r'\b_bit\b',
                       lambda m: f"b'{random.randint(0, 255):08b}'", text)

        # --- String / char literals ---
        # _char(N) and _string(N) — variable-length quoted string
        text = re.sub(r'\b_char\(\s*(\d+)\s*\)',
                       lambda m: f"'{self._random_string(int(m.group(1)))}'", text)
        text = re.sub(r'\b_string\(\s*(\d+)\s*\)',
                       lambda m: f"'{self._random_string(int(m.group(1)))}'", text)
        # _varchar(N) — fixed trailing \b bug: use lookahead instead
        text = re.sub(r'\b_varchar\(\s*(\d+)\s*\)',
                       lambda m: f"'{self._random_string(int(m.group(1)))}'", text)
        # Bare _char — random single-character string (distinct from _field_char)
        text = re.sub(r'\b_char\b', lambda m: f"'{self._random_string(1)}'", text)
        text = re.sub(r'\b_string\b', lambda m: f"'{self._random_string()}'", text)
        text = re.sub(r'\b_varchar\b', lambda m: f"'{self._random_string()}'", text)
        text = re.sub(r'\b_english\b', lambda m: f"'{self._random_string()}'", text)
        text = re.sub(r'\b_englishnoquote\b', lambda m: self._random_string(), text)
        text = re.sub(r'\b_text\b', lambda m: f"'{self._random_string(100)}'", text)
        text = re.sub(r'\b_letter\b',
                       lambda m: f"'{random.choice('abcdefghijklmnopqrstuvwxyz')}'", text)
        # _quid — quoted unique identifier (backtick-wrapped)
        text = re.sub(r'\b_quid\b',
                       lambda m: f"`{self._random_string(8)}`", text)
        text = re.sub(r'\b_hex\b',
                       lambda m: f"0x{random.randint(0, 0xFFFFFFFF):08X}", text)

        # --- Binary / blob data ---
        text = re.sub(r'\b_data\b',
                       lambda m: f"UNHEX('{random.randint(0, 0xFFFFFFFF):08X}')", text)
        text = re.sub(r'\b_blob\b',
                       lambda m: f"UNHEX('{random.randint(0, 0xFFFFFFFF):08X}')", text)
        text = re.sub(r'\b_binary\b',
                       lambda m: f"UNHEX('{random.randint(0, 0xFFFF):04X}')", text)

        # --- Temporal literals ---
        text = re.sub(r'\b_timestamp\b', lambda m: self._random_datetime(), text)
        text = re.sub(r'\b_datetime\b', lambda m: self._random_datetime(), text)
        text = re.sub(r'\b_date\b', lambda m: self._random_date(), text)
        text = re.sub(r'\b_time\b', lambda m: self._random_time(), text)
        text = re.sub(r'\b_year\b',
                       lambda m: f"'{random.randint(1970, 2038)}'", text)

        # --- JSON literals ---
        text = re.sub(r'\b_jsonpath\b', lambda m: self._random_jsonpath(), text)
        text = re.sub(r'\b_jsonkey\b', lambda m: self._random_jsonkey(), text)
        text = re.sub(r'\b_jsonvalue\b', lambda m: self._random_jsonvalue(), text)
        text = re.sub(r'\b_jsonarray\b',
                       lambda m: f"'[{random.randint(1,100)},{random.randint(1,100)}]'", text)
        text = re.sub(r'\b_jsonpair\b',
                       lambda m: f"'{{\"k{random.randint(1,9)}\":{random.randint(1,100)}}}'", text)
        text = re.sub(r'\b_json\b', lambda m: self._random_json(), text)

        # --- Thread / connection / misc ---
        text = re.sub(r'\b_thread_id\b', '1', text)
        text = re.sub(r'\b_thread_count\b', '1', text)
        text = re.sub(r'\b_tmpnam\b', "'/tmp/fz_tmp'", text)

        return text

    def _expand_perl_var(self, var_name, schema):
        """Expand perl-style variables ($table_name, $col_name, etc.)."""
        var = var_name.lstrip('$').lower()
        tbl = schema.random_table() if schema and schema.has_tables() else None

        if 'table' in var:
            return tbl.name if tbl else 't1'
        elif 'col' in var and 'name' in var:
            if tbl:
                col = tbl.random_column()
                return col.name if col else 'col_int'
            return 'col_int'
        elif 'col' in var and 'type' in var:
            return random.choice(['INT', 'VARCHAR(200)', 'TEXT', 'BIGINT', 'DOUBLE'])
        else:
            return var_name  # Keep as-is

    def _random_string(self, max_len=20):
        length = random.randint(1, max(1, max_len))
        chars = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789 ', k=length))
        return chars.replace("'", "''")

    def _random_date(self):
        y = random.randint(2000, 2038)
        m = random.randint(1, 12)
        d = random.randint(1, 28)
        return f"'{y}-{m:02d}-{d:02d}'"

    def _random_time(self):
        h = random.randint(0, 23)
        mi = random.randint(0, 59)
        s = random.randint(0, 59)
        return f"'{h:02d}:{mi:02d}:{s:02d}'"

    def _random_datetime(self):
        return f"{self._random_date()[:-1]} {self._random_time()[1:]}"

    def _random_jsonpath(self):
        parts = ['$']
        for _ in range(random.randint(1, 3)):
            if random.random() < 0.7:
                parts.append(f'.k{random.randint(1, 9)}')
            else:
                parts.append(f'[{random.randint(0, 5)}]')
        return f"'{''.join(parts)}'"

    def _random_jsonkey(self):
        return f"'k{random.randint(1, 20)}'"

    def _random_jsonvalue(self):
        choice = random.randint(0, 4)
        if choice == 0:
            return str(random.randint(-100, 100))
        elif choice == 1:
            return "'" + self._random_string(10) + "'"
        elif choice == 2:
            return 'NULL'
        elif choice == 3:
            return random.choice(['true', 'false'])
        else:
            return "'{}'"

    def _random_json(self):
        choice = random.randint(0, 4)
        if choice == 0:
            return "'{}'"
        elif choice == 1:
            k = random.randint(1, 9)
            v = self._random_string(5)
            return '\'{"k' + str(k) + '":"' + v + '"}\''
        elif choice == 2:
            a, b = random.randint(1, 100), random.randint(1, 100)
            return "'[" + str(a) + "," + str(b) + "]'"
        elif choice == 3:
            return "'null'"
        else:
            a = random.randint(1, 100)
            b = self._random_string(3)
            return '\'{"a":' + str(a) + ',"b":"' + b + '"}\''

    def _cleanup(self, text):
        """Clean up expanded text into valid SQL."""
        # Collapse whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        # Remove stray semicolons in the middle
        text = text.rstrip(';').strip()
        # Remove empty parens from perl blocks
        text = re.sub(r'\(\s*\)', '', text)
        # Remove double spaces
        text = re.sub(r'  +', ' ', text)

        # --- Structural fixes for Perl-dependent grammar output ---

        # Remove stray Perl fragments: ',', @groupby } and similar
        text = re.sub(r"'\s*,\s*'\s*,\s*@\w+\s*\}", '', text)
        text = re.sub(r',\s*@\w+\s*\}', '', text)
        text = re.sub(r'@\w+', '', text)

        # Strip leftover [annotation] brackets (belt-and-suspenders)
        text = re.sub(r'\[\w+\]', '', text)

        # Fix "AND <=" / "AND <" / "OR <=" without left operand
        # e.g. "AND <= ( 6 + 2 )" → "AND alias1.col_int <= ( 6 + 2 )"
        text = re.sub(r'\b(AND|OR)\s+(<=?|>=?|<>|!=)\s',
                       r'\1 alias1.col_int \2 ', text)

        # Fix bare AS without alias name — Perl was supposed to generate it.
        # "t1 AS WHERE ..." or "t1 AS ," or "t1 AS )" or "t1 AS ON" etc.
        # Insert a random alias so MariaDB can resolve the table ref.
        _AS_NEEDS_ALIAS = (
            r'\bAS\s+(?=WHERE\b|SET\b|ON\b|FROM\b|ORDER\b|GROUP\b|HAVING\b'
            r'|LIMIT\b|UNION\b|LEFT\b|RIGHT\b|INNER\b|OUTER\b|STRAIGHT_JOIN\b'
            r'|CROSS\b|NATURAL\b|JOIN\b|,|\)|\(|;|$)'
        )
        text = re.sub(_AS_NEEDS_ALIAS,
                       lambda m: f'AS alias{random.randint(1,4)} ', text)

        # Fix empty LIMIT (Perl was supposed to generate the limit value)
        text = re.sub(r'\bLIMIT\s*(?=;|\s*$|\s*UNION|\s*\)|\s*FOR\b)',
                       f'LIMIT {random.randint(1, 100)} ', text)

        # Fix "ORDER BY SEPARATOR" inside GROUP_CONCAT (missing column before SEPARATOR)
        text = re.sub(r'\bORDER BY\s*(?=SEPARATOR\b)',
                       f'ORDER BY {random.randint(1,4)} ', text)

        # Fix "DROP INDEX" without index name (Perl $idx_name stripped)
        text = re.sub(r'\bDROP INDEX\s*$', 'DROP INDEX `idx1`', text)
        text = re.sub(r'\bDROP INDEX\s*(?=;|\s*$)', 'DROP INDEX `idx1` ', text)

        # Remove unexpanded perl variables: $var_name, $my_int, etc.
        text = re.sub(r'\$\w+', '1', text)
        # Remove unexpanded rule names that look like identifiers in wrong places
        # e.g. "table_names", "column_name_int", "my_int", "string_fill", "fill_begin", "fill_end"
        # These are RQG rule names that didn't expand — replace with safe values
        text = re.sub(r'\btable_names\b', 't1', text)
        text = re.sub(r'\bcolumn_name_int\b', 'col_int', text)
        text = re.sub(r'\bcolumn_name\b', 'col_int', text)
        text = re.sub(r'\bmy_int\b', str(random.randint(-1000, 1000)), text)
        text = re.sub(r'\bstring_fill\b', "'test'", text)
        text = re.sub(r'\bfill_begin\b', "REPEAT(SUBSTR(CAST(", text)
        text = re.sub(r'\bfill_end\b', " AS CHAR),1,1), 100)", text)
        text = re.sub(r'\bstring_col_name\b', 'col_varchar', text)
        text = re.sub(r'\bchar_or_varchar\b', '', text)
        text = re.sub(r'\bsize19_or_size20\b', '', text)
        text = re.sub(r'\bcol_to_idx\b', '', text)
        text = re.sub(r'\bcol9_to_idx\b', '', text)
        text = re.sub(r'\bcol_int_properties\b', '', text)
        text = re.sub(r'\bcol_string_properties\b', '', text)
        text = re.sub(r'\bcol_text_properties\b', '', text)
        text = re.sub(r'\bcol_varchar_properties\b', '', text)
        text = re.sub(r'\bcol_string_g_properties\b', '', text)
        text = re.sub(r'\bcol_int_g_properties\b', '', text)
        text = re.sub(r'\bcol_text_g_properties\b', '', text)
        text = re.sub(r'\bnon_generated_cols\b', 'col_int INT', text)
        text = re.sub(r'\bgenerated_cols\b', '', text)
        text = re.sub(r'\bcommit_rollback\b', 'COMMIT', text)
        text = re.sub(r'\bset_dbug\b', '', text)
        text = re.sub(r'\bset_dbug_null\b', '', text)
        text = re.sub(r'\bset_small_timeouts\b', '', text)
        text = re.sub(r'\bset_big_timeouts\b', '', text)
        text = re.sub(r'\bddl_algorithm_lock_option\b', '', text)
        text = re.sub(r'\bidx_name_prefix\b', 'idx_fz', text)
        text = re.sub(r'\bsmart_base_table\b', 't1', text)
        text = re.sub(r'\bprefix\b', '', text)
        text = re.sub(r'\brformat\b', 'DYNAMIC', text)
        text = re.sub(r'\byes_no\b', random.choice(['YES', 'NO']), text)
        text = re.sub(r'\bzero_one\b', random.choice(['0', '1']), text)
        text = re.sub(r'\bencryption_key_id\b', str(random.randint(1, 33)), text)
        text = re.sub(r'\bdatabase_name_[sn]\b', 'test', text)
        text = re.sub(r'\bprocedure_name_[sn]\b', 'p1', text)
        text = re.sub(r'\bfunction_name_[sn]\b', 'f1', text)
        text = re.sub(r'\bevent_name_[sn]\b', 'e1', text)
        text = re.sub(r'\b\w+_table_name_[sn]\b', 't1', text)
        # Force all ENGINE references to InnoDB
        text = re.sub(r'\bENGINE\s*=\s*(MyISAM|MEMORY|Aria|ARCHIVE|CSV|BLACKHOLE|HEAP)\b',
                       'ENGINE=InnoDB', text, flags=re.IGNORECASE)
        # Fix DROP INDEX ... ON (missing table name after stripping Perl $idx_table)
        text = re.sub(r'\bDROP INDEX\s+(`[^`]+`)\s+ON\s*$',
                       r'DROP INDEX \1 ON t1', text)

        # Fix missing commas in index column lists:
        #   ADD INDEX ... (col_int col_int col_int) → (col_int, col_int, col_int)
        # Pattern: inside parens after INDEX, consecutive bare identifiers
        # without commas between them.
        def _fix_idx_cols(m):
            cols = m.group(1).split()
            return '(' + ', '.join(cols) + ')'
        text = re.sub(
            r'\((\s*(?:col_\w+|_field\w*|id)(?:\s+(?:col_\w+|_field\w*|id))+)\s*\)',
            _fix_idx_cols, text)

        # Clean up resulting double spaces/commas
        text = re.sub(r',\s*,', ',', text)
        text = re.sub(r'\(\s*,', '(', text)
        text = re.sub(r',\s*\)', ')', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def generate_query(self, schema=None, entry_rule='query'):
        """Generate one SQL statement by expanding from the entry rule."""
        if entry_rule not in self.rules:
            # Try common entry points
            for try_rule in ['query', 'thread1', 'dml', 'select']:
                if try_rule in self.rules:
                    entry_rule = try_rule
                    break
            else:
                return None

        sql = self.expand(entry_rule, schema)
        if not sql or len(sql) < 3:
            return None
        # Reject SQL that still has unexpanded tokens (likely garbage)
        _REJECT_TOKENS = [
            '_thread_count', '@stmt_create', '@stmt_ins',
            'smart_base_table }', 'fail_00',
            # Stray Perl/grammar fragments
            '@groupby', "','",
        ]
        if any(bad in sql for bad in _REJECT_TOKENS):
            return None

        # Reject if the SQL starts with a non-SQL token (e.g. bare "table ...")
        first_word = sql.split()[0].upper() if sql.split() else ''
        _SQL_STARTERS = {
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'ALTER', 'CREATE', 'DROP',
            'SET', 'COMMIT', 'ROLLBACK', 'BEGIN', 'START', 'TRUNCATE', 'REPLACE',
            'CALL', 'HANDLER', 'LOCK', 'UNLOCK', 'FLUSH', 'OPTIMIZE', 'ANALYZE',
            'CHECK', 'REPAIR', 'RENAME', 'GRANT', 'REVOKE', 'PREPARE', 'EXECUTE',
            'DEALLOCATE', 'SAVEPOINT', 'RELEASE', 'XA', 'SHOW', 'DESCRIBE',
            'EXPLAIN', 'KILL', 'LOAD', 'INSTALL', 'UNINSTALL', 'RESET', 'PURGE',
            'CHANGE', 'CACHE', 'USE', 'DO', 'SIGNAL', 'RESIGNAL', 'GET',
            'SHUTDOWN', 'WITH', '(', 'HELP',
        }
        if first_word and first_word not in _SQL_STARTERS:
            return None

        return sql

    def get_entry_rules(self):
        """Return likely entry-point rule names."""
        candidates = ['query', 'thread1', 'dml', 'select', 'insert',
                       'update', 'delete', 'ddl']
        return [r for r in candidates if r in self.rules]

    def stats(self):
        total_alts = sum(len(v) for v in self.rules.values())
        return f"{len(self.rules)} rules, {total_alts} alternatives"


def apply_redefine(base, redefine):
    """
    Apply a redefine grammar on top of a base grammar.
    Rules in the redefine REPLACE matching rules in the base.
    Returns a new Grammar with the merged rules.
    """
    merged = Grammar()
    # Copy base rules
    for name, alts in base.rules.items():
        merged.rules[name] = list(alts)
    # Override with redefine rules
    for name, alts in redefine.rules.items():
        merged.rules[name] = list(alts)
    return merged


# ===================================================================
# Grammar combo builder — mirrors InnoDB_standard.cc test matrix
# ===================================================================

# Base grammars (the main --grammar= in each test)
BASE_GRAMMARS = [
    'table_stress_innodb.yy',
    'table_stress_innodb_dml.yy',
    'table_stress_innodb_fk.yy',
    'table_stress_innodb_nocopy.yy',
    'table_stress_innodb_nocopy1.yy',
    'oltp.yy',
    'oltp-transactional.yy',
    'concurrency.yy',
    'concurrency_innodb.yy',
    'partitions_innodb.yy',
    'full_text_search.yy',
    'engine_stress.yy',
    'many_indexes.yy',
    'instant_add.yy',
    'alter_online.yy',
    'fk_truncate.yy',
    'innodb_compression_encryption.yy',
]

# Redefine grammars (each one overrides specific rules)
REDEFINE_GRAMMARS = [
    'alter_table.yy',
    'instant_add.yy',
    'bulk_insert.yy',
    'versioning.yy',
    'sequences.yy',
    'json.yy',
    'multi_update.yy',
    'redefine_temporary_tables.yy',
    'redefine_innodb_undo.yy',
    'redefine_innodb_sys_ddl.yy',
    'redefine_innodb_log_write_ahead_size.yy',
    'redefine_innodb_log_size_dynamic.yy',
    'redefine_innodb_log_parameters.yy',
    'redefine_innodb_log_file_buffering.yy',
    'redefine_checks_off.yy',
    'xa.yy',
    # modules/
    'modules/alter_table_columns.yy',
    'modules/foreign_keys.yy',
    'modules/locks.yy',
    'modules/locks-10.4-extra.yy',
]


class GrammarPool:
    """
    Manages a pool of base grammars and redefine grammars.
    Each query request picks a random base grammar, applies 0-4 random
    redefines on top, and expands a rule from the combined grammar.
    This mirrors how InnoDB_standard.cc combines --grammar + --redefine.
    """

    def __init__(self):
        self.base_grammars = []       # list of (filename, Grammar)
        self.redefine_grammars = []   # list of (filename, Grammar)
        self.all_grammars = []        # list of (filename, Grammar) — everything loaded

    def load_directory(self, grammar_dir):
        """Load all .yy files from a directory, classify as base or redefine."""
        if not os.path.isdir(grammar_dir):
            return

        # Load all .yy files
        all_files = {}
        for root, dirs, files in os.walk(grammar_dir):
            for fname in sorted(files):
                if fname.endswith('.yy'):
                    path = os.path.join(root, fname)
                    try:
                        g = Grammar()
                        g.load_file(path)
                        g._source_file = fname
                        all_files[fname] = g
                        # Also store with relative path for modules/
                        rel = os.path.relpath(path, grammar_dir)
                        all_files[rel] = g
                    except Exception as e:
                        logger.debug(f"Failed to load {path}: {e}")

        # Classify
        for fname in BASE_GRAMMARS:
            if fname in all_files:
                g = all_files[fname]
                if g.get_entry_rules():
                    self.base_grammars.append((fname, g))

        for fname in REDEFINE_GRAMMARS:
            if fname in all_files:
                self.redefine_grammars.append((fname, all_files[fname]))

        # Any .yy with entry rules that isn't already classified → base
        classified = set(f for f, _ in self.base_grammars) | set(f for f, _ in self.redefine_grammars)
        for fname, g in all_files.items():
            if fname not in classified and '/' not in fname and g.get_entry_rules():
                self.base_grammars.append((fname, g))

        self.all_grammars = list(all_files.items())

        logger.info(f"GrammarPool: {len(self.base_grammars)} base grammars, "
                     f"{len(self.redefine_grammars)} redefines")

    def load_files(self, paths):
        """Load specific .yy files."""
        for path in paths:
            if os.path.isdir(path):
                self.load_directory(path)
            elif os.path.isfile(path) and path.endswith('.yy'):
                try:
                    g = Grammar()
                    g.load_file(path)
                    fname = os.path.basename(path)
                    g._source_file = fname
                    if g.get_entry_rules():
                        self.base_grammars.append((fname, g))
                    else:
                        self.redefine_grammars.append((fname, g))
                except Exception as e:
                    logger.debug(f"Failed to load {path}: {e}")

    def generate_query(self, schema):
        """
        Pick a random base grammar, apply 0-4 random redefines,
        expand a rule, return SQL.
        """
        if not self.base_grammars:
            return None

        # Pick random base
        base_name, base = random.choice(self.base_grammars)

        # Apply 0-4 random redefines
        num_redefines = random.randint(0, min(4, len(self.redefine_grammars)))
        if num_redefines > 0 and self.redefine_grammars:
            redefines = random.sample(self.redefine_grammars,
                                       min(num_redefines, len(self.redefine_grammars)))
            combined = base
            for rdef_name, rdef in redefines:
                combined = apply_redefine(combined, rdef)
        else:
            combined = base

        sql = combined.generate_query(schema)
        return sql

    def has_grammars(self):
        return len(self.base_grammars) > 0

    def stats(self):
        return (f"{len(self.base_grammars)} base, "
                f"{len(self.redefine_grammars)} redefines, "
                f"{len(self.all_grammars)} total .yy files")
