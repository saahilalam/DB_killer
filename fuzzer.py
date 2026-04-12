"""
Main fuzzer engine.
Walks AST trees, collects fragments, and applies mutations recursively.
Modeled after ClickHouse's QueryFuzzer but targeting MariaDB/InnoDB.
"""

import random
import logging
import sqlglot
from sqlglot import exp
from sqlglot.dialects.mysql import MySQL
from sqlglot.errors import ParseError, OptimizeError

from fragments import FragmentPool
from config import chance, pick, Prob
from mutations import (
    fuzz_literal, fuzz_function, fuzz_select, fuzz_joins,
    fuzz_create_table, fuzz_insert, fuzz_update, fuzz_delete,
    inject_subquery_in_select, inject_union, wrap_in_case,
    generate_transaction_statement, generate_alter_table,
)

logger = logging.getLogger(__name__)

MAX_DEPTH = 200
MAX_ITERATIONS = 100_000


class Fuzzer:
    """
    AST-based SQL fuzzer for MariaDB.

    Usage:
        fuzzer = Fuzzer(seed=42)
        fuzzer.load_seed_file("regression_tests.sql")
        for mutated_sql in fuzzer.fuzz_all(runs_per_query=10):
            print(mutated_sql)
    """

    def __init__(self, seed=None):
        if seed is not None:
            random.seed(seed)
        self.pool = FragmentPool()
        self.seed_queries = []
        self._depth = 0
        self._iterations = 0

    def load_seed_file(self, path):
        """Load seed queries from a SQL file (one statement per line or semicolon-separated)."""
        with open(path, 'r', errors='replace') as f:
            content = f.read()

        self._parse_and_add_seeds(content)
        logger.info(f"Loaded {len(self.seed_queries)} seed queries from {path}")
        logger.info(self.pool.stats())

    def load_seed_sql(self, sql_text):
        """Load seed queries from a SQL string."""
        self._parse_and_add_seeds(sql_text)

    def _parse_and_add_seeds(self, content):
        """Parse SQL content into individual statements and collect fragments."""
        # Split by semicolons, handling multi-line statements
        statements = self._split_statements(content)

        for stmt_text in statements:
            stmt_text = stmt_text.strip()
            if not stmt_text or stmt_text.startswith('--') or stmt_text.startswith('#'):
                continue

            try:
                parsed = sqlglot.parse_one(stmt_text, dialect="mysql")
                self.seed_queries.append(parsed)
                self.pool.collect(parsed)
            except Exception as e:
                # Store unparseable queries as raw strings for pass-through fuzzing
                logger.debug(f"Could not parse: {stmt_text[:80]}... ({e})")
                # Still keep as raw for potential use
                self.seed_queries.append(stmt_text)

    def _split_statements(self, content):
        """Split SQL content into statements, respecting quotes and comments."""
        statements = []
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
                current.append(c)
                i += 1
                continue

            if in_block_comment:
                current.append(c)
                if c == '*' and i + 1 < len(content) and content[i + 1] == '/':
                    current.append('/')
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
                    current.append(c)
                    i += 1
                    continue
                if c == '#':
                    in_line_comment = True
                    current.append(c)
                    i += 1
                    continue
                if c == '/' and i + 1 < len(content) and content[i + 1] == '*':
                    in_block_comment = True
                    current.append(c)
                    current.append('*')
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

        # Last statement (no trailing semicolon)
        stmt = ''.join(current).strip()
        if stmt:
            statements.append(stmt)

        return statements

    def fuzz_one(self, query):
        """
        Take a single query (AST or string) and return a mutated SQL string.
        """
        self._depth = 0
        self._iterations = 0

        if isinstance(query, str):
            # Raw string query — try to parse, fall back to string-level fuzzing
            try:
                ast = sqlglot.parse_one(query, dialect="mysql")
            except Exception:
                return self._fuzz_raw_string(query)
        else:
            ast = query.copy()

        # Collect fragments from this query (grows pool over time)
        self.pool.collect(ast)

        # Apply mutations
        try:
            mutated = self._fuzz_ast(ast)
        except Exception as e:
            logger.debug(f"Mutation error: {e}")
            return self._try_generate(ast)

        # Convert back to SQL
        try:
            sql = mutated.sql(dialect="mysql")
            return sql
        except Exception as e:
            logger.debug(f"SQL generation error: {e}")
            return self._try_generate(ast)

    def _fuzz_ast(self, ast):
        """Recursively walk and mutate the AST."""
        self._depth += 1
        self._iterations += 1

        if self._depth > MAX_DEPTH or self._iterations > MAX_ITERATIONS:
            self._depth -= 1
            return ast

        # Type-specific top-level mutations
        if isinstance(ast, exp.Select):
            ast = fuzz_select(ast, self.pool)
            ast = fuzz_joins(ast, self.pool)
            ast = inject_subquery_in_select(ast, self.pool)
            if chance(200):
                ast = inject_union(ast, self.pool)

        elif isinstance(ast, exp.Create):
            ast = fuzz_create_table(ast, self.pool)

        elif isinstance(ast, exp.Insert):
            ast = fuzz_insert(ast, self.pool)

        elif isinstance(ast, exp.Update):
            ast = fuzz_update(ast, self.pool)

        elif isinstance(ast, exp.Delete):
            ast = fuzz_delete(ast, self.pool)

        # Walk children and mutate
        if isinstance(ast, exp.Expression):
            for key, value in list(ast.args.items()):
                if isinstance(value, exp.Expression):
                    ast.args[key] = self._fuzz_node(value)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, exp.Expression):
                            value[i] = self._fuzz_node(item)

        self._depth -= 1
        return ast

    def _fuzz_node(self, node):
        """Apply node-level mutations."""
        self._iterations += 1
        if self._iterations > MAX_ITERATIONS:
            return node

        # Literal mutation
        if isinstance(node, exp.Literal):
            node = fuzz_literal(node)
            return node

        # Function mutation
        if isinstance(node, (exp.Func, exp.Anonymous)):
            node = fuzz_function(node)

        # Column reference — occasionally swap with a pool fragment
        if isinstance(node, exp.Column) and chance(30):
            replacement = self.pool.get_column_like()
            if replacement:
                return replacement

        # Wrap expression in CASE
        if isinstance(node, (exp.Column, exp.Literal, exp.Func)) and chance(Prob.WRAP_IN_CASE):
            node = wrap_in_case(node, self.pool)

        # Recurse into children
        if isinstance(node, exp.Expression):
            for key, value in list(node.args.items()):
                if isinstance(value, exp.Expression):
                    node.args[key] = self._fuzz_node(value)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, exp.Expression):
                            value[i] = self._fuzz_node(item)

        return node

    def _fuzz_raw_string(self, query):
        """String-level fuzzing for unparseable queries."""
        mutations = [
            lambda q: q.replace("SELECT", pick(["SELECT", "SELECT DISTINCT", "SELECT SQL_NO_CACHE", "SELECT ALL"])),
            lambda q: q.replace("WHERE", pick(["WHERE", "WHERE NOT", "HAVING"])),
            lambda q: q + f" LIMIT {pick([0, 1, 10, 2147483647])}",
            lambda q: q.replace("=", pick(["=", "!=", "<>", ">", "<", ">=", "<=", "<=>"])),
            lambda q: q.replace("AND", pick(["AND", "OR", "XOR"])),
            lambda q: q.replace("NULL", pick(["NULL", "0", "''", "1", "TRUE", "FALSE"])),
        ]
        result = query
        for mutation in mutations:
            if chance(5):
                try:
                    result = mutation(result)
                except Exception:
                    pass
        return result

    def _try_generate(self, original):
        """Fallback: try to generate SQL from the original."""
        try:
            return original.sql(dialect="mysql")
        except Exception:
            return str(original)

    def fuzz_all(self, runs_per_query=10, include_transactions=True, include_alters=True):
        """
        Generator that yields mutated SQL strings.
        Each seed query is mutated `runs_per_query` times.
        Optionally injects transaction and ALTER TABLE statements.
        """
        for query in self.seed_queries:
            for _ in range(runs_per_query):
                yield self.fuzz_one(query)

                # Occasionally inject transaction statements
                if include_transactions and chance(20):
                    yield generate_transaction_statement()

                # Occasionally inject ALTER TABLE
                if include_alters and chance(30):
                    yield generate_alter_table(self.pool)

    def fuzz_query(self, sql_text, runs=10):
        """
        Convenience: parse a single query and return N mutations.
        """
        try:
            ast = sqlglot.parse_one(sql_text, dialect="mysql")
            self.pool.collect(ast)
        except Exception:
            ast = sql_text

        results = []
        for _ in range(runs):
            results.append(self.fuzz_one(ast))
        return results
