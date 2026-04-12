"""
Fragment pool collector.
Harvests column-like and table-like AST fragments from seed queries
for cross-pollination during fuzzing (the key insight from ClickHouse's approach).
"""

import random
import sqlglot
from sqlglot import exp

MAX_POOL_SIZE = 2000


class FragmentPool:
    """Collects and serves AST fragments for cross-query mutation."""

    def __init__(self):
        self.column_like = []   # expressions, literals, identifiers, function calls
        self.table_like = []    # table names, subqueries, derived tables
        self.column_names = []  # bare column name strings seen
        self.table_names = []   # bare table name strings seen

    def collect(self, ast):
        """Walk an AST and harvest fragments into the pools."""
        if ast is None:
            return

        for node in ast.walk():
            # Column-like: literals, columns, functions, stars, subqueries in expression position
            if isinstance(node, (exp.Literal, exp.Column, exp.Anonymous,
                                 exp.Func, exp.Star, exp.Paren, exp.Between,
                                 exp.In, exp.Binary, exp.Unary, exp.Case,
                                 exp.Cast, exp.Subquery)):
                self._add_column_like(node)

            # Table-like: table references, subqueries as tables
            if isinstance(node, (exp.Table, exp.Subquery)):
                self._add_table_like(node)

            # Collect bare names
            if isinstance(node, exp.Column) and node.name:
                if node.name not in self.column_names:
                    self.column_names.append(node.name)
                    if len(self.column_names) > MAX_POOL_SIZE:
                        self.column_names.pop(random.randint(0, len(self.column_names) - 1))

            if isinstance(node, exp.Table) and node.name:
                if node.name not in self.table_names:
                    self.table_names.append(node.name)
                    if len(self.table_names) > MAX_POOL_SIZE:
                        self.table_names.pop(random.randint(0, len(self.table_names) - 1))

    def _add_column_like(self, node):
        self.column_like.append(node.copy())
        if len(self.column_like) > MAX_POOL_SIZE:
            self.column_like.pop(random.randint(0, len(self.column_like) - 1))

    def _add_table_like(self, node):
        self.table_like.append(node.copy())
        if len(self.table_like) > MAX_POOL_SIZE:
            self.table_like.pop(random.randint(0, len(self.table_like) - 1))

    def get_column_like(self):
        """Return a random column-like fragment, or None if pool is empty."""
        if not self.column_like:
            return None
        return random.choice(self.column_like).copy()

    def get_table_like(self):
        """Return a random table-like fragment, or None if pool is empty."""
        if not self.table_like:
            return None
        return random.choice(self.table_like).copy()

    def get_column_name(self):
        """Return a random column name string."""
        if not self.column_names:
            return "c1"
        return random.choice(self.column_names)

    def get_table_name(self):
        """Return a random table name string."""
        if not self.table_names:
            return "t1"
        return random.choice(self.table_names)

    def stats(self):
        return (f"FragmentPool: {len(self.column_like)} column-like, "
                f"{len(self.table_like)} table-like, "
                f"{len(self.column_names)} col names, "
                f"{len(self.table_names)} table names")
