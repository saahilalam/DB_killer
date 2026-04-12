"""
Mutation strategies for the MariaDB AST Fuzzer.
Each mutator takes an AST node (sqlglot expression) and the fragment pool,
and returns a (possibly modified) node.
"""

import random
import sqlglot
from sqlglot import exp
from sqlglot.dialects.mysql import MySQL

from config import (
    Prob, chance, pick,
    BAD_INTEGERS, BAD_FLOATS, BAD_STRINGS, BAD_DATES, BAD_DATETIMES,
    FUNCTION_SWAP_MAP, AGGREGATE_SWAP_MAP, ALL_AGGREGATES,
    ALL_COLUMN_TYPES, INTEGER_TYPES, STRING_TYPES, DATE_TYPES,
    INNODB_ROW_FORMATS, INNODB_KEY_BLOCK_SIZES, INNODB_COMPRESSION_ALGORITHMS,
    STORAGE_ENGINES, CHARSETS,
)


# ===================================================================
# Literal / value mutations
# ===================================================================

def fuzz_literal(node):
    """Mutate a literal value node."""
    if not isinstance(node, exp.Literal):
        return node

    # Chance to replace with NULL
    if chance(Prob.REPLACE_WITH_NULL):
        return exp.Null()

    if node.is_int:
        return _fuzz_int_literal(node)
    elif node.is_number:
        return _fuzz_float_literal(node)
    elif node.is_string:
        return _fuzz_string_literal(node)

    return node


def _fuzz_int_literal(node):
    try:
        val = int(node.this)
    except (ValueError, TypeError):
        val = 0

    action = random.randint(0, 9)
    if action == 0:
        return exp.Literal.number(pick(BAD_INTEGERS))
    elif action == 1:
        return exp.Literal.number(val + random.randint(-10, 10))
    elif action == 2:
        return exp.Literal.number(val * random.choice([-1, 2, 10, 0]))
    elif action == 3:
        return exp.Literal.number(val ^ random.randint(0, 0xFFFF))
    elif action == 4:
        return exp.Literal.number(abs(val) if val < 0 else -val)
    elif action == 5:
        return exp.Literal.string(str(val))  # type crossover: int -> string
    elif action == 6:
        return exp.Literal.number(val + 1)
    elif action == 7:
        return exp.Literal.number(val - 1)
    elif action == 8:
        return exp.Literal.number(0)
    else:
        return exp.Literal.number(random.randint(-2**31, 2**31))


def _fuzz_float_literal(node):
    try:
        val = float(node.this)
    except (ValueError, TypeError):
        val = 0.0

    action = random.randint(0, 6)
    if action == 0:
        return exp.Literal.number(pick(BAD_FLOATS))
    elif action == 1:
        return exp.Literal.number(val * random.choice([-1.0, 0.5, 2.0, 10.0]))
    elif action == 2:
        return exp.Literal.number(val + random.uniform(-100, 100))
    elif action == 3:
        return exp.Literal.number(int(val))  # type crossover: float -> int
    elif action == 4:
        return exp.Literal.string(str(val))
    elif action == 5:
        return exp.Literal.number(0.0)
    else:
        return exp.Literal.number(random.uniform(-1e10, 1e10))


def _fuzz_string_literal(node):
    val = node.this or ""

    action = random.randint(0, 14)
    if action == 0:
        return exp.Literal.string(pick(BAD_STRINGS))
    elif action == 1:
        return exp.Literal.string("")
    elif action == 2:
        return exp.Literal.string(val * 2)
    elif action == 3:
        return exp.Literal.string(val + "\x00")
    elif action == 4:
        # Swap LIKE wildcards
        return exp.Literal.string(val.replace("%", "_").replace("_", "%"))
    elif action == 5:
        return exp.Literal.string(pick(BAD_DATES))
    elif action == 6:
        return exp.Literal.string(pick(BAD_DATETIMES))
    elif action == 7:
        return exp.Literal.number(random.randint(-100, 100))  # string -> int
    elif action == 8:
        return exp.Literal.string(val[::-1])  # reverse
    elif action == 9:
        if len(val) > 0:
            pos = random.randint(0, len(val) - 1)
            return exp.Literal.string(val[:pos] + val[pos + 1:])  # delete char
        return node
    elif action == 10:
        return exp.Literal.string(val.upper())
    elif action == 11:
        return exp.Literal.string(val.lower())
    elif action == 12:
        return exp.Literal.string("NULL")
    elif action == 13:
        return exp.Literal.string("0")
    else:
        return exp.Literal.string("".join(random.choices("abcdefghijklmnop0123456789", k=random.randint(1, 64))))


# ===================================================================
# Function mutations
# ===================================================================

def fuzz_function(node):
    """Swap a function for an equivalent one, or mutate its arguments."""
    if not isinstance(node, (exp.Func, exp.Anonymous)):
        return node

    fname = _get_func_name(node).upper()

    # Swap aggregate
    if fname in AGGREGATE_SWAP_MAP and chance(Prob.SWAP_AGGREGATE):
        alternatives = AGGREGATE_SWAP_MAP[fname]
        new_name = pick(alternatives)
        return _replace_func_name(node, new_name)

    # Swap regular function
    if fname in FUNCTION_SWAP_MAP and chance(Prob.SWAP_FUNCTION):
        alternatives = FUNCTION_SWAP_MAP[fname]
        new_name = pick(alternatives)
        return _replace_func_name(node, new_name)

    return node


def _get_func_name(node):
    if isinstance(node, exp.Anonymous):
        return node.name or ""
    return type(node).__name__ if not hasattr(node, 'sql_name') else node.sql_name()


def _replace_func_name(node, new_name):
    """Replace function name, keeping arguments. Use Anonymous for safety."""
    args = list(node.args.get("expressions", []) or [])
    # Also grab 'this' argument if present
    this = node.args.get("this")
    if this and isinstance(this, exp.Expression):
        all_args = [this.copy()] + [a.copy() for a in args]
    else:
        all_args = [a.copy() for a in args]

    return exp.Anonymous(this=new_name, expressions=all_args)


# ===================================================================
# SELECT clause mutations
# ===================================================================

def fuzz_select(node, pool):
    """Mutate a SELECT statement's clauses."""
    if not isinstance(node, exp.Select):
        return node

    # Toggle DISTINCT
    if chance(Prob.TOGGLE_DISTINCT):
        if node.args.get("distinct"):
            node.args["distinct"] = None
        else:
            node.args["distinct"] = exp.Distinct()

    # WHERE mutations
    _fuzz_where(node, pool)

    # GROUP BY mutations
    _fuzz_group_by(node, pool)

    # HAVING mutations
    _fuzz_having(node, pool)

    # ORDER BY mutations
    _fuzz_order_by(node, pool)

    # LIMIT mutations
    _fuzz_limit(node)

    # FOR UPDATE / LOCK IN SHARE MODE
    _fuzz_locking(node)

    return node


def _fuzz_where(node, pool):
    where = node.args.get("where")

    if where and chance(Prob.REMOVE_WHERE):
        node.args["where"] = None
        return

    if where and chance(Prob.REPLACE_WHERE):
        new_pred = _generate_predicate(pool)
        if new_pred:
            node.args["where"] = exp.Where(this=new_pred)
        return

    if not where and chance(Prob.ADD_WHERE):
        new_pred = _generate_predicate(pool)
        if new_pred:
            node.args["where"] = exp.Where(this=new_pred)
        return

    # Mutate existing WHERE predicate tree
    if where and chance(10):
        _permute_predicate(where)


def _fuzz_group_by(node, pool):
    group = node.args.get("group")

    if group and chance(Prob.REMOVE_GROUP_BY):
        node.args["group"] = None
        return

    if not group and chance(Prob.ADD_GROUP_BY):
        col = pool.get_column_like()
        if col:
            node.args["group"] = exp.Group(expressions=[col])
        return

    # Shuffle / add / remove elements
    if group and hasattr(group, 'expressions'):
        _fuzz_expression_list(group.expressions, pool)


def _fuzz_having(node, pool):
    having = node.args.get("having")

    if having and chance(Prob.REMOVE_HAVING):
        node.args["having"] = None
        return

    if not having and chance(Prob.ADD_HAVING):
        pred = _generate_predicate(pool)
        if pred:
            node.args["having"] = exp.Having(this=pred)


def _fuzz_order_by(node, pool):
    order = node.args.get("order")

    if order and chance(Prob.REMOVE_ORDER_BY):
        node.args["order"] = None
        return

    if not order and chance(Prob.ADD_ORDER_BY):
        col = pool.get_column_like()
        if col:
            ordered = exp.Ordered(this=col, desc=random.choice([True, False]))
            node.args["order"] = exp.Order(expressions=[ordered])
        return

    # Fuzz direction, add/remove elements
    if order and hasattr(order, 'expressions'):
        for i, ordered in enumerate(order.expressions):
            if isinstance(ordered, exp.Ordered) and chance(10):
                ordered.args["desc"] = not ordered.args.get("desc", False)
            if isinstance(ordered, exp.Ordered) and chance(20):
                # Toggle NULLS FIRST/LAST
                current = ordered.args.get("nulls_first")
                if current is None:
                    ordered.args["nulls_first"] = random.choice([True, False])
                else:
                    ordered.args["nulls_first"] = not current


def _fuzz_limit(node):
    limit = node.args.get("limit")

    if limit and chance(Prob.REMOVE_LIMIT):
        node.args["limit"] = None
        return

    if not limit and chance(Prob.ADD_LIMIT):
        val = pick([0, 1, 2, 10, 100, 1000, 2147483647])
        node.args["limit"] = exp.Limit(expression=exp.Literal.number(val))
        return

    # Fuzz limit value
    if limit and chance(10):
        val = pick([0, 1, 2, 10, 100, 1000, 2147483647])
        limit.args["expression"] = exp.Literal.number(val)

    # Add/remove OFFSET
    offset = node.args.get("offset")
    if offset and chance(50):
        node.args["offset"] = None
    elif not offset and chance(50):
        val = pick([0, 1, 10, 100, 1000])
        node.args["offset"] = exp.Offset(expression=exp.Literal.number(val))


def _fuzz_locking(node):
    """Toggle FOR UPDATE / LOCK IN SHARE MODE."""
    locks = node.args.get("locks")

    if locks and chance(Prob.TOGGLE_FOR_UPDATE):
        node.args["locks"] = None
        return

    if not locks and chance(Prob.TOGGLE_FOR_UPDATE):
        lock_type = random.choice(["UPDATE", "SHARE"])
        node.args["locks"] = [exp.Lock(update=lock_type == "UPDATE")]


# ===================================================================
# Expression list mutations
# ===================================================================

def _fuzz_expression_list(expressions, pool):
    """Shuffle, add, or remove elements in an expression list."""
    if not expressions:
        return

    if chance(Prob.SHUFFLE_LIST) and len(expressions) > 1:
        random.shuffle(expressions)

    if chance(Prob.REMOVE_ELEMENT) and len(expressions) > 1:
        expressions.pop(random.randint(0, len(expressions) - 1))

    if chance(Prob.ADD_ELEMENT):
        fragment = pool.get_column_like()
        if fragment:
            expressions.append(fragment)


# ===================================================================
# JOIN mutations
# ===================================================================

JOIN_TYPES = ["JOIN", "LEFT JOIN", "RIGHT JOIN", "INNER JOIN",
              "CROSS JOIN", "NATURAL JOIN", "LEFT OUTER JOIN",
              "RIGHT OUTER JOIN", "STRAIGHT_JOIN"]


def fuzz_joins(node, pool):
    """Mutate JOIN clauses in a FROM."""
    if not isinstance(node, exp.Select):
        return node

    joins = node.args.get("joins") or []

    # Change existing join types
    for join in joins:
        if isinstance(join, exp.Join) and chance(Prob.CHANGE_JOIN_TYPE):
            _mutate_join_type(join)

    # Remove a join
    if joins and chance(Prob.REMOVE_JOIN) and len(joins) > 0:
        joins.pop(random.randint(0, len(joins) - 1))
        node.args["joins"] = joins

    # Add a join
    if chance(Prob.ADD_JOIN):
        tbl = pool.get_table_name()
        alias = f"fz_{random.randint(0, 999)}"
        col1 = pool.get_column_name()
        col2 = pool.get_column_name()

        join_kind = pick(["", "LEFT", "RIGHT", "INNER", "CROSS"])
        new_join = exp.Join(
            this=exp.Table(this=exp.to_identifier(tbl), alias=exp.TableAlias(this=exp.to_identifier(alias))),
            on=exp.EQ(
                this=exp.Column(this=exp.to_identifier(col1)),
                expression=exp.Column(this=exp.to_identifier(col2), table=exp.to_identifier(alias)),
            ),
            kind=join_kind,
        )
        joins.append(new_join)
        node.args["joins"] = joins

    return node


def _mutate_join_type(join):
    kinds = ["", "INNER", "LEFT", "RIGHT", "CROSS", "LEFT OUTER", "RIGHT OUTER"]
    join.args["kind"] = pick(kinds)
    if chance(5):
        # Toggle NATURAL
        if join.args.get("natural"):
            join.args["natural"] = None
        else:
            join.args["natural"] = True


# ===================================================================
# Predicate generation
# ===================================================================

def _generate_predicate(pool):
    """Generate a synthetic WHERE/HAVING predicate."""
    col_name = pool.get_column_name()
    col = exp.Column(this=exp.to_identifier(col_name))

    action = random.randint(0, 11)

    if action == 0:
        return exp.Is(this=col, expression=exp.Null())
    elif action == 1:
        return exp.Not(this=exp.Is(this=col, expression=exp.Null()))
    elif action == 2:
        val = exp.Literal.number(pick(BAD_INTEGERS))
        return exp.EQ(this=col, expression=val)
    elif action == 3:
        val = exp.Literal.string(pick(BAD_STRINGS))
        return exp.EQ(this=col, expression=val)
    elif action == 4:
        lo = exp.Literal.number(pick(BAD_INTEGERS))
        hi = exp.Literal.number(pick(BAD_INTEGERS))
        return exp.Between(this=col, low=lo, high=hi)
    elif action == 5:
        vals = [exp.Literal.number(pick(BAD_INTEGERS)) for _ in range(random.randint(1, 5))]
        return exp.In(this=col, expressions=vals)
    elif action == 6:
        col2_name = pool.get_column_name()
        col2 = exp.Column(this=exp.to_identifier(col2_name))
        op = random.choice([exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE])
        return op(this=col, expression=col2)
    elif action == 7:
        pattern = exp.Literal.string(pick(["%test%", "_%", "%", "_", "a%b"]))
        return exp.Like(this=col, expression=pattern)
    elif action == 8:
        # EXISTS (SELECT 1 FROM <table>)
        tbl = pool.get_table_name()
        subq = exp.Select(
            expressions=[exp.Literal.number(1)],
        ).from_(exp.Table(this=exp.to_identifier(tbl)))
        return exp.Exists(this=exp.Subquery(this=subq))
    elif action == 9:
        # col > (SELECT MAX(col2) FROM tbl)
        col2 = pool.get_column_name()
        tbl = pool.get_table_name()
        subq = exp.Select(
            expressions=[exp.Anonymous(this="MAX", expressions=[exp.Column(this=exp.to_identifier(col2))])],
        ).from_(exp.Table(this=exp.to_identifier(tbl)))
        return exp.GT(this=col, expression=exp.Subquery(this=subq))
    elif action == 10:
        # Combine two predicates with AND/OR
        p1 = _generate_simple_predicate(pool)
        p2 = _generate_simple_predicate(pool)
        if p1 and p2:
            if random.choice([True, False]):
                return exp.And(this=p1, expression=p2)
            else:
                return exp.Or(this=p1, expression=p2)
        return p1 or p2
    else:
        return _generate_simple_predicate(pool)


def _generate_simple_predicate(pool):
    col_name = pool.get_column_name()
    col = exp.Column(this=exp.to_identifier(col_name))
    val = exp.Literal.number(pick(BAD_INTEGERS))
    op = random.choice([exp.EQ, exp.NEQ, exp.GT, exp.LT])
    return op(this=col, expression=val)


def _permute_predicate(where_node):
    """Shuffle operands of AND/OR in a predicate tree."""
    pred = where_node.this if hasattr(where_node, 'this') else where_node
    if isinstance(pred, (exp.And, exp.Or)):
        if chance(3):
            # Swap left and right
            pred.args["this"], pred.args["expression"] = pred.args["expression"], pred.args["this"]
        if chance(5):
            # Negate the whole thing
            where_node.args["this"] = exp.Not(this=pred)


# ===================================================================
# DDL / CREATE TABLE mutations (InnoDB-focused)
# ===================================================================

def fuzz_create_table(node, pool):
    """Mutate a CREATE TABLE statement with InnoDB focus."""
    if not isinstance(node, exp.Create):
        return node

    kind = node.args.get("kind", "").upper()
    if kind not in ("TABLE", ""):
        return node

    # Fuzz column definitions
    schema = node.args.get("this")
    if isinstance(schema, exp.Schema):
        for col_expr in (schema.expressions or []):
            if isinstance(col_expr, exp.ColumnDef):
                _fuzz_column_def(col_expr)

    # Fuzz table properties
    properties = node.args.get("properties")
    if properties:
        _fuzz_table_properties(properties)
    else:
        # Add some InnoDB properties
        if chance(5):
            _add_innodb_properties(node)

    return node


def _fuzz_column_def(col_def):
    """Mutate a column definition."""
    kind = col_def.args.get("kind")
    if kind and chance(Prob.SWAP_DATA_TYPE):
        _fuzz_data_type(kind)

    # Toggle NULL/NOT NULL
    constraints = col_def.args.get("constraints") or []
    if chance(Prob.TOGGLE_NULLABLE):
        has_not_null = any(
            isinstance(c.args.get("kind"), exp.NotNullColumnConstraint)
            for c in constraints if isinstance(c, exp.ColumnConstraint)
        )
        if has_not_null:
            # Remove NOT NULL constraints
            col_def.args["constraints"] = [
                c for c in constraints
                if not (isinstance(c, exp.ColumnConstraint) and
                        isinstance(c.args.get("kind"), exp.NotNullColumnConstraint))
            ]
        else:
            constraints.append(
                exp.ColumnConstraint(kind=exp.NotNullColumnConstraint())
            )
            col_def.args["constraints"] = constraints


def _fuzz_data_type(type_node):
    """Mutate a data type."""
    if not isinstance(type_node, exp.DataType):
        return

    # Replace with random type
    new_type = pick(ALL_COLUMN_TYPES)
    type_mapping = {
        "TINYINT": exp.DataType.Type.TINYINT,
        "SMALLINT": exp.DataType.Type.SMALLINT,
        "MEDIUMINT": exp.DataType.Type.MEDIUMINT,
        "INT": exp.DataType.Type.INT,
        "BIGINT": exp.DataType.Type.BIGINT,
        "FLOAT": exp.DataType.Type.FLOAT,
        "DOUBLE": exp.DataType.Type.DOUBLE,
        "DECIMAL": exp.DataType.Type.DECIMAL,
        "CHAR": exp.DataType.Type.CHAR,
        "VARCHAR": exp.DataType.Type.VARCHAR,
        "TEXT": exp.DataType.Type.TEXT,
        "TINYTEXT": exp.DataType.Type.TEXT,
        "MEDIUMTEXT": exp.DataType.Type.TEXT,
        "LONGTEXT": exp.DataType.Type.TEXT,
        "BINARY": exp.DataType.Type.BINARY,
        "VARBINARY": exp.DataType.Type.VARBINARY,
        "BLOB": exp.DataType.Type.BINARY,
        "TINYBLOB": exp.DataType.Type.BINARY,
        "MEDIUMBLOB": exp.DataType.Type.BINARY,
        "LONGBLOB": exp.DataType.Type.BINARY,
        "DATE": exp.DataType.Type.DATE,
        "TIME": exp.DataType.Type.TIME,
        "DATETIME": exp.DataType.Type.DATETIME,
        "TIMESTAMP": exp.DataType.Type.TIMESTAMP,
        "YEAR": exp.DataType.Type.INT,
        "JSON": exp.DataType.Type.JSON,
        "BIT": exp.DataType.Type.BIT,
        "BOOLEAN": exp.DataType.Type.BOOLEAN,
        "ENUM": exp.DataType.Type.ENUM,
        "SET": exp.DataType.Type.SET,
    }

    mapped = type_mapping.get(new_type)
    if mapped:
        type_node.args["this"] = mapped
        # Add/fuzz type parameters (length, precision, etc.)
        if new_type in ("VARCHAR", "CHAR", "VARBINARY", "BINARY"):
            length = pick([1, 10, 50, 255, 256, 1000, 65535])
            type_node.args["expressions"] = [exp.DataTypeParam(this=exp.Literal.number(length))]
        elif new_type == "DECIMAL":
            precision = pick([5, 10, 20, 38, 65])
            scale = pick([0, 2, 5, 10, 30])
            type_node.args["expressions"] = [
                exp.DataTypeParam(this=exp.Literal.number(precision)),
                exp.DataTypeParam(this=exp.Literal.number(scale)),
            ]
        elif new_type in ("ENUM", "SET"):
            vals = [exp.Literal.string(f"val_{i}") for i in range(random.randint(1, 5))]
            type_node.args["expressions"] = vals


def _fuzz_table_properties(properties):
    """Mutate table-level properties (ENGINE, ROW_FORMAT, etc.)."""
    if not hasattr(properties, 'expressions'):
        return

    for prop in (properties.expressions or []):
        if isinstance(prop, exp.EngineProperty) and chance(Prob.CHANGE_ENGINE):
            prop.args["this"] = exp.Literal.string(pick(STORAGE_ENGINES))
        elif isinstance(prop, exp.Property):
            name = str(prop.args.get("this", "")).upper()
            if "ROW_FORMAT" in name and chance(Prob.CHANGE_ROW_FORMAT):
                prop.args["value"] = exp.Literal.string(pick(INNODB_ROW_FORMATS))
            elif "KEY_BLOCK_SIZE" in name and chance(Prob.CHANGE_COMPRESSION):
                prop.args["value"] = exp.Literal.number(pick(INNODB_KEY_BLOCK_SIZES))
            elif "CHARSET" in name and chance(Prob.CHANGE_CHARSET):
                prop.args["value"] = exp.Literal.string(pick(CHARSETS))


def _add_innodb_properties(node):
    """Add InnoDB-specific table properties."""
    props = []

    if chance(3):
        props.append(exp.Property(
            this=exp.Literal.string("ROW_FORMAT"),
            value=exp.Literal.string(pick(INNODB_ROW_FORMATS)),
        ))
    if chance(3):
        props.append(exp.Property(
            this=exp.Literal.string("KEY_BLOCK_SIZE"),
            value=exp.Literal.number(pick(INNODB_KEY_BLOCK_SIZES)),
        ))
    if chance(3):
        props.append(exp.Property(
            this=exp.Literal.string("COMPRESSION"),
            value=exp.Literal.string(pick(INNODB_COMPRESSION_ALGORITHMS)),
        ))

    if props:
        existing = node.args.get("properties")
        if existing and hasattr(existing, 'expressions'):
            existing.expressions.extend(props)
        else:
            node.args["properties"] = exp.Properties(expressions=props)


# ===================================================================
# DML mutations (INSERT, UPDATE, DELETE)
# ===================================================================

def fuzz_insert(node, pool):
    """Mutate an INSERT statement."""
    if not isinstance(node, exp.Insert):
        return node

    # Fuzz values in the insert
    expr = node.args.get("expression")
    if isinstance(expr, exp.Values):
        for tup in (expr.expressions or []):
            if isinstance(tup, exp.Tuple):
                for i, val in enumerate(tup.expressions):
                    if isinstance(val, exp.Literal) and chance(5):
                        tup.expressions[i] = fuzz_literal(val)
                    elif chance(Prob.REPLACE_WITH_NULL):
                        tup.expressions[i] = exp.Null()

    # Toggle IGNORE
    if chance(20):
        # Insert OR IGNORE / INSERT IGNORE
        pass  # sqlglot handles this via overwrite arg

    return node


def fuzz_update(node, pool):
    """Mutate an UPDATE statement."""
    if not isinstance(node, exp.Update):
        return node

    # Fuzz SET values
    set_exprs = node.args.get("expressions") or []
    for eq in set_exprs:
        if isinstance(eq, exp.EQ):
            val = eq.args.get("expression")
            if isinstance(val, exp.Literal) and chance(5):
                eq.args["expression"] = fuzz_literal(val)
            elif chance(Prob.REPLACE_WITH_NULL):
                eq.args["expression"] = exp.Null()

    # Fuzz WHERE
    where = node.args.get("where")
    if where and chance(20):
        new_pred = _generate_predicate(pool)
        if new_pred:
            node.args["where"] = exp.Where(this=new_pred)

    return node


def fuzz_delete(node, pool):
    """Mutate a DELETE statement."""
    if not isinstance(node, exp.Delete):
        return node

    # Fuzz WHERE
    where = node.args.get("where")
    if where and chance(20):
        new_pred = _generate_predicate(pool)
        if new_pred:
            node.args["where"] = exp.Where(this=new_pred)

    # Remove WHERE (dangerous but interesting for fuzzing)
    if where and chance(100):
        node.args["where"] = None

    return node


# ===================================================================
# Advanced structural mutations
# ===================================================================

def inject_subquery_in_select(node, pool):
    """Wrap a SELECT column in a scalar subquery."""
    if not isinstance(node, exp.Select):
        return node

    expressions = node.expressions
    if not expressions or not chance(Prob.WRAP_IN_SUBQUERY):
        return node

    idx = random.randint(0, len(expressions) - 1)
    col = pool.get_column_name()
    tbl = pool.get_table_name()

    subq = exp.Select(
        expressions=[exp.Anonymous(
            this=pick(["MAX", "MIN", "COUNT", "SUM", "AVG"]),
            expressions=[exp.Column(this=exp.to_identifier(col))]
        )],
    ).from_(exp.Table(this=exp.to_identifier(tbl)))

    expressions[idx] = exp.Subquery(this=subq, alias=exp.TableAlias(this=exp.to_identifier(f"sq_{random.randint(0,99)}")))
    return node


def inject_union(node, pool):
    """Add a UNION/UNION ALL with another SELECT."""
    if not isinstance(node, exp.Select) or not chance(Prob.INJECT_UNION):
        return node

    col = pool.get_column_like()
    tbl = pool.get_table_name()
    if not col:
        col = exp.Literal.number(1)

    other = exp.Select(
        expressions=[col],
    ).from_(exp.Table(this=exp.to_identifier(tbl)))

    union_type = random.choice(["UNION", "UNION ALL", "EXCEPT", "INTERSECT"])

    if union_type == "UNION ALL":
        return exp.Union(this=node, expression=other, distinct=False)
    elif union_type == "UNION":
        return exp.Union(this=node, expression=other, distinct=True)
    elif union_type == "EXCEPT":
        return exp.Except(this=node, expression=other)
    else:
        return exp.Intersect(this=node, expression=other)


def wrap_in_case(node, pool):
    """Wrap an expression in a CASE WHEN."""
    if not chance(Prob.WRAP_IN_CASE):
        return node

    col = pool.get_column_name()
    pred = exp.Is(this=exp.Column(this=exp.to_identifier(col)), expression=exp.Null())

    return exp.Case(
        ifs=[exp.If(this=pred, true=node.copy())],
        default=exp.Null(),
    )


# ===================================================================
# Transaction / session mutations (MariaDB specific)
# ===================================================================

def generate_transaction_statement():
    """Generate a random transaction-related statement."""
    from config import ISOLATION_LEVELS

    action = random.randint(0, 8)

    if action == 0:
        return "BEGIN"
    elif action == 1:
        return "COMMIT"
    elif action == 2:
        return "ROLLBACK"
    elif action == 3:
        name = f"sp_{random.randint(0, 99)}"
        return f"SAVEPOINT {name}"
    elif action == 4:
        name = f"sp_{random.randint(0, 99)}"
        return f"ROLLBACK TO SAVEPOINT {name}"
    elif action == 5:
        name = f"sp_{random.randint(0, 99)}"
        return f"RELEASE SAVEPOINT {name}"
    elif action == 6:
        level = pick(ISOLATION_LEVELS)
        return f"SET TRANSACTION ISOLATION LEVEL {level}"
    elif action == 7:
        return f"SET autocommit = {random.choice([0, 1])}"
    else:
        return f"SET innodb_lock_wait_timeout = {pick([0, 1, 5, 50, 1073741824])}"


# ===================================================================
# ALTER TABLE mutations (InnoDB-focused)
# ===================================================================

def generate_alter_table(pool):
    """Generate a random ALTER TABLE statement for InnoDB stress testing."""
    tbl = pool.get_table_name()
    col = pool.get_column_name()
    new_col = f"fz_col_{random.randint(0, 999)}"

    actions = [
        f"ALTER TABLE {tbl} ADD COLUMN {new_col} {pick(ALL_COLUMN_TYPES)}",
        f"ALTER TABLE {tbl} DROP COLUMN {col}",
        f"ALTER TABLE {tbl} MODIFY COLUMN {col} {pick(ALL_COLUMN_TYPES)}",
        f"ALTER TABLE {tbl} CHANGE COLUMN {col} {new_col} {pick(ALL_COLUMN_TYPES)}",
        f"ALTER TABLE {tbl} ADD INDEX idx_{random.randint(0,999)} ({col})",
        f"ALTER TABLE {tbl} DROP INDEX idx_{random.randint(0,999)}",
        f"ALTER TABLE {tbl} ENGINE={pick(STORAGE_ENGINES)}",
        f"ALTER TABLE {tbl} ROW_FORMAT={pick(INNODB_ROW_FORMATS)}",
        f"ALTER TABLE {tbl} KEY_BLOCK_SIZE={pick(INNODB_KEY_BLOCK_SIZES)}",
        f"ALTER TABLE {tbl} ADD PRIMARY KEY ({col})",
        f"ALTER TABLE {tbl} DROP PRIMARY KEY",
        f"ALTER TABLE {tbl} AUTO_INCREMENT={pick(BAD_INTEGERS)}",
        f"ALTER TABLE {tbl} CONVERT TO CHARACTER SET {pick(CHARSETS)}",
        f"ALTER TABLE {tbl} FORCE",
        f"ALTER TABLE {tbl} ALGORITHM={pick(['INPLACE', 'COPY', 'INSTANT', 'NOCOPY', 'DEFAULT'])}",
        f"ALTER TABLE {tbl} LOCK={pick(['NONE', 'SHARED', 'EXCLUSIVE', 'DEFAULT'])}",
        f"ALTER TABLE {tbl} ADD PARTITION (PARTITION p_{random.randint(0,99)} VALUES LESS THAN ({pick(BAD_INTEGERS)}))",
        f"ALTER TABLE {tbl} REORGANIZE PARTITION",
        f"ALTER TABLE {tbl} OPTIMIZE PARTITION ALL",
    ]
    return pick(actions)
