"""
Configuration for the MariaDB AST Fuzzer.
Probability constants, boundary values, and function swap groups.
"""

import random

# ---------------------------------------------------------------------------
# Probability constants (1/N chance) — higher N = rarer mutation
# ---------------------------------------------------------------------------

class Prob:
    # Structural mutations
    TOGGLE_DISTINCT = 50
    ADD_WHERE = 50
    REMOVE_WHERE = 50
    REPLACE_WHERE = 50
    ADD_GROUP_BY = 50
    REMOVE_GROUP_BY = 50
    ADD_ORDER_BY = 50
    REMOVE_ORDER_BY = 50
    ADD_HAVING = 50
    REMOVE_HAVING = 50
    ADD_LIMIT = 50
    REMOVE_LIMIT = 50
    TOGGLE_FOR_UPDATE = 50
    TOGGLE_LOCK_IN_SHARE = 50

    # Expression list mutations
    SHUFFLE_LIST = 20
    REMOVE_ELEMENT = 50
    ADD_ELEMENT = 50

    # Function swap
    SWAP_FUNCTION = 20
    SWAP_AGGREGATE = 20

    # Literal mutations
    REPLACE_WITH_NULL = 20
    TYPE_CROSSOVER = 20

    # JOIN mutations
    ADD_JOIN = 50
    REMOVE_JOIN = 50
    CHANGE_JOIN_TYPE = 20

    # DDL / InnoDB mutations
    CHANGE_ENGINE = 30
    CHANGE_ROW_FORMAT = 30
    CHANGE_CHARSET = 50
    ADD_INDEX = 50
    TOGGLE_NULLABLE = 30
    SWAP_DATA_TYPE = 20
    CHANGE_COMPRESSION = 30

    # Transaction mutations
    ADD_SAVEPOINT = 100
    TOGGLE_AUTOCOMMIT = 100

    # Wrapping mutations
    WRAP_IN_SUBQUERY = 1500
    WRAP_IN_FUNCTION = 1000
    WRAP_IN_CASE = 1000
    INJECT_UNION = 200
    ADD_SUBQUERY_IN_WHERE = 200


# ---------------------------------------------------------------------------
# Boundary / "bad" values
# ---------------------------------------------------------------------------

BAD_INTEGERS = [
    -2, -1, 0, 1, 2, 3, 7, 10, 100, 255, 256, 1023, 1024,
    65535, 65536, 2147483647, 2147483648, -2147483648, -2147483649,
    9223372036854775807, -9223372036854775808,
    18446744073709551615,  # UINT64_MAX
]

BAD_FLOATS = [
    0.0, -0.0, 0.0001, 0.5, 0.9999, 1.0, -1.0,
    1e-10, 1e10, 1e38, -1e38, 1e308, -1e308,
    float('inf'), float('-inf'), float('nan'),
]

BAD_STRINGS = [
    "", " ", "NULL", "null", "0", "-1", "1",
    "'" , "''", "\\", "\x00",
    "a" * 255, "a" * 256, "a" * 65535,
    "2024-01-01", "2024-13-32", "0000-00-00",
    "9999-12-31 23:59:59", "0000-00-00 00:00:00",
    "00:00:00", "25:61:61",
    "%", "_", "%test%", "_test_",
    "1; DROP TABLE t1; --",
    "Robert'); DROP TABLE students;--",
    # Removed invalid UTF-8/BOM/zero-width — they produce binary in .sql files
    # that break the mariadb client during replay
    "{}",  '{"key": "value"}', "[]", '[1,2,3]',
    "CURRENT_TIMESTAMP", "NOW()",
    "TRUE", "FALSE",
]

BAD_DATES = [
    "0000-00-00", "0000-01-01", "1000-01-01", "1970-01-01",
    "2000-02-29", "2001-02-29",  # leap year edge
    "2038-01-19", "2038-01-20",  # Y2K38
    "9999-12-31", "1969-12-31",
]

BAD_DATETIMES = [
    "0000-00-00 00:00:00", "1970-01-01 00:00:00",
    "2038-01-19 03:14:07", "2038-01-19 03:14:08",
    "9999-12-31 23:59:59",
    "1000-01-01 00:00:00.000000",
]

# ---------------------------------------------------------------------------
# MariaDB function equivalence groups for swapping
# ---------------------------------------------------------------------------

FUNCTION_SWAP_GROUPS = [
    # String functions
    ["UPPER", "LOWER", "REVERSE", "TRIM", "LTRIM", "RTRIM", "LCASE", "UCASE"],
    ["LENGTH", "CHAR_LENGTH", "CHARACTER_LENGTH", "OCTET_LENGTH", "BIT_LENGTH"],
    ["CONCAT", "CONCAT_WS"],
    ["LEFT", "RIGHT"],
    ["LPAD", "RPAD"],
    ["LOCATE", "INSTR", "POSITION"],
    ["REPLACE", "INSERT"],
    ["SUBSTRING", "SUBSTR", "MID"],

    # Numeric functions
    ["ABS", "CEIL", "CEILING", "FLOOR", "ROUND", "TRUNCATE", "SIGN"],
    ["SQRT", "LN", "LOG", "LOG2", "LOG10", "EXP"],
    ["SIN", "COS", "TAN", "COT", "ASIN", "ACOS", "ATAN"],
    ["MOD", "DIV"],
    ["RAND", "UUID", "UUID_SHORT"],
    ["GREATEST", "LEAST"],

    # Date functions
    ["NOW", "CURRENT_TIMESTAMP", "SYSDATE", "LOCALTIME", "LOCALTIMESTAMP"],
    ["CURDATE", "CURRENT_DATE"],
    ["CURTIME", "CURRENT_TIME"],
    ["YEAR", "MONTH", "DAY", "DAYOFMONTH", "DAYOFWEEK", "DAYOFYEAR",
     "HOUR", "MINUTE", "SECOND", "MICROSECOND", "QUARTER", "WEEK"],
    ["DATE_ADD", "DATE_SUB", "ADDDATE", "SUBDATE"],
    ["DATEDIFF", "TIMESTAMPDIFF", "TIMEDIFF"],
    ["DATE_FORMAT", "TIME_FORMAT"],
    ["STR_TO_DATE", "FROM_UNIXTIME", "UNIX_TIMESTAMP"],

    # Comparison / logic
    ["IF", "IFNULL", "NULLIF", "COALESCE"],
    ["ISNULL", "IS NOT NULL"],

    # Pattern matching
    ["LIKE", "NOT LIKE", "REGEXP", "NOT REGEXP", "RLIKE"],

    # Encryption / hash
    ["MD5", "SHA1", "SHA2", "CRC32"],
    ["AES_ENCRYPT", "AES_DECRYPT"],

    # Type conversion
    ["CAST", "CONVERT"],

    # JSON functions (MariaDB 10.2+)
    ["JSON_EXTRACT", "JSON_VALUE", "JSON_QUERY"],
    ["JSON_SET", "JSON_INSERT", "JSON_REPLACE", "JSON_REMOVE"],
    ["JSON_ARRAY", "JSON_OBJECT"],
    ["JSON_CONTAINS", "JSON_CONTAINS_PATH", "JSON_OVERLAPS"],
    ["JSON_LENGTH", "JSON_DEPTH", "JSON_TYPE", "JSON_VALID"],

    # Misc
    ["BENCHMARK", "SLEEP"],
    ["VERSION", "DATABASE", "USER", "CURRENT_USER", "SYSTEM_USER", "SESSION_USER"],
    ["CONNECTION_ID", "LAST_INSERT_ID", "ROW_COUNT", "FOUND_ROWS"],
]

# Build lookup: function_name -> list of alternatives
FUNCTION_SWAP_MAP = {}
for group in FUNCTION_SWAP_GROUPS:
    for fn in group:
        FUNCTION_SWAP_MAP[fn.upper()] = [f for f in group if f.upper() != fn.upper()]

# ---------------------------------------------------------------------------
# Aggregate function equivalence groups
# ---------------------------------------------------------------------------

AGGREGATE_SWAP_GROUPS = [
    # Single-arg aggregates
    ["COUNT", "SUM", "AVG", "MIN", "MAX",
     "BIT_AND", "BIT_OR", "BIT_XOR",
     "STD", "STDDEV", "STDDEV_POP", "STDDEV_SAMP",
     "VAR_POP", "VAR_SAMP", "VARIANCE",
     "ANY_VALUE",
     "GROUP_CONCAT"],

    # Two-arg aggregates (not many in MariaDB)
    ["PERCENTILE_CONT", "PERCENTILE_DISC"],
]

AGGREGATE_SWAP_MAP = {}
for group in AGGREGATE_SWAP_GROUPS:
    for fn in group:
        AGGREGATE_SWAP_MAP[fn.upper()] = [f for f in group if f.upper() != fn.upper()]

ALL_AGGREGATES = set()
for group in AGGREGATE_SWAP_GROUPS:
    for fn in group:
        ALL_AGGREGATES.add(fn.upper())

# ---------------------------------------------------------------------------
# MariaDB data types for fuzzing DDL
# ---------------------------------------------------------------------------

INTEGER_TYPES = ["TINYINT", "SMALLINT", "MEDIUMINT", "INT", "BIGINT"]
FLOAT_TYPES = ["FLOAT", "DOUBLE", "DECIMAL"]
STRING_TYPES = ["CHAR", "VARCHAR", "TINYTEXT", "TEXT", "MEDIUMTEXT", "LONGTEXT"]
BINARY_TYPES = ["BINARY", "VARBINARY", "TINYBLOB", "BLOB", "MEDIUMBLOB", "LONGBLOB"]
DATE_TYPES = ["DATE", "TIME", "DATETIME", "TIMESTAMP", "YEAR"]
OTHER_TYPES = ["ENUM", "SET", "JSON", "BIT", "BOOLEAN"]

ALL_COLUMN_TYPES = INTEGER_TYPES + FLOAT_TYPES + STRING_TYPES + BINARY_TYPES + DATE_TYPES + OTHER_TYPES

# ---------------------------------------------------------------------------
# InnoDB-specific options
# ---------------------------------------------------------------------------

INNODB_ROW_FORMATS = ["REDUNDANT", "COMPACT", "DYNAMIC", "COMPRESSED"]
INNODB_KEY_BLOCK_SIZES = [0, 1, 2, 4, 8, 16]
INNODB_PAGE_SIZES = [4096, 8192, 16384, 32768, 65536]
INNODB_COMPRESSION_ALGORITHMS = ["none", "zlib", "lz4", "lzma", "bzip2", "snappy"]

STORAGE_ENGINES = ["InnoDB"]

CHARSETS = ["utf8mb4", "utf8mb3", "latin1", "binary", "ascii", "utf16", "utf32"]
COLLATIONS = [
    "utf8mb4_general_ci", "utf8mb4_unicode_ci", "utf8mb4_bin",
    "latin1_swedish_ci", "latin1_bin", "binary",
]

# ---------------------------------------------------------------------------
# MariaDB isolation levels and transaction options
# ---------------------------------------------------------------------------

ISOLATION_LEVELS = [
    "READ UNCOMMITTED", "READ COMMITTED",
    "REPEATABLE READ", "SERIALIZABLE",
]

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def chance(n):
    """Return True with probability 1/n."""
    return random.randint(1, n) == 1


def pick(lst):
    """Pick a random element from a list."""
    if not lst:
        return None
    return random.choice(lst)
