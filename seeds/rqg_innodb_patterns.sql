-- =============================================================================
-- RQG-derived InnoDB seed patterns for AST fuzzer
-- Extracted from MariaDB RQG grammar files (.yy)
-- Sources:
--   conf/mariadb/table_stress_innodb.yy
--   conf/mariadb/table_stress_innodb_basic.yy
--   conf/mariadb/table_stress_innodb_dml.yy
--   conf/mariadb/concurrency_innodb.yy
--   conf/mariadb/partitions_innodb.yy
--   conf/mariadb/oltp.yy
--   conf/engines/innodb/full_text_search.yy
-- =============================================================================

-- =============================================
-- SECTION 1: CREATE TABLE - InnoDB ROW_FORMAT variants
-- =============================================

CREATE TABLE IF NOT EXISTS t1 (
  col1 INT,
  col2 INT,
  col_int INTEGER,
  col_string VARCHAR(20),
  col_varchar VARCHAR(500),
  col_text TEXT
) ENGINE = InnoDB ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS t2 (
  col1 INT,
  col2 INT,
  col_int INTEGER,
  col_string CHAR(19),
  col_varchar VARCHAR(500),
  col_text TEXT
) ENGINE = InnoDB ROW_FORMAT = Compressed;

CREATE TABLE IF NOT EXISTS t3 (
  col1 INT,
  col2 INT,
  col_int INTEGER,
  col_string VARCHAR(20),
  col_varchar VARCHAR(500),
  col_text TEXT
) ENGINE = InnoDB ROW_FORMAT = Compact;

CREATE TABLE IF NOT EXISTS t4 (
  col1 INT,
  col2 INT,
  col_int INTEGER,
  col_string CHAR(20),
  col_varchar VARCHAR(500),
  col_text TEXT
) ENGINE = InnoDB ROW_FORMAT = Redundant;

-- InnoDB with encryption
CREATE TABLE IF NOT EXISTS t5 (
  col1 INT,
  col2 INT,
  col_int INTEGER,
  col_string VARCHAR(19),
  col_varchar VARCHAR(500),
  col_text TEXT
) ENGINE = InnoDB ROW_FORMAT = Compact ENCRYPTED=YES ENCRYPTION_KEY_ID=1;

-- InnoDB with page compression
CREATE TABLE IF NOT EXISTS t6 (
  col1 INT,
  col2 INT,
  col_int INTEGER,
  col_string VARCHAR(20),
  col_varchar VARCHAR(500),
  col_text TEXT
) ENGINE = InnoDB ROW_FORMAT = Compact PAGE_COMPRESSED=1;

-- InnoDB with page compression + encryption
CREATE TABLE IF NOT EXISTS t7 (
  col1 INT,
  col2 INT,
  col_int INTEGER,
  col_string CHAR(19),
  col_varchar VARCHAR(500),
  col_text TEXT
) ENGINE = InnoDB ROW_FORMAT = Compact PAGE_COMPRESSED=1 ENCRYPTED=YES ENCRYPTION_KEY_ID=33;

-- =============================================
-- SECTION 2: CREATE TABLE with generated/virtual columns
-- =============================================

CREATE TABLE IF NOT EXISTS t1_gcol (
  col1 INT,
  col2 INT,
  col_int INTEGER,
  col_string VARCHAR(20),
  col_varchar VARCHAR(500),
  col_text TEXT,
  col_int_g INTEGER GENERATED ALWAYS AS (col_int) VIRTUAL,
  col_string_g VARCHAR(13) GENERATED ALWAYS AS (SUBSTR(RTRIM(col_string),4,13)) PERSISTENT,
  col_text_g TEXT GENERATED ALWAYS AS (SUBSTR(col_text,1,499)) VIRTUAL
) ENGINE = InnoDB ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS t2_gcol (
  col1 INT,
  col2 INT,
  col_int INTEGER,
  col_string CHAR(19),
  col_varchar VARCHAR(500),
  col_text TEXT,
  col_int_g INTEGER GENERATED ALWAYS AS (col_int) PERSISTENT,
  col_string_g CHAR(12) GENERATED ALWAYS AS (SUBSTR(RTRIM(col_string),4,12)) VIRTUAL,
  col_text_g TEXT GENERATED ALWAYS AS (SUBSTR(col_text,1,499)) PERSISTENT
) ENGINE = InnoDB ROW_FORMAT = Compressed;

CREATE TABLE IF NOT EXISTS t3_gcol (
  col1 INT PRIMARY KEY,
  col2 INT,
  col_int INTEGER,
  col_string VARCHAR(20),
  col_varchar VARCHAR(500),
  col_text TEXT,
  col_int_g INTEGER GENERATED ALWAYS AS (col_int) VIRTUAL,
  col_varchar_g VARCHAR(500) GENERATED ALWAYS AS (SUBSTR(col_varchar,1,499)) VIRTUAL
) ENGINE = InnoDB ROW_FORMAT = Compact;

-- =============================================
-- SECTION 3: CREATE TABLE with PRIMARY KEY (from table_stress_innodb_basic)
-- =============================================

CREATE TABLE IF NOT EXISTS t1_pk (
  col1 INT PRIMARY KEY,
  col2 INT,
  col_int INTEGER,
  col_string VARCHAR(19),
  col_varchar VARCHAR(500),
  col_text TEXT
) ENGINE = InnoDB ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS t2_pk (
  col1 INT PRIMARY KEY,
  col2 INT,
  col_int INTEGER,
  col_string CHAR(20),
  col_varchar VARCHAR(500),
  col_text TEXT,
  col_int_g INTEGER GENERATED ALWAYS AS (col_int) VIRTUAL,
  col_string_g VARCHAR(12) GENERATED ALWAYS AS (SUBSTR(RTRIM(col_string),4,12)) PERSISTENT,
  col_text_g TEXT GENERATED ALWAYS AS (SUBSTR(col_text,1,499)) VIRTUAL
) ENGINE = InnoDB ROW_FORMAT = Compressed;

-- =============================================
-- SECTION 4: CREATE TABLE - Partitioned tables (from partitions_innodb.yy)
-- =============================================

CREATE TABLE IF NOT EXISTS t1_part (
  `col_int_nokey` INTEGER,
  `col_int_key` INTEGER NOT NULL,
  KEY (`col_int_key`)
) ENGINE = InnoDB
PARTITION BY RANGE (`col_int_nokey`) (
  PARTITION p0 VALUES LESS THAN (3),
  PARTITION p1 VALUES LESS THAN (100),
  PARTITION p2 VALUES LESS THAN (1000),
  PARTITION p3 VALUES LESS THAN MAXVALUE
);

CREATE TABLE IF NOT EXISTS t2_part (
  `col_int_nokey` INTEGER,
  `col_int_key` INTEGER NOT NULL,
  KEY (`col_int_key` ASC)
) ENGINE = InnoDB
PARTITION BY LIST (`col_int_nokey`) (
  PARTITION p0 VALUES IN (0, NULL),
  PARTITION p1 VALUES IN (1, 2, 3),
  PARTITION p2 VALUES IN (4, 5, 6),
  PARTITION p3 VALUES IN (7, 8, 9)
);

CREATE TABLE IF NOT EXISTS t3_part (
  `col_int_nokey` INTEGER,
  `col_int_key` INTEGER NOT NULL,
  KEY (`col_int_key` DESC)
) ENGINE = InnoDB
PARTITION BY HASH (`col_int_nokey`) PARTITIONS 4;

CREATE TABLE IF NOT EXISTS t4_part (
  `col_int_nokey` INTEGER,
  `col_int_key` INTEGER NOT NULL,
  KEY (`col_int_key`)
) ENGINE = InnoDB
PARTITION BY LINEAR HASH (`col_int_nokey`) PARTITIONS 3;

CREATE TABLE IF NOT EXISTS t5_part (
  `col_int_nokey` INTEGER,
  `col_int_key` INTEGER NOT NULL,
  KEY (`col_int_key`)
) ENGINE = InnoDB
PARTITION BY KEY (`col_int_key`) PARTITIONS 2;

CREATE TABLE IF NOT EXISTS t6_part (
  `col_int_nokey` INTEGER,
  `col_int_key` INTEGER NOT NULL,
  KEY (`col_int_key`)
) ENGINE = InnoDB
PARTITION BY RANGE (`col_int_nokey`)
SUBPARTITION BY HASH (`col_int_nokey`) SUBPARTITIONS 2 (
  PARTITION p0 VALUES LESS THAN (3),
  PARTITION p1 VALUES LESS THAN (100),
  PARTITION p2 VALUES LESS THAN (1000),
  PARTITION p3 VALUES LESS THAN MAXVALUE
);

-- Non-partitioned comparison table
CREATE TABLE IF NOT EXISTS t1_nopart (
  `col_int_nokey` INTEGER,
  `col_int_key` INTEGER NOT NULL,
  KEY (`col_int_key`)
) ENGINE = InnoDB;

-- CREATE TABLE ... AS SELECT
CREATE TABLE IF NOT EXISTS t1_ctas ENGINE = InnoDB
PARTITION BY KEY (col1) PARTITIONS 2
AS SELECT * FROM t1;

-- CREATE TABLE with concurrency.yy patterns
CREATE TABLE IF NOT EXISTS t1_conc LIKE t1;
ALTER TABLE t1_conc ENGINE = InnoDB;
INSERT INTO t1_conc SELECT * FROM t1;

-- =============================================
-- SECTION 5: ALTER TABLE - ADD/DROP index patterns (from table_stress_innodb.yy)
-- =============================================

-- Add unique index
ALTER TABLE t1 ADD UNIQUE INDEX IF NOT EXISTS uidx1 (col1);
ALTER TABLE t1 ADD UNIQUE KEY IF NOT EXISTS uidx2 (col2, col_int);
ALTER TABLE t1 ADD UNIQUE INDEX IF NOT EXISTS uidx3 (col_string(9));

-- Add regular index
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int);
ALTER TABLE t1 ADD KEY IF NOT EXISTS idx2 (col_varchar(9));
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx3 (col1, col_string(9));

-- Add primary key
ALTER TABLE t1 ADD PRIMARY KEY IF NOT EXISTS (col1);
ALTER TABLE t1 ADD PRIMARY KEY IF NOT EXISTS (col1, col2);

-- Add fulltext index
ALTER TABLE t1 ADD FULLTEXT INDEX IF NOT EXISTS ftidx1 (col_text);
ALTER TABLE t1 ADD FULLTEXT KEY IF NOT EXISTS ftidx2 (col_varchar);
ALTER TABLE t1 ADD FULLTEXT INDEX IF NOT EXISTS ftidx3 (col_text, col_varchar);

-- Drop indexes
ALTER TABLE t1 DROP INDEX uidx1;
ALTER TABLE t1 DROP KEY idx1;
ALTER TABLE t1 DROP INDEX ftidx1;
ALTER TABLE t1 DROP PRIMARY KEY;

-- Combined add + drop
ALTER TABLE t1 DROP INDEX idx1, ADD INDEX IF NOT EXISTS idx1 (col2);
ALTER TABLE t1 DROP KEY uidx1, ADD UNIQUE KEY IF NOT EXISTS uidx1 (col1, col2);
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx2 (col_int), ADD UNIQUE INDEX IF NOT EXISTS uidx2 (col2);

-- =============================================
-- SECTION 6: ALTER TABLE - ALGORITHM and LOCK options (from table_stress_innodb.yy)
-- =============================================

ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int), ALGORITHM = DEFAULT;
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int), ALGORITHM = INSTANT;
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int), ALGORITHM = NOCOPY;
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int), ALGORITHM = INPLACE;
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int), ALGORITHM = COPY;

ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int), LOCK = DEFAULT;
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int), LOCK = NONE;
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int), LOCK = SHARED;
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int), LOCK = EXCLUSIVE;

-- Combined ALGORITHM + LOCK
ALTER TABLE t1 ADD UNIQUE INDEX IF NOT EXISTS uidx1 (col1), ALGORITHM = INPLACE, LOCK = NONE;
ALTER TABLE t1 ADD INDEX IF NOT EXISTS idx1 (col_int), ALGORITHM = COPY, LOCK = SHARED;
ALTER TABLE t1 DROP INDEX idx1, ALGORITHM = INSTANT, LOCK = EXCLUSIVE;
ALTER TABLE t1 ADD PRIMARY KEY IF NOT EXISTS (col1), LOCK = EXCLUSIVE, ALGORITHM = COPY;

-- =============================================
-- SECTION 7: ALTER TABLE - MODIFY/CHANGE column (from table_stress_innodb.yy)
-- =============================================

ALTER TABLE t1 MODIFY COLUMN col_string VARCHAR(20) CHARACTER SET latin1 COLLATE latin1_bin;
ALTER TABLE t1 MODIFY COLUMN col_text TEXT CHARACTER SET utf8 COLLATE utf8_general_ci;
ALTER TABLE t1 MODIFY COLUMN col_varchar VARCHAR(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
ALTER TABLE t1 MODIFY COLUMN col_string CHAR(19) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci;

-- Move column position
ALTER TABLE t1 MODIFY COLUMN col_int INTEGER FIRST;
ALTER TABLE t1 MODIFY COLUMN col_string VARCHAR(20) AFTER col1;
ALTER TABLE t1 MODIFY COLUMN col_text TEXT AFTER col_int;

-- NULL/NOT NULL changes
ALTER TABLE t1 MODIFY COLUMN col_int INTEGER NULL;
ALTER TABLE t1 MODIFY COLUMN col_int INTEGER NOT NULL;

-- Change column type
ALTER TABLE t1 MODIFY COLUMN col_int INT, ALGORITHM = NOCOPY;
ALTER TABLE t1 MODIFY COLUMN col_int BIGINT, ALGORITHM = INPLACE, LOCK = NONE;

-- CHANGE COLUMN (rename)
ALTER TABLE t1 CHANGE COLUMN IF EXISTS col_int my_col_int INTEGER;
ALTER TABLE t1 CHANGE COLUMN IF EXISTS my_col_int col_int INTEGER;
ALTER TABLE t1 CHANGE COLUMN col_int col_int BIGINT;
ALTER TABLE t1 CHANGE COLUMN col_int col_int INTEGER;

-- ADD COLUMN (replace_column pattern)
ALTER TABLE t1 ADD COLUMN IF NOT EXISTS col_int_copy INTEGER FIRST, ALGORITHM = INPLACE, LOCK = NONE;
UPDATE t1 SET col_int_copy = col_int;
ALTER TABLE t1 DROP COLUMN IF EXISTS col_int, ALGORITHM = INPLACE, LOCK = NONE;
ALTER TABLE t1 CHANGE COLUMN IF EXISTS col_int_copy col_int INTEGER, ALGORITHM = INPLACE, LOCK = NONE;

-- chaos_column pattern: ADD/DROP/MODIFY ephemeral column
ALTER TABLE t1 ADD COLUMN IF NOT EXISTS col_date DATE DEFAULT CURDATE();
ALTER TABLE t1 DROP COLUMN IF EXISTS col_date;
ALTER TABLE t1 MODIFY COLUMN IF EXISTS col_date DATE FIRST;
ALTER TABLE t1 MODIFY COLUMN IF EXISTS col_date DATE AFTER col1;

-- Column default changes (from concurrency_innodb.yy)
ALTER TABLE t1 MODIFY COLUMN col_int INTEGER DEFAULT 13;
ALTER TABLE t1 MODIFY COLUMN col_int INTEGER DEFAULT NULL;
ALTER TABLE t1 ADD COLUMN extra INTEGER DEFAULT 13;
ALTER TABLE t1 DROP COLUMN extra;

-- =============================================
-- SECTION 8: ALTER TABLE - Partition operations (from partitions_innodb.yy)
-- =============================================

ALTER TABLE t1_part ADD PARTITION (PARTITION p4 VALUES LESS THAN MAXVALUE);
ALTER TABLE t1_part DROP PARTITION p0;
ALTER TABLE t1_part COALESCE PARTITION 1;
ALTER TABLE t1_part COALESCE PARTITION 2;

ALTER TABLE t1_part ANALYZE PARTITION p0,p1;
ALTER TABLE t1_part CHECK PARTITION p0,p1,p2;
ALTER TABLE t1_part REBUILD PARTITION p1,p2;
ALTER TABLE t1_part REPAIR PARTITION p0,p1,p2,p3;
ALTER TABLE t1_part OPTIMIZE PARTITION p0,p1;
ALTER TABLE t1_part TRUNCATE PARTITION p0;
ALTER TABLE t1_part TRUNCATE PARTITION p1,p2;

ALTER TABLE t1_part REMOVE PARTITIONING;
ALTER TABLE t1_part REORGANIZE PARTITION p0,p1,p2,p3 INTO (
  PARTITION p0 VALUES LESS THAN (5),
  PARTITION p1 VALUES LESS THAN (50),
  PARTITION p2 VALUES LESS THAN (500),
  PARTITION p3 VALUES LESS THAN MAXVALUE
);

-- Re-partition
ALTER TABLE t1_part PARTITION BY RANGE (`col_int_nokey`) (
  PARTITION p0 VALUES LESS THAN (3),
  PARTITION p1 VALUES LESS THAN (100),
  PARTITION p2 VALUES LESS THAN (1000),
  PARTITION p3 VALUES LESS THAN MAXVALUE
);
ALTER TABLE t1_part PARTITION BY KEY (`col_int_key`) PARTITIONS 2;
ALTER TABLE t1_part PARTITION BY LINEAR HASH (`col_int_nokey`) PARTITIONS 3;

ALTER TABLE t1_part ENABLE KEYS;
ALTER TABLE t1_part DISABLE KEYS;

ALTER TABLE t1_part ENGINE = InnoDB;

-- EXCHANGE PARTITION
ALTER TABLE t1_part EXCHANGE PARTITION p0 WITH TABLE t1_nopart;

-- =============================================
-- SECTION 9: ALTER TABLE - Misc (from table_stress_innodb.yy, concurrency.yy)
-- =============================================

ALTER TABLE t1 ENGINE = InnoDB ROW_FORMAT = Dynamic;
ALTER TABLE t1 ENGINE = InnoDB ROW_FORMAT = Compressed;
ALTER TABLE t1 ENGINE = InnoDB ROW_FORMAT = Compact;
ALTER TABLE t1 ENGINE = InnoDB ROW_FORMAT = Redundant;
ALTER TABLE t1 ENGINE = InnoDB ROW_FORMAT = DEFAULT;

ALTER TABLE t1 ENABLE KEYS;
ALTER TABLE t1 DISABLE KEYS;

ALTER IGNORE TABLE t1 ADD UNIQUE INDEX IF NOT EXISTS uidx1 (col1);
ALTER IGNORE TABLE t1 MODIFY COLUMN col_int INTEGER NOT NULL;

ALTER TABLE t1 COMMENT = 'UPDATED to 5';
ALTER TABLE t1 RENAME TO t1_renamed;

-- RENAME TABLE
RENAME TABLE t1 TO t1_new;
RENAME TABLE t1_new TO t1;
RENAME TABLE t1 TO t1_new, t2 TO t2_new;

-- =============================================
-- SECTION 10: TRUNCATE TABLE
-- =============================================

TRUNCATE TABLE t1;
TRUNCATE t2;

-- =============================================
-- SECTION 11: INSERT patterns (from table_stress_innodb_dml.yy, table_stress_innodb.yy)
-- =============================================

-- Basic insert
INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (1, 1, 1, REPEAT(SUBSTR(CAST(1 AS CHAR),1,1), 10), REPEAT(SUBSTR(CAST(1 AS CHAR),1,1), 8193));

-- Insert to trigger duplicate key
INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (5, 5, 5, REPEAT(SUBSTR(CAST(5 AS CHAR),1,1), 10), REPEAT(SUBSTR(CAST(5 AS CHAR),1,1), 8193));

-- Insert with slight variations to provoke duplicates
INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (3, 2, 3, REPEAT(SUBSTR(CAST(3 AS CHAR),1,1), 10), REPEAT(SUBSTR(CAST(3 AS CHAR),1,1), 8193));
INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (3, 3, 2, REPEAT(SUBSTR(CAST(3 AS CHAR),1,1), 10), REPEAT(SUBSTR(CAST(3 AS CHAR),1,1), 8193));
INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (3, 3, 3, REPEAT(SUBSTR(CAST(3 AS CHAR),1,1), 10), REPEAT(SUBSTR(CAST(2 AS CHAR),1,1), 8193));

-- Multi-row insert
INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (7, 7, 7, REPEAT('7', 10), REPEAT('7', 8193)),
  (7, 7, 7, REPEAT('7', 10), REPEAT('7', 8193));

-- INSERT with ON DUPLICATE KEY UPDATE
INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (1, 1, 1, REPEAT('1', 10), REPEAT('1', 8193))
  ON DUPLICATE KEY UPDATE col_int = 42;

INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (2, 2, 2, REPEAT('2', 10), REPEAT('2', 8193))
  ON DUPLICATE KEY UPDATE col_int = VALUES(col_int);

INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (3, 3, 3, REPEAT('3', 10), REPEAT('3', 8193))
  ON DUPLICATE KEY UPDATE col_int = 99, col_string = VALUES(col_string);

-- INSERT ... ON DUPLICATE KEY UPDATE with self-reference
INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (4, 4, 4, REPEAT('4', 10), REPEAT('4', 8193))
  ON DUPLICATE KEY UPDATE col_int = col_int + 1;

-- REPLACE INTO
REPLACE INTO t1 (col1, col2, col_int, col_string, col_text) VALUES
  (5, 5, 5, REPEAT('5', 10), REPEAT('5', 8193)),
  (5, 5, 5, REPEAT('5', 10), REPEAT('5', 8193));

-- OLTP-style inserts (from oltp.yy)
INSERT IGNORE INTO t1 (col1) VALUES (NULL);
INSERT IGNORE INTO t1 (col_int) VALUES (100);
INSERT IGNORE INTO t1 (col_string) VALUES ('test_string');
INSERT IGNORE INTO t1 (col1, col_int) VALUES (NULL, 42);
INSERT IGNORE INTO t1 (col1, col_string) VALUES (NULL, 'hello_world');

-- INSERT ... SELECT (from concurrency_innodb.yy)
INSERT INTO t1 (col1) SELECT col1 FROM t2 WHERE col1 BETWEEN 1 AND 5 LIMIT 1;
INSERT IGNORE INTO t1 (col1, col_int) SELECT col1, col_int FROM t2 WHERE col1 BETWEEN 1 AND 5 LIMIT 1;

-- PREPARE / EXECUTE style insert
PREPARE stmt FROM 'INSERT INTO t1 (col1, col2, col_int, col_string, col_text) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE col_int = VALUES(col_int)';
EXECUTE stmt USING 1, 1, 1, '1', '1';
DEALLOCATE PREPARE stmt;

-- Partition-aware INSERT (from partitions_innodb.yy)
INSERT INTO t1_part (`col_int_nokey`, `col_int_key`) VALUES (1, 1), (2, 2), (3, 3), (4, 4);
REPLACE INTO t1_part (`col_int_nokey`, `col_int_key`) VALUES (5, 5), (6, 6);

-- Full text search INSERT (from full_text_search.yy)
INSERT INTO t1 (col_text) VALUES ('the quick brown fox jumps over the lazy dog');
INSERT INTO t1 (col_text) VALUES ('database management system query optimization');

-- =============================================
-- SECTION 12: UPDATE patterns
-- =============================================

-- Simple update
UPDATE t1 SET col_int = 42;
UPDATE t1 SET col1 = 5;
UPDATE t1 SET col2 = 10;
UPDATE t1 SET col_string = REPEAT(SUBSTR(CAST(7 AS CHAR),1,1), 10);
UPDATE t1 SET col_text = REPEAT(SUBSTR(CAST(3 AS CHAR),1,1), 8193);

-- Update with ORDER BY + LIMIT (force duplicate key on two rows)
UPDATE t1 SET col1 = 5 ORDER BY col1 DESC LIMIT 2;
UPDATE t1 SET col2 = 3 ORDER BY col1 DESC LIMIT 2;
UPDATE t1 SET col_int = 1 ORDER BY col1 DESC LIMIT 2;

-- OLTP-style updates (from oltp.yy)
UPDATE IGNORE t1 SET col_int = col_int + 1 WHERE col1 = 100;
UPDATE t1 SET col_string = 'updated_string' WHERE col1 = 50;

-- Updates with WHERE (from concurrency_innodb.yy)
UPDATE t1 SET col_int = 7 WHERE col1 > 5 LIMIT 3;
UPDATE LOW_PRIORITY IGNORE t1 SET col_int = 9 WHERE col1 > 3 LIMIT 5;

-- Multi-table UPDATE (from concurrency_innodb.yy)
UPDATE IGNORE t1 AS A NATURAL JOIN t2 B SET A.col_int = 7, B.col_int = 8;
UPDATE LOW_PRIORITY IGNORE t1 AS A NATURAL JOIN t2 B SET A.col1 = 1, B.col1 = 2;

-- =============================================
-- SECTION 13: DELETE patterns
-- =============================================

-- Delete with WHERE + OR NULL
DELETE FROM t1 WHERE col1 = 5 OR col1 IS NULL;
DELETE FROM t1 WHERE col2 = 3 OR col2 IS NULL;
DELETE FROM t1 WHERE col_int = 1 OR col_int IS NULL;

-- OLTP-style delete (from oltp.yy)
DELETE FROM t1 WHERE col1 = 100;

-- Delete with ORDER BY + LIMIT (from partitions_innodb.yy)
DELETE FROM t1 WHERE col1 = 5 ORDER BY col1, col2 LIMIT 3;

-- Multi-table DELETE (from concurrency_innodb.yy)
DELETE A, B FROM t1 AS A NATURAL JOIN t2 B WHERE A.col1 BETWEEN 3 AND 5;
DELETE A FROM t1 AS A WHERE A.col1 BETWEEN 0 AND 2;
DELETE LOW_PRIORITY QUICK FROM t1 WHERE col1 > 5 LIMIT 1;

-- Delete with subquery
DELETE A FROM t1 AS A WHERE A.col1 IN (SELECT col1 FROM t2 AS B WHERE B.col1 = A.col1);
DELETE A FROM t1 AS A WHERE A.col1 IN (SELECT col1 FROM t2 AS B WHERE B.col1 = 5);

-- =============================================
-- SECTION 14: SELECT patterns (from oltp.yy, partitions_innodb.yy, concurrency.yy)
-- =============================================

-- Point select (OLTP)
SELECT col1 FROM t1 WHERE col1 = 100;
SELECT * FROM t1 WHERE col1 = 50;

-- Simple range (OLTP)
SELECT col1 FROM t1 WHERE col1 BETWEEN 50 AND 150;
SELECT col_int FROM t1 WHERE col1 BETWEEN 1 AND 10;

-- Sum range (OLTP)
SELECT SUM(col_int) FROM t1 WHERE col1 BETWEEN 50 AND 150;

-- Order range (OLTP)
SELECT col_int FROM t1 WHERE col1 BETWEEN 50 AND 150 ORDER BY col_int;

-- Distinct range (OLTP)
SELECT DISTINCT col_int FROM t1 WHERE col1 BETWEEN 50 AND 150 ORDER BY col_int;

-- Partition-aware SELECT (from partitions_innodb.yy)
SELECT `col_int_nokey` % 10 AS `col_int_nokey`, `col_int_key` % 10 AS `col_int_key`
  FROM t1_part PARTITION (p0,p1);
SELECT `col_int_nokey` % 10 AS `col_int_nokey`, `col_int_key` % 10 AS `col_int_key`
  FROM t1_part PARTITION (p0,p1,p2,p3);
SELECT `col_int_nokey` FROM t1_part WHERE `col_int_nokey` BETWEEN 3 AND 7;
SELECT `col_int_nokey` FROM t1_part WHERE `col_int_nokey` > 5;
SELECT `col_int_nokey` FROM t1_part WHERE `col_int_nokey` = 3;
SELECT `col_int_nokey` FROM t1_part WHERE `col_int_nokey` != 5;

-- EXPLAIN PARTITIONS
EXPLAIN PARTITIONS SELECT `col_int_nokey` FROM t1_part WHERE `col_int_nokey` = 5;

-- SELECT with subquery (from concurrency_innodb.yy)
SELECT * FROM t1 AS A WHERE A.col1 IN (SELECT col1 FROM t2 AS B WHERE B.col1 = A.col1);
SELECT * FROM t1 AS A WHERE A.col1 IN (SELECT col1 FROM t2 AS B WHERE B.col1 = 5);

-- SELECT with JOIN
SELECT * FROM t1 AS A NATURAL JOIN t2 B WHERE A.col1 BETWEEN 1 AND 3;

-- SELECT with UNION
SELECT col1, col_int FROM t1 AS A WHERE col1 BETWEEN 1 AND 5
UNION
SELECT col1, col_int FROM t2 AS B WHERE col1 BETWEEN 1 AND 5;

-- SELECT with derived table
SELECT * FROM (SELECT * FROM t1) AS derived_t WHERE col1 BETWEEN 1 AND 5;

-- SELECT FOR UPDATE and LOCK IN SHARE MODE
SELECT * FROM t1 WHERE col1 BETWEEN 1 AND 5 FOR UPDATE;
SELECT * FROM t1 WHERE col1 = 3 LOCK IN SHARE MODE;
SELECT * FROM t1 WHERE col1 BETWEEN 1 AND 3 FOR UPDATE;
SELECT col1, col_int FROM t1 WHERE col1 > 5 LOCK IN SHARE MODE;

-- SQL_NO_CACHE / SQL_CACHE
SELECT SQL_NO_CACHE * FROM t1 WHERE col1 = 5;
SELECT SQL_CACHE col_int FROM t1 WHERE col1 BETWEEN 1 AND 10;
SELECT HIGH_PRIORITY * FROM t1 WHERE col1 = 3;

-- SELECT INTO (for LOAD DATA pattern)
SELECT * FROM t1 INTO OUTFILE '/tmp/rqg_dump.csv';

-- Information schema queries (from concurrency_innodb.yy)
SELECT * FROM information_schema.schemata WHERE schema_name = 'test';
SELECT * FROM information_schema.tables WHERE table_schema = 'test' AND table_name = 't1';
SELECT * FROM information_schema.columns WHERE table_schema = 'test' AND table_name = 't1' AND column_name = 'col_int';

-- =============================================
-- SECTION 15: Full Text Search patterns (from full_text_search.yy)
-- =============================================

-- Natural language search
SELECT * FROM t1 WHERE MATCH (col_text) AGAINST ('database' IN NATURAL LANGUAGE MODE);
SELECT col1, MATCH (col_text) AGAINST ('optimization' IN NATURAL LANGUAGE MODE) AS SCORE
  FROM t1 WHERE MATCH (col_text) AGAINST ('optimization' IN NATURAL LANGUAGE MODE);
SELECT col1, MATCH (col_text) AGAINST ('quick brown' IN NATURAL LANGUAGE MODE) AS SCORE
  FROM t1 ORDER BY SCORE DESC LIMIT 3;

-- Boolean search
SELECT * FROM t1 WHERE MATCH (col_text) AGAINST ('+database -fox' IN BOOLEAN MODE);
SELECT * FROM t1 WHERE MATCH (col_text) AGAINST ('+quick +brown' IN BOOLEAN MODE);
SELECT count(*) FROM t1 WHERE MATCH (col_text) AGAINST ('lazy*' IN BOOLEAN MODE);
SELECT col1, MATCH (col_text) AGAINST ('>system <dog' IN BOOLEAN MODE) AS SCORE
  FROM t1 WHERE MATCH (col_text) AGAINST ('>system <dog' IN BOOLEAN MODE) > 0;

-- Query expansion search
SELECT * FROM t1 WHERE MATCH (col_text) AGAINST ('query' WITH QUERY EXPANSION);
SELECT col1, MATCH (col_text) AGAINST ('management' WITH QUERY EXPANSION) AS SCORE
  FROM t1 ORDER BY SCORE DESC LIMIT 5;

-- FTS-based UPDATE and DELETE
UPDATE t1 SET col_text = 'updated text content' WHERE MATCH (col_text) AGAINST ('database' IN NATURAL LANGUAGE MODE);
DELETE FROM t1 WHERE MATCH (col_text) AGAINST ('+fox +lazy' IN BOOLEAN MODE);

-- FTS index DDL
ALTER TABLE t1 ADD FULLTEXT INDEX ftidx1 (col_text);
ALTER TABLE t1 DROP INDEX ftidx1;

-- =============================================
-- SECTION 16: Transaction patterns (from concurrency_innodb.yy)
-- =============================================

BEGIN;
COMMIT;
ROLLBACK;

BEGIN WORK;
COMMIT WORK;
ROLLBACK WORK;

START TRANSACTION;
COMMIT;

START TRANSACTION WITH CONSISTENT SNAPSHOT;
COMMIT;

-- COMMIT/ROLLBACK with CHAIN
COMMIT AND CHAIN;
COMMIT AND NO CHAIN;
ROLLBACK AND CHAIN;
ROLLBACK AND NO CHAIN;

-- COMMIT/ROLLBACK with RELEASE
COMMIT RELEASE;
ROLLBACK RELEASE;

-- SAVEPOINT patterns
SAVEPOINT A;
SAVEPOINT B;
RELEASE SAVEPOINT A;
ROLLBACK TO A;
ROLLBACK WORK TO SAVEPOINT B;
ROLLBACK TO SAVEPOINT A;

-- Transaction isolation levels
SET SESSION TX_ISOLATION = 'READ-UNCOMMITTED';
SET SESSION TX_ISOLATION = 'READ-COMMITTED';
SET SESSION TX_ISOLATION = 'REPEATABLE-READ';
SET SESSION TX_ISOLATION = 'SERIALIZABLE';

-- AUTOCOMMIT
SET AUTOCOMMIT = 0;
SET AUTOCOMMIT = 1;

-- DML within transaction
BEGIN;
INSERT INTO t1 (col1, col2, col_int) VALUES (10, 10, 10);
UPDATE t1 SET col_int = 99 WHERE col1 = 10;
SAVEPOINT A;
DELETE FROM t1 WHERE col1 = 10;
ROLLBACK TO A;
COMMIT;

-- =============================================
-- SECTION 17: Locking patterns (from concurrency_innodb.yy)
-- =============================================

-- LOCK TABLES
LOCK TABLES t1 READ;
UNLOCK TABLES;

LOCK TABLES t1 WRITE;
UNLOCK TABLES;

LOCK TABLES t1 READ LOCAL;
UNLOCK TABLES;

LOCK TABLES t1 LOW_PRIORITY WRITE;
UNLOCK TABLES;

LOCK TABLES t1 AS a READ, t2 AS b WRITE;
UNLOCK TABLES;

-- Lock wait timeouts
SET SESSION lock_wait_timeout = 2;
SET SESSION innodb_lock_wait_timeout = 1;
SET SESSION lock_wait_timeout = 60;
SET SESSION innodb_lock_wait_timeout = 30;

-- =============================================
-- SECTION 18: KILL patterns (from table_stress_innodb.yy, concurrency.yy)
-- =============================================

KILL SOFT CONNECTION 1;
KILL SOFT QUERY 1;

-- =============================================
-- SECTION 19: CHECK TABLE, OPTIMIZE, etc. (from table_stress_innodb.yy, concurrency.yy)
-- =============================================

CHECK TABLE t1 EXTENDED;
CHECK TABLE t1;
CHECK TABLE t1 FOR UPGRADE;
CHECK TABLE t1 QUICK;
CHECK TABLE t1 FAST;
CHECK TABLE t1 MEDIUM;
CHECK TABLE t1 CHANGED;

OPTIMIZE TABLE t1;
OPTIMIZE LOCAL TABLE t1, t2;
OPTIMIZE NO_WRITE_TO_BINLOG TABLE t1;

ANALYZE TABLE t1;
ANALYZE LOCAL TABLE t1, t2;
ANALYZE NO_WRITE_TO_BINLOG TABLE t1;

REPAIR TABLE t1;
REPAIR LOCAL TABLE t1 QUICK;
REPAIR NO_WRITE_TO_BINLOG TABLE t1 QUICK EXTENDED;
REPAIR TABLE t1 USE_FRM;

CHECKSUM TABLE t1;
CHECKSUM TABLE t1, t2;
CHECKSUM TABLE t1 QUICK;
CHECKSUM TABLE t1 EXTENDED;

-- =============================================
-- SECTION 20: FLUSH patterns (from concurrency_innodb.yy)
-- =============================================

FLUSH TABLE t1;
FLUSH TABLE t1, t2;
FLUSH TABLES;
FLUSH TABLES WITH READ LOCK;
UNLOCK TABLES;

-- =============================================
-- SECTION 21: BACKUP STAGE patterns (from table_stress_innodb.yy)
-- =============================================

-- Full backup stage sequence
BACKUP STAGE START;
BACKUP STAGE FLUSH;
BACKUP STAGE BLOCK_DDL;
BACKUP STAGE BLOCK_COMMIT;
BACKUP STAGE END;

-- Individual backup stages (diced/random)
BACKUP STAGE START;
BACKUP STAGE FLUSH;
BACKUP STAGE BLOCK_DDL;
BACKUP STAGE BLOCK_COMMIT;
BACKUP STAGE END;

-- =============================================
-- SECTION 22: HANDLER patterns (from concurrency_innodb.yy)
-- =============================================

HANDLER t1 OPEN AS handler_a;
HANDLER handler_a READ `PRIMARY` FIRST;
HANDLER handler_a READ `PRIMARY` NEXT;
HANDLER handler_a READ `PRIMARY` PREV;
HANDLER handler_a READ `PRIMARY` LAST;
HANDLER handler_a READ idx1 FIRST;
HANDLER handler_a READ idx1 > (5);
HANDLER handler_a READ idx1 = (3);
HANDLER handler_a READ idx1 <= (7);
HANDLER handler_a READ FIRST;
HANDLER handler_a READ NEXT;
HANDLER handler_a CLOSE;

-- =============================================
-- SECTION 23: Buffer pool resize (from table_stress_innodb.yy)
-- =============================================

SET GLOBAL innodb_buffer_pool_size = 8388608;
SET GLOBAL innodb_buffer_pool_size = 33554432;
SET GLOBAL innodb_buffer_pool_size = 134217728;
SET GLOBAL innodb_buffer_pool_size = 268435456;

-- =============================================
-- SECTION 24: InnoDB system variable tweaks (from concurrency_innodb.yy)
-- =============================================

SET GLOBAL innodb_file_per_table = 0;
SET GLOBAL innodb_file_per_table = 1;

-- =============================================
-- SECTION 25: SHOW commands (from concurrency_innodb.yy)
-- =============================================

SHOW TABLES;
SHOW TABLE STATUS;
SHOW CREATE TABLE t1;
SHOW FULL COLUMNS FROM t1;
SHOW COLUMNS IN t1 LIKE '%INT%';
SHOW OPEN TABLES IN test;
SHOW STATUS;
SHOW DATABASES;
SHOW CREATE DATABASE test;
SHOW TRIGGERS;
SHOW PROCEDURE STATUS;
SHOW FUNCTION STATUS;
SHOW EVENTS IN test;
SHOW GRANTS FOR CURRENT_USER;

-- =============================================
-- SECTION 26: CREATE/DROP DATABASE (from concurrency_innodb.yy)
-- =============================================

CREATE DATABASE IF NOT EXISTS testdb_n DEFAULT CHARACTER SET utf8;
CREATE SCHEMA IF NOT EXISTS testdb_n2 DEFAULT COLLATE utf8_bin;
ALTER DATABASE testdb_n DEFAULT CHARACTER SET utf8;
DROP DATABASE IF EXISTS testdb_n;
DROP SCHEMA IF EXISTS testdb_n2;

-- =============================================
-- SECTION 27: DROP TABLE patterns
-- =============================================

DROP TABLE IF EXISTS t1;
DROP TABLE IF EXISTS t1, t2;
DROP TABLE IF EXISTS t1 RESTRICT;
DROP TABLE IF EXISTS t1 CASCADE;
DROP TEMPORARY TABLE IF EXISTS tmp1;

-- =============================================
-- SECTION 28: VIEW patterns (from concurrency_innodb.yy)
-- =============================================

CREATE OR REPLACE ALGORITHM = UNDEFINED VIEW v1 AS SELECT * FROM t1 WHERE col1 BETWEEN 1 AND 5;
CREATE ALGORITHM = MERGE VIEW v1 AS SELECT col1, col_int FROM t1 WHERE col1 BETWEEN 1 AND 3;
CREATE ALGORITHM = TEMPTABLE VIEW v1 AS SELECT col1, col_int FROM t1 WHERE col1 > 5;
ALTER ALGORITHM = MERGE VIEW v1 AS SELECT * FROM t1 WHERE col1 BETWEEN 1 AND 5;
DROP VIEW IF EXISTS v1;
DROP VIEW IF EXISTS v1 RESTRICT;
DROP VIEW IF EXISTS v1 CASCADE;
SHOW CREATE VIEW v1;

-- =============================================
-- SECTION 29: STORED PROCEDURE patterns (from concurrency_innodb.yy)
-- =============================================

CREATE PROCEDURE p1() BEGIN SELECT * FROM t1 WHERE col1 BETWEEN 1 AND 3; UPDATE t1 SET col_int = 99 WHERE col1 > 5 LIMIT 1; END;
CALL p1();
DROP PROCEDURE IF EXISTS p1;
ALTER PROCEDURE p1 COMMENT 'UPDATED to 5';

-- =============================================
-- SECTION 30: STORED FUNCTION patterns (from concurrency_innodb.yy)
-- =============================================

CREATE FUNCTION f1() RETURNS INTEGER BEGIN SET @my_var = 1; SELECT MAX(col_int) FROM t1 INTO @my_var; RETURN 1; END;
DROP FUNCTION IF EXISTS f1;
ALTER FUNCTION f1 COMMENT 'UPDATED to 3';

-- =============================================
-- SECTION 31: TRIGGER patterns (from concurrency_innodb.yy)
-- =============================================

CREATE TRIGGER tr1 BEFORE INSERT ON t1 FOR EACH ROW BEGIN INSERT IGNORE INTO t2 (col1) VALUES (NEW.col1); END;
CREATE TRIGGER tr2 AFTER UPDATE ON t1 FOR EACH ROW BEGIN DELETE FROM t2 WHERE col1 = OLD.col1; END;
CREATE TRIGGER tr3 BEFORE DELETE ON t1 FOR EACH ROW BEGIN UPDATE t2 SET col_int = col_int + 1 WHERE col1 = OLD.col1; END;
DROP TRIGGER IF EXISTS tr1;

-- =============================================
-- SECTION 32: EVENT patterns (from concurrency_innodb.yy)
-- =============================================

SET GLOBAL EVENT_SCHEDULER = ON;
CREATE EVENT IF NOT EXISTS e1 ON SCHEDULE EVERY 10 SECOND STARTS NOW() ENDS NOW() + INTERVAL 21 SECOND ON COMPLETION PRESERVE DO SELECT * FROM t1 LIMIT 1;
ALTER EVENT e1 COMMENT 'UPDATED to 7';
DROP EVENT IF EXISTS e1;
SET GLOBAL EVENT_SCHEDULER = OFF;

-- =============================================
-- SECTION 33: FOREIGN KEY patterns (from concurrency_innodb.yy)
-- =============================================

CREATE TABLE IF NOT EXISTS t1_fk (pk INT PRIMARY KEY, col_int INTEGER, INDEX idx1 (col_int)) ENGINE = InnoDB;
CREATE TABLE IF NOT EXISTS t2_fk (pk INT PRIMARY KEY, col_int INTEGER, INDEX idx1 (col_int)) ENGINE = InnoDB AS SELECT * FROM t1_fk;
ALTER TABLE t2_fk ADD CONSTRAINT fk1 FOREIGN KEY (col_int) REFERENCES t1_fk (col_int);
ALTER TABLE t2_fk ADD CONSTRAINT fk2 FOREIGN KEY (col_int) REFERENCES t1_fk (col_int) ON DELETE CASCADE;
ALTER TABLE t2_fk ADD CONSTRAINT fk3 FOREIGN KEY (col_int) REFERENCES t1_fk (col_int) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE t2_fk ADD CONSTRAINT fk4 FOREIGN KEY (col_int) REFERENCES t1_fk (col_int) ON UPDATE RESTRICT;
ALTER TABLE t2_fk ADD CONSTRAINT fk5 FOREIGN KEY (col_int) REFERENCES t1_fk (col_int) ON DELETE NO ACTION ON UPDATE NO ACTION;
ALTER IGNORE TABLE t2_fk DROP FOREIGN KEY fk1;

-- =============================================
-- SECTION 34: GRANT/REVOKE patterns (from concurrency_innodb.yy)
-- =============================================

CREATE USER IF NOT EXISTS otto@localhost;
GRANT ALL ON t1 TO otto@localhost;
REVOKE ALL ON t1 FROM otto@localhost;
SHOW GRANTS FOR otto@localhost;

-- =============================================
-- SECTION 35: LOAD DATA patterns (from concurrency_innodb.yy)
-- =============================================

SELECT * FROM t1 INTO OUTFILE '/tmp/rqg_load_test.csv';
LOAD DATA INFILE '/tmp/rqg_load_test.csv' IGNORE INTO TABLE t2;
LOAD DATA INFILE '/tmp/rqg_load_test.csv' REPLACE INTO TABLE t2;
LOAD DATA LOW_PRIORITY INFILE '/tmp/rqg_load_test.csv' IGNORE INTO TABLE t2;
LOAD DATA CONCURRENT INFILE '/tmp/rqg_load_test.csv' IGNORE INTO TABLE t2;

-- =============================================
-- SECTION 36: CACHE INDEX / LOAD INDEX (from partitions_innodb.yy)
-- =============================================

CACHE INDEX t1_part IN c1;
CACHE INDEX t1_part PARTITION (ALL) IN c1;
CACHE INDEX t1_part PARTITION (p0, p1) IN c1;
LOAD INDEX INTO CACHE t1_part;
LOAD INDEX INTO CACHE t1_part PARTITION (ALL);
LOAD INDEX INTO CACHE t1_part PARTITION (p0, p1) IGNORE LEAVES;

SET GLOBAL c1.key_buffer_size = 1024;
SET GLOBAL c1.key_buffer_size = 65536;
SET GLOBAL c1.key_cache_block_size = 512;
SET GLOBAL c1.key_cache_block_size = 4096;
SET GLOBAL c1.key_cache_block_size = 16384;

-- =============================================
-- SECTION 37: DO and user locks (from concurrency_innodb.yy)
-- =============================================

DO 1;
DO (SELECT COUNT(*) FROM t1 WHERE col1 BETWEEN 3 AND 8);
DO IS_FREE_LOCK('1');
DO IS_USED_LOCK('1');
DO RELEASE_LOCK('1');
DO GET_LOCK('1', 0.5);

-- =============================================
-- SECTION 38: SQL MODE (from concurrency_innodb.yy)
-- =============================================

SET SESSION SQL_MODE = '';
SET SESSION SQL_MODE = 'TRADITIONAL';

-- =============================================
-- SECTION 39: PROCEDURE ANALYSE (from concurrency_innodb.yy)
-- =============================================

SELECT * FROM t1 WHERE col1 BETWEEN 1 AND 3 PROCEDURE ANALYSE(10, 2000);

-- =============================================
-- SECTION 40: Composite stress patterns (multi-statement sequences)
-- =============================================

-- Pattern: Create, populate, alter, verify, drop
CREATE TABLE IF NOT EXISTS t_stress (col1 INT PRIMARY KEY, col2 INT, col_text TEXT) ENGINE = InnoDB ROW_FORMAT = Dynamic;
INSERT INTO t_stress VALUES (1, 1, REPEAT('a', 100)), (2, 2, REPEAT('b', 100)), (3, 3, REPEAT('c', 100));
ALTER TABLE t_stress ADD INDEX idx1 (col2), ALGORITHM = INPLACE, LOCK = NONE;
ALTER TABLE t_stress ADD FULLTEXT INDEX ftidx1 (col_text);
CHECK TABLE t_stress EXTENDED;
ALTER TABLE t_stress DROP INDEX idx1, ALGORITHM = INPLACE;
DROP TABLE IF EXISTS t_stress;

-- Pattern: Transaction with savepoints
SET AUTOCOMMIT = 0;
BEGIN;
INSERT INTO t1 (col1, col2, col_int) VALUES (100, 100, 100);
SAVEPOINT A;
UPDATE t1 SET col_int = 200 WHERE col1 = 100;
SAVEPOINT B;
DELETE FROM t1 WHERE col1 = 100;
ROLLBACK TO SAVEPOINT B;
RELEASE SAVEPOINT A;
COMMIT;

-- Pattern: Partition maintenance cycle
ALTER TABLE t1_part ANALYZE PARTITION p0, p1, p2, p3;
ALTER TABLE t1_part OPTIMIZE PARTITION p0, p1;
ALTER TABLE t1_part CHECK PARTITION ALL;
ALTER TABLE t1_part REBUILD PARTITION p0;
ALTER TABLE t1_part REPAIR PARTITION p0, p1, p2, p3;

-- Pattern: Column replacement (from table_stress_innodb.yy replace_column)
ALTER TABLE t1 ADD COLUMN IF NOT EXISTS col_varchar_copy VARCHAR(500) FIRST, ALGORITHM = INPLACE, LOCK = NONE;
UPDATE t1 SET col_varchar_copy = col_varchar;
ALTER TABLE t1 DROP COLUMN IF EXISTS col_varchar, ALGORITHM = INPLACE, LOCK = NONE;
ALTER TABLE t1 CHANGE COLUMN IF EXISTS col_varchar_copy col_varchar VARCHAR(500), ALGORITHM = INPLACE, LOCK = NONE;

-- Pattern: Schema lifecycle (from concurrency_innodb.yy database_sequence)
CREATE SCHEMA IF NOT EXISTS testdb_lifecycle DEFAULT CHARACTER SET utf8;
CREATE TABLE IF NOT EXISTS testdb_lifecycle.t1 (col1 INT, col2 INT) ENGINE = InnoDB;
INSERT INTO testdb_lifecycle.t1 VALUES (1, 1), (2, 2);
DROP SCHEMA IF EXISTS testdb_lifecycle;

-- Pattern: RENAME TABLE cycle (from table_stress_innodb.yy)
CREATE SCHEMA IF NOT EXISTS cool_down;
RENAME TABLE t1 TO cool_down.t1;
RENAME TABLE cool_down.t1 TO t1;
DROP SCHEMA IF EXISTS cool_down;
