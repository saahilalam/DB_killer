-- InnoDB basic operations seed queries for AST fuzzer
-- These provide fragments for cross-pollination

CREATE TABLE t1 (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    value DECIMAL(10,2) DEFAULT 0.00,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    data TEXT,
    status ENUM('active', 'inactive', 'deleted') DEFAULT 'active',
    flags SET('a', 'b', 'c')
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

CREATE TABLE t2 (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    t1_id INT NOT NULL,
    payload BLOB,
    json_data JSON,
    score FLOAT DEFAULT 0,
    FOREIGN KEY (t1_id) REFERENCES t1(id) ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_t1_id (t1_id),
    INDEX idx_score (score)
) ENGINE=InnoDB KEY_BLOCK_SIZE=8;

CREATE TABLE t3 (
    id INT PRIMARY KEY,
    a INT, b INT, c INT, d VARCHAR(100),
    INDEX idx_abc (a, b, c),
    UNIQUE INDEX idx_d (d)
) ENGINE=InnoDB ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=4;

INSERT INTO t1 (name, value, data, status) VALUES ('test1', 100.50, 'hello world', 'active');
INSERT INTO t1 (name, value, data, status) VALUES ('test2', -99.99, REPEAT('x', 1000), 'inactive');
INSERT INTO t1 (name, value, data, status) VALUES ('test3', 0, NULL, 'deleted');
INSERT INTO t1 (name, value, data, status) VALUES ('test4', 2147483647, '', 'active');

INSERT INTO t2 (t1_id, payload, json_data, score) VALUES (1, UNHEX('DEADBEEF'), '{"key": "value"}', 3.14);
INSERT INTO t2 (t1_id, payload, json_data, score) VALUES (2, NULL, '[1,2,3]', -1.0);

INSERT INTO t3 VALUES (1, 10, 20, 30, 'abc');
INSERT INTO t3 VALUES (2, 20, 30, 40, 'def');
INSERT INTO t3 VALUES (3, NULL, NULL, NULL, NULL);

SELECT * FROM t1;
SELECT * FROM t1 WHERE id = 1;
SELECT * FROM t1 WHERE name LIKE '%test%';
SELECT * FROM t1 WHERE value BETWEEN 0 AND 100;
SELECT * FROM t1 WHERE status IN ('active', 'inactive');
SELECT * FROM t1 WHERE data IS NULL;
SELECT * FROM t1 WHERE data IS NOT NULL;

SELECT t1.name, t2.score FROM t1 INNER JOIN t2 ON t1.id = t2.t1_id;
SELECT t1.name, t2.score FROM t1 LEFT JOIN t2 ON t1.id = t2.t1_id WHERE t2.score > 0;
SELECT t1.*, t2.*, t3.* FROM t1 JOIN t2 ON t1.id = t2.t1_id JOIN t3 ON t1.id = t3.id;

SELECT status, COUNT(*), SUM(value), AVG(value), MIN(value), MAX(value) FROM t1 GROUP BY status;
SELECT status, COUNT(*) AS cnt FROM t1 GROUP BY status HAVING cnt > 1;
SELECT name FROM t1 ORDER BY value DESC LIMIT 10;
SELECT name FROM t1 ORDER BY value ASC, name DESC LIMIT 5 OFFSET 2;

SELECT DISTINCT status FROM t1;
SELECT SQL_NO_CACHE * FROM t1 WHERE id > 0 FOR UPDATE;
SELECT * FROM t1 WHERE id = 1 LOCK IN SHARE MODE;

SELECT * FROM t1 WHERE id IN (SELECT t1_id FROM t2 WHERE score > 0);
SELECT * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE t2.t1_id = t1.id);
SELECT name, (SELECT MAX(score) FROM t2 WHERE t2.t1_id = t1.id) AS max_score FROM t1;

UPDATE t1 SET value = value + 1 WHERE id = 1;
UPDATE t1 SET status = 'deleted', value = 0 WHERE name LIKE '%test%';
UPDATE t1 SET data = CONCAT(data, ' updated') WHERE data IS NOT NULL;

DELETE FROM t1 WHERE status = 'deleted';
DELETE FROM t2 WHERE score < 0;

SELECT * FROM t1 UNION SELECT * FROM t1 WHERE id > 2;
SELECT * FROM t1 UNION ALL SELECT * FROM t1;

BEGIN;
INSERT INTO t1 (name, value) VALUES ('tx_test', 42);
SAVEPOINT sp1;
UPDATE t1 SET value = value * 2 WHERE name = 'tx_test';
ROLLBACK TO SAVEPOINT sp1;
COMMIT;

ALTER TABLE t1 ADD COLUMN extra INT DEFAULT 0;
ALTER TABLE t1 ADD INDEX idx_extra (extra);
ALTER TABLE t1 DROP INDEX idx_extra;
ALTER TABLE t1 MODIFY COLUMN extra BIGINT;
ALTER TABLE t1 DROP COLUMN extra;
ALTER TABLE t1 ENGINE=InnoDB;
ALTER TABLE t1 ROW_FORMAT=COMPRESSED;
ALTER TABLE t1 ROW_FORMAT=DYNAMIC;

OPTIMIZE TABLE t1;
ANALYZE TABLE t1;
CHECK TABLE t1;
CHECKSUM TABLE t1;

TRUNCATE TABLE t3;
DROP TABLE IF EXISTS t3;
DROP TABLE IF EXISTS t2;
DROP TABLE IF EXISTS t1;
