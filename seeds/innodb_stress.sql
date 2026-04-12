-- InnoDB stress / edge case seed queries

CREATE TABLE stress1 (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tiny_col TINYINT,
    small_col SMALLINT,
    med_col MEDIUMINT,
    big_col BIGINT,
    ubig_col BIGINT UNSIGNED,
    f_col FLOAT,
    d_col DOUBLE,
    dec_col DECIMAL(65,30),
    bit_col BIT(64),
    dt_col DATETIME(6),
    ts_col TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    y_col YEAR,
    t_col TIME(6),
    c_col CHAR(255),
    vc_col VARCHAR(16383),
    bin_col BINARY(255),
    vbin_col VARBINARY(65535),
    tt_col TINYTEXT,
    tx_col TEXT,
    mt_col MEDIUMTEXT,
    lt_col LONGTEXT,
    tb_col TINYBLOB,
    bl_col BLOB,
    mb_col MEDIUMBLOB,
    lb_col LONGBLOB,
    en_col ENUM('a','b','c','d','e'),
    se_col SET('x','y','z'),
    js_col JSON
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

CREATE TABLE stress2 (
    id INT PRIMARY KEY,
    val INT NOT NULL DEFAULT 0,
    INDEX idx_val (val)
) ENGINE=InnoDB ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=4;

CREATE TABLE stress3 LIKE stress1;

-- Boundary value inserts
INSERT INTO stress1 (tiny_col, small_col, med_col, big_col, ubig_col)
VALUES (127, 32767, 8388607, 9223372036854775807, 18446744073709551615);

INSERT INTO stress1 (tiny_col, small_col, med_col, big_col, ubig_col)
VALUES (-128, -32768, -8388608, -9223372036854775808, 0);

INSERT INTO stress1 (f_col, d_col, dec_col) VALUES (3.402823e+38, 1.7976931348623157e+308, 99999999999999999999999999999999999.999999999999999999999999999999);
INSERT INTO stress1 (f_col, d_col, dec_col) VALUES (-3.402823e+38, -1.7976931348623157e+308, -99999999999999999999999999999999999.999999999999999999999999999999);
INSERT INTO stress1 (f_col, d_col, dec_col) VALUES (0, 0, 0);
INSERT INTO stress1 (f_col, d_col) VALUES (1e-38, 1e-308);

INSERT INTO stress1 (dt_col, ts_col) VALUES ('1000-01-01 00:00:00.000000', '1970-01-01 00:00:01');
INSERT INTO stress1 (dt_col, ts_col) VALUES ('9999-12-31 23:59:59.999999', '2038-01-19 03:14:07');
INSERT INTO stress1 (dt_col) VALUES ('0000-00-00 00:00:00');

INSERT INTO stress1 (c_col, vc_col) VALUES (REPEAT('A', 255), REPEAT('B', 16383));
INSERT INTO stress1 (c_col, vc_col) VALUES ('', '');
INSERT INTO stress1 (c_col) VALUES (CHAR(0));

INSERT INTO stress1 (js_col) VALUES ('{}');
INSERT INTO stress1 (js_col) VALUES ('[]');
INSERT INTO stress1 (js_col) VALUES ('null');
INSERT INTO stress1 (js_col) VALUES ('{"nested": {"deep": {"very": "deep"}}}');
INSERT INTO stress1 (js_col) VALUES (CONCAT('[', REPEAT('"x",', 999), '"x"]'));

-- Complex queries
SELECT * FROM stress1 WHERE tiny_col = 127 AND small_col > 0 OR big_col < 0;
SELECT * FROM stress1 WHERE f_col BETWEEN -1e38 AND 1e38;
SELECT * FROM stress1 WHERE dec_col != 0 ORDER BY dec_col DESC LIMIT 100;
SELECT * FROM stress1 WHERE js_col IS NOT NULL AND JSON_VALID(js_col);
SELECT JSON_EXTRACT(js_col, '$.nested.deep') FROM stress1 WHERE js_col IS NOT NULL;
SELECT JSON_VALUE(js_col, '$.nested.deep.very') FROM stress1;

SELECT * FROM stress1 WHERE dt_col > '2000-01-01' AND dt_col < '2038-01-19';
SELECT * FROM stress1 WHERE ts_col BETWEEN '1970-01-01 00:00:01' AND '2038-01-19 03:14:07';

SELECT COUNT(*), SUM(big_col), AVG(d_col), STD(f_col) FROM stress1;
SELECT tiny_col, GROUP_CONCAT(id ORDER BY id SEPARATOR ',') FROM stress1 GROUP BY tiny_col;

-- Self join
SELECT a.id, b.id FROM stress1 a CROSS JOIN stress1 b LIMIT 1000;
SELECT a.id FROM stress1 a LEFT JOIN stress1 b ON a.big_col = b.big_col WHERE b.id IS NULL;

-- Subqueries
SELECT * FROM stress1 WHERE id = (SELECT MAX(id) FROM stress1);
SELECT * FROM stress1 WHERE id IN (SELECT id FROM stress1 ORDER BY RAND() LIMIT 5);
SELECT * FROM (SELECT id, tiny_col, ROW_NUMBER() OVER (ORDER BY id) AS rn FROM stress1) t WHERE rn <= 10;

-- Multi-table operations
UPDATE stress1 s1 JOIN stress2 s2 ON s1.id = s2.id SET s1.tiny_col = s2.val;
DELETE s1 FROM stress1 s1 JOIN stress2 s2 ON s1.id = s2.id WHERE s2.val = 0;

-- InnoDB operations
SELECT * FROM stress1 FOR UPDATE;
SELECT * FROM stress2 LOCK IN SHARE MODE;

-- Bulk insert from select
INSERT INTO stress2 (id, val) SELECT id, tiny_col FROM stress1 ON DUPLICATE KEY UPDATE val = VALUES(val);

SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;

ALTER TABLE stress1 ADD FULLTEXT INDEX ft_idx (tx_col);
ALTER TABLE stress1 DROP INDEX ft_idx;
ALTER TABLE stress1 ADD SPATIAL INDEX sp_idx (c_col);
ALTER TABLE stress2 ALGORITHM=INPLACE, LOCK=NONE, ADD COLUMN new_col INT;
ALTER TABLE stress2 ALGORITHM=COPY, DROP COLUMN new_col;

OPTIMIZE TABLE stress1;
ALTER TABLE stress1 FORCE;

DROP TABLE IF EXISTS stress3;
DROP TABLE IF EXISTS stress2;
DROP TABLE IF EXISTS stress1;
