thread1_init_add:
    CREATE TABLE test . aux_table1 (pk INTEGER, col1 INTEGER, KEY idx1(col1), PRIMARY KEY(pk)) ENGINE = InnoDB STATS_PERSISTENT = 1;
    CREATE TABLE test . aux_table2 LIKE test . aux_table1; INSERT INTO test . aux_table2 VALUES(1,1);

thread1_add:
    ALTER TABLE innodb_sys_table FORCE, ALGORITHM = copy_or_nocopy               |
    FLUSH TABLE test . aux_table1                                                |
    FLUSH TABLE test . aux_table2                                                |
    SELECT * FROM test . aux_table2                                              |
    BEGIN ; INSERT INTO test . aux_table1 VALUES ( my_digit, $my_digit) ; COMMIT |
    BEGIN ; INSERT INTO test . aux_table1 VALUES ( my_digit, $my_digit) ; COMMIT |
    BEGIN ; DELETE FROM test . aux_table1 WHERE pk = my_digit ; COMMIT ;

innodb_sys_table:
    mysql.innodb_table_stats |
    mysql.innodb_index_stats ;

flush_table:
    mysql.innodb_table_stats |
    mysql.innodb_index_stats |
    test.aux_table1          |
    test.aux_table2          ;

copy_or_nocopy:
    copy   |
    nocopy ;

my_digit:
    { $my_digit = 0 } |
    { $my_digit = 1 } |
    { $my_digit = 2 } |
    { $my_digit = 3 } |
    { $my_digit = 4 } |
    { $my_digit = 5 } |
    { $my_digit = 6 } |
    { $my_digit = 7 } |
    { $my_digit = 8 } |
    { $my_digit = 9 } ;

