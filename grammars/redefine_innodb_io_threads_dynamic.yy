# innodb-write-io-threads Global, 1 till 64, default 4
# innodb-read-io-threads  Global, 1 till 64, default 4
thread1_add:
    SET GLOBAL innodb-read-io-threads = one_till_64 |
    SET GLOBAL innodb-write-io-threads = one_till_64 ;

one_till_64:
     1 |
     4 |
    16 |
    64 ;

