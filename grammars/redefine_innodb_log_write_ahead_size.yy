# MDEV-33894 MariaDB does unexpected storage read IO for the redo log
# reintroduces (removed in MariaDB 10.8, added 10.11,11.4) the system
# variable innodb_log_write_ahead_size.

thread1_add:
   compute_and_set_innodb_log_write_ahead_size ;

compute_and_set_innodb_log_write_ahead_size:
   # Allowed range: 512 to innodb_page_size
   SET GLOBAL innodb_log_write_ahead_size = @@innodb_page_size     |
   SET GLOBAL innodb_log_write_ahead_size = 2048                   |
   SET GLOBAL innodb_log_write_ahead_size = 512                    ;
