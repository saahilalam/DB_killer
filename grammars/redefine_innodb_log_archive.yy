# Copyright (C) 2025 MariaDB plc
#
# redefine_innodb_log_archive.yy
# This grammar is written by Saahil Alam during his time in MariaDB
# Grammar for testing MDEV-37949: Implement innodb_log_archive
#
# Key variables tested:
#   - innodb_log_archive (ON/OFF) - main feature toggle,this should not be used when using reporter as it creates false failures
#   - innodb_log_file_size (4M to 4G when archive=ON)
#   - innodb_log_file_mmap (ON/OFF) - memory-mapped vs pread/pwrite
#
# Testing considerations from Marko (PR #4405):
#   - Test all I/O combinations (PMEM, mmap, pread/pwrite)
#
# IMPORTANT CONSTRAINT: innodb_encrypt_log CANNOT be used with innodb_log_archive=ON
# From PR: "all --suite=encryption tests that use innodb_encrypt_log must be skipped
# when using innodb_log_archive. This is because the server would have to be
# reinitialized; we do not allow changing the format of an archived log on startup."
# The encryption + archive combination is only tested via innodb.log_file_size_online,encrypted
#
# Usage: --redefine=conf/mariadb/redefine_innodb_log_archive.yy
#        --mysqld=--innodb_log_archive=ON
#        --mysqld=--innodb_log_file_size=4M
#
# Note: innodb_log_archive is dynamic (can be toggled via SET GLOBAL)
#       innodb_log_file_mmap is dynamic
#       innodb_log_file_size changes take effect when current log file fills up

query_init_add:
    log_archive_init ;

log_archive_init:
    # Verify log archive status at session start
    SELECT @@GLOBAL.innodb_log_archive AS log_archive_status,
           @@GLOBAL.innodb_log_file_size AS log_file_size,
           @@GLOBAL.innodb_log_file_mmap AS log_file_mmap ;

thread1_add:
    log_archive_operation ;

thread2_add:
    log_archive_operation ;

log_archive_operation:
    log_archive_toggle          |
    log_archive_toggle          |
    log_archive_toggle          |
    log_archive_check_status    |
    log_archive_check_status    |
    log_archive_check_lsn       |
#   log_archive_mmap_toggle     |
    log_archive_set_file_size   |
    log_archive_heavy_dml       |
    log_archive_heavy_dml       |
    log_archive_heavy_dml       |
    log_archive_concurrent_ddl  ;

# Toggle log archiving - the main feature
log_archive_toggle:
    SET GLOBAL innodb_log_archive = log_archive_value ;

log_archive_value:
    ON  |
#    OFF |
    1   ;
#    0   ;

# Check log archive status via information_schema
log_archive_check_status:
    SELECT @@GLOBAL.innodb_log_archive |
    SELECT variable_value FROM information_schema.global_status
        WHERE variable_name = 'INNODB_LSN_ARCHIVED' |
    SELECT variable_value FROM information_schema.global_status
        WHERE variable_name LIKE 'INNODB%LSN%' |
    SHOW GLOBAL STATUS LIKE 'Innodb%log%' ;

# Check LSN information - important for backup integration
log_archive_check_lsn:
    SELECT variable_value FROM information_schema.global_status
        WHERE variable_name = 'INNODB_LSN_ARCHIVED' |
    SELECT variable_value FROM information_schema.global_status
        WHERE variable_name = 'INNODB_LSN_CURRENT' |
    SHOW GLOBAL STATUS LIKE 'Innodb_lsn%' ;

# Note: innodb_log_recovery_start and innodb_log_recovery_target are startup-only
# parameters used for point-in-time recovery. They cannot be set dynamically.
# Testing these requires the LogArchiveRecovery reporter which handles:
#   --innodb-log-recovery-start=<LSN>  (start recovery from this LSN)
#   --innodb-log-recovery-target=<LSN> (stop recovery at this LSN)

# Toggle memory-mapped I/O for log files
log_archive_mmap_toggle:
    SET GLOBAL innodb_log_file_mmap = mmap_value ;

mmap_value:
    ON  |
    OFF |
    1   |
    0   ;

# Set log file size - changes take effect when current file fills
# Range: 4M to 4G when innodb_log_archive=ON
log_archive_set_file_size:
    SET GLOBAL innodb_log_file_size = log_file_size_value ;

log_file_size_value:
    4194304      |  # 4M - minimum
    8388608      |  # 8M
    16777216     |  # 16M
    33554432     |  # 32M
    67108864     |  # 64M
    134217728    |  # 128M
    268435456    |  # 256M
    536870912    |  # 512M
    1073741824   |  # 1G
    2147483648   |  # 2G
    4294967295   ;  # 4G-1 - maximum when archive=ON

# Generate significant redo log activity
log_archive_heavy_dml:
    log_archive_insert_batch   |
    log_archive_update_batch   |
    log_archive_delete_batch   |
    log_archive_transaction    ;

log_archive_insert_batch:
    INSERT INTO _table ( _field ) VALUES ( _data ) |
    INSERT INTO _table ( _field ) SELECT _field FROM _table LIMIT 100 ;

log_archive_update_batch:
    UPDATE _table SET _field = _data WHERE _field IS NOT NULL LIMIT 50 |
    UPDATE _table SET _field = _data ;

log_archive_delete_batch:
    DELETE FROM _table LIMIT 10 |
    DELETE FROM _table WHERE _field IS NULL ;

log_archive_transaction:
    START TRANSACTION ;
        log_archive_insert_batch ;
        log_archive_update_batch ;
    COMMIT |
    START TRANSACTION ;
        log_archive_update_batch ;
        log_archive_delete_batch ;
    ROLLBACK ;

# DDL during log archiving - should generate archive entries
log_archive_concurrent_ddl:
    CREATE TABLE IF NOT EXISTS log_test_tbl ( id INT PRIMARY KEY AUTO_INCREMENT,
        data VARCHAR(255), ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP ) ENGINE=InnoDB |
    DROP TABLE IF EXISTS log_test_tbl |
    ALTER TABLE _table ENGINE=InnoDB |
    OPTIMIZE TABLE _table ;
