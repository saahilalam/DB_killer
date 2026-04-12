thread1_add:
    SET GLOBAL innodb_undo_log_truncate = z_zero_or_one |
    SET GLOBAL innodb_purge_rseg_truncate_frequency = truncate_frequency |
    SET GLOBAL innodb_immediate_scrub_data_uncompressed = z_zero_or_one ;

z_zero_or_one:
    0 |
    1 ;

truncate_frequency:
    1 |
    128 ;
