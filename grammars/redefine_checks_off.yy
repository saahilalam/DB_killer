# Use in special cases only
# -------------------------
# Warning:
# ALTER TABLE `test` . `t5` FORCE could fail with 1062 : Duplicate entry '\x00' for key 'col_char'
# Some thinkable *_connect_add would work better but *_connect_add is not yet supported.
thread_init_add:
    SET foreign_key_checks = 0, unique_checks = 0 ;
query_init_add:
    thread_init_add ;
