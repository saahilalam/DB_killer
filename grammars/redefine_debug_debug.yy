thread1_add:
     var;
thread2_add:
     var;
var:
   SET DEBUG_DBUG='+d,page_intermittent_checksum_mismatch'|
   SET DEBUG_DBUG='+d,page_checksum_mismatch,page_read_fail'|
   SET DEBUG_DBUG='+d,ib_rename_indexes_too_many_concurrent_trxs'|
   SET DEBUG_DBUG='+d,ib_build_indexes_too_many_concurrent_trxs,ib_rename_indexes_too_many_concurrent_trxs'|
   SET DEBUG_DBUG='+d,ib_create_index_fail'|
   SET DEBUG_DBUG='+d,trx_commit_fail,trx_undo_page_error'|
   SET DEBUG_DBUG='+d,trx_rollback_fail,trx_undo_log_corruption'|
   SET DEBUG_DBUG='+d,log_write_fail,log_flush_fail'|
   SET DEBUG_DBUG='+d,dict_create_table_fail'|
   SET DEBUG_DBUG='+d,row_lock_fail,lock_deadlock_force'|
   SET DEBUG_DBUG='+d,fil_space_extend_fail,fil_io_error'|
   SET DEBUG_DBUG='+d,page_intermittent_checksum_mismatch,ib_rename_indexes_too_many_concurrent_trxs,log_write_fail'|
   SET GLOBAL debug_dbug = '';
