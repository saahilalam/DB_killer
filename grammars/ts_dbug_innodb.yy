# Copyright (c) 2018, MariaDB Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
# USA
#

# This grammar can be used as redefine for any grammar like table_stress.yy
# containing the rules 'set_dbug' and 'set_dbug_null'.
# It is focused on InnoDB functionality.
#

######
# Found in MTR test:
# SET DEBUG_DBUG='+d,ib_build_indexes_too_many_concurrent_trxs, ib_rename_indexes_too_many_concurrent_trxs, ib_drop_index_too_many_concurrent_trxs';
# --error ER_TOO_MANY_CONCURRENT_TRXS
# ALTER TABLE t1 ADD UNIQUE INDEX(c2);
# SET DEBUG_DBUG = @saved_debug_dbug;
# set_debug
#
# SET ... DEBUG_DBUG
# ------------------
# GLOBAL and SESSION is supported. The GLOBAL setting is only taken over as setting for a session when connecting.
# SET DEBUG_DBUG = '' and also SET DEBUG_DBUG = NULL reset the SESSION setting to empty.
#
# SET SESSION DEBUG_DBG does not COMMIT at begin of own execution.
#
set_debug_dbug:
   SET SESSION DEBUG_DBUG = dbug_value ;

dbug_value:
   NULL                                             | # Triggers excessive writing in servererror log.
#  '+d,crash_after_log_ibuf_upd_inplace'            | # Makes a crash
#  '+d,dict_set_index_corrupted'                    | # Nothing found in 10.2 testing
#  '+d,disk_is_full'                                | # Per MTR harmless    simplified
#  '+d,fatal-semaphore-timeout'                     | # Per MTR crash
#  '+d,ib_build_indexes_too_many_concurrent_trxs'   | # Nothing found in 10.2 testing
#  '+d,ib_rename_indexes_too_many_concurrent_trxs'  | # Nothing found in 10.2 testing
#  '+d,ib_drop_index_too_many_concurrent_trxs'      | # Nothing found in 10.2 testing
#  '+d,ib_drop_foreign_error'                       | # Nothing found in 10.2 testing
#  '+d,ib_ha_innodb_stat_not_initialized'           | # Nothing found in 10.2 testing, Per MTR harmless
#  '+d,ib_rebuild_cannot_rename'                    | # Nothing found in 10.2 testing
#  '+d,ib_rename_column_error'                      | # !DB_OUT_OF_FILE_SPACE! gets thrown and RQG exits with STATUS_ENVIRONMENT_FAILURE
#  '+d,ib_row_merge_buf_add_two'                    | # Nothing found in 10.2 testing
#  '+d,innobase_tmpfile_creation_failure'           | # Per MTR harmless    simplified
#  '+d,innodb_OOM_inplace_alter'                    | # Per MTR harmless, disabled because RQG reacts with STATUS_ENVIRONMENT_FAILURE
#  '+d,innodb_OOM_prepare_inplace_alter'            | # Per MTR harmless, disabled because RQG reacts with STATUS_ENVIRONMENT_FAILURE
#  '+d,innodb_test_cannot_add_fk_system'            | # Nothing found in 10.2 testing
#  '+d,innodb_test_no_foreign_idx'                  | # Nothing found in 10.2 testing
#  '+d,innodb_test_no_reference_idx'                | # Nothing found in 10.2 testing
#  '+d,innodb_test_open_ref_fail'                   | # Nothing found in 10.2 testing, Per MTR harmless
#  '+d,innodb_test_wrong_fk_option'                 | # Nothing found in 10.2 testing
#  '+d,row_drop_table_add_to_background'            | # MDEV-16876 InnoDB: Failing assertion: block->magic_n == MEM_BLOCK_MAGIC_N
#  '+d,row_ins_extern_checkpoint'                   | # Nothing found in 10.2 testing
#  '+d,row_ins_index_entry_timeout'                 | # Nothing found in 10.2 testing, source code looks harmless, resets itself
#  '+d,row_ins_sec_index_entry_timeout'             | # Nothing found in 10.2 testing, source code looks harmless, resets itself
   '+d,create_index_fail'                           |
   '+d,row_upd_extern_checkpoint'                   ; # Nothing found in 10.2 testing

   
# mark_table_corrupted
# ib_table_add_foreign_fail
# 


set_debug_dbug:
    SET SESSION DEBUG_DBUG = NULL                   ;
