# Copyright (c) 2018, 2022 MariaDB Corporation
# Copyright (c) 2023       MariaDB plc
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

# Derivate of table_stress_innodb.yy which
# - focuses on DDL algorithm NOCOPY only
# - avoids table rebuilds which would be caused by manipulating col1
#   or TRUNCATE TABLE, ADD DROP PRIMARY KEY
# - avoids BLOCK STAGE because of frequent trouble

# The grammar is dedicated to stress tables with
# - DDL direct or indirect
#   Examples:
#      ALTER TABLE test.t1 ADD COLUMN
#      DROP TABLE test.t1
#      RENAME TABLE test.t1 TO new_test.t1
#      DROP SCHEMA new_test (affects the tables stored within the schema)
#      DROP several tables at once
#      Perform more than change affecting the definition of a table
# - DML trying to modify data and (combine with and/or)
#   - hitting frequent duplicate key or foreign key constraint violations
#   - being in some transaction which get intentional rolled back later
# - DDL and DML being "attacked" by KILL QUERY <session> and KILL <session>
# - DDL-DDL, DDL-DML, DML-DML locking conflicts caused by concurrency
# as efficient as possible regarding costs in
# - grammar development
# - at test runtime
# - in analysis (grammar simplification) and replay of bad effects met.
# In order to achieve that certain decisions had to be made
# 1. SQL statements should be kept as simple as possible.
# 2. No coverage for features like for the example the stored program language.
#    Nevertheless
#    - creating, use and drop of triggers needs to be checked because
#      they are bound to tables
#    - stored procedures might be used for auxiliary purposes
# 3. We focus on coarse grained bad effects like crashes and similar.
#    Some immediate (just after finishing statement execution) and deep
#    (table definition or table content) checking via some validator is mostly
#    impossible because of various reasons.
#
# The current grammar is partially based on the code of conf/runtime/alter_online.yy
#     Copyright (c) 2012 Oracle and/or its affiliates. All rights reserved.
# and should become the successor of that test.
#

# Even with threads = 1 an ALTER TABLE ... ADD COLUMN could fail.
# Example:
# ALTER TABLE t1 ADD COLUMN IF NOT EXISTS col3_copy INT FIRST,
# LOCK = NONE, ALGORITHM = COPY
# 1846 LOCK=NONE is not supported. Reason: COPY algorithm requires a lock. Try LOCK=SHARED.
# Impact:
# 1. 1054 Unknown column '%s' in 'field list' for
#    UPDATE t1 SET col3_copy = col3
# 2. ALTER TABLE t1 DROP COLUMN IF EXISTS col3  works
#    ALTER TABLE t1 CHANGE COLUMN <...> col3_copy col3 INT, LOCK = EXCLUSIVE makes no replacement
#    and the table is incomplete.
# Possible solutions:
# a) Try ALTER TABLE t1 ADD COLUMN IF NOT EXISTS <maybe missing column> and than fill it via
#    UPDATE t1 .... <template column or table> or REPLACE ...
# b) DROP and recreate any working table
#    - after some maximum lifetime and/or
#    - after detecting the defect (no of columns smaller than expected)
#
#
# _digit --> Range 0 till 9

fail_001:
   { $fail = 'my_fail_001' ; return undef }; SELECT * FROM $fail ;

# Create the tables we are working on.
# Doing that in 'thread1_init' avoids clashes compared to trying it by every thread
# if 'query_init' would be used.
thread1_init:
   create_table ;

thread_connect:
   maintain_session_entry ; SET AUTOCOMMIT = 0; SET @fill_amount = (@@innodb_page_size / 2 ) + 1 ; set_small_timeouts ;

set_small_timeouts:
   SET SESSION lock_wait_timeout = 2 ; SET SESSION innodb_lock_wait_timeout = 1 ;
set_big_timeouts:
   SET SESSION lock_wait_timeout = 60 ; SET SESSION innodb_lock_wait_timeout = 30 ;

maintain_session_entry:
   REPLACE INTO rqg . rqg_sessions SET rqg_id = _thread_id , processlist_id = CONNECTION_ID(), pid = { my $x = $$ } , connect_time = UNIX_TIMESTAMP();  COMMIT ;

fail_003:
   { $fail = 'my_fail_003' ; return undef }; SELECT * FROM $fail ;

kill_query_or_session_or_release:
# We are here interested on the impact of
# - killing (KILL ...)
#   - the excution of a DDL/DML
#   - a session
# - giving up the session voluntary (... RELEASE)
# regarding whatever statements being just in execution, transactions open, freeing of resources
# like locks, memory being occupied etc.
#
# Per manual:
#    KILL [HARD | SOFT] [CONNECTION | QUERY [ID] ] [thread_id | USER user_name | query_id]
#    Killing queries that repair or create indexes on MyISAM and Aria tables may result in
#    corrupted tables. Use the SOFT option to avoid this!
#
#    COMMIT [WORK] [AND [NO] CHAIN] [[NO] RELEASE]
#    ROLLBACK ... RELEASE
#
# Observation:
#    KILL <get default which is HARD> QUERY <ALTER TABLE ... ADD FTS INDEX>
#    lets the thread harvest "1034 Create index by sort failed" which
#    RQG valuates as STATUS_DATABASE_CORRUPTION.
# Up till today (2019-05) I am unsure how to fix that problem
# - use SOFT all time (current and maybe permanent solution)
#   Crash recovery testing should cover what is not checked when using SOFT
# - do not valuate "1034 Create index by sort failed" as STATUS_DATABASE_CORRUPTION.
#
#
# The following aspects are not in scope at all
# - coverage of the full SQL syntax "KILL ...", "COMMIT/ROLLBACK ..."
# - will the right connections and queries get hit etc.
#
# Scenarios covered:
# 1. S1 kills S2
# 2. S1 kills S1
# 3. S1 tries to kill S3 which already does no more exist.
# 4. S1 gives up with ROLLBACK ... RELEASE.
#    It is assumed that RELEASE added to ROLLBACK will work as well as in combination with COMMIT.
#    Hence this will be not generated.
# 5. Various combinations of sessions running 1. till 5.
#
# (1) COMMIT before and after selecting in rqg . rqg_sessions in order to avoid effects caused by
#     - a maybe open transaction before that select
#     - the later statements of a transaction maybe opened by that select
# (2) No COMMIT before and after selecting in rqg . rqg_sessions in order to have no freed locks
#     before the KILL affecting the own session is issued. This is only valid if AUTOCOMMIT=0.
#
   COMMIT ; correct_rqg_sessions_table      ; COMMIT                                 | # (1)
            own_id_part   AND kill_age_cond          ; KILL SOFT CONNECTION @kill_id | # (2)
            own_id_part                              ; KILL SOFT QUERY      @kill_id | # (2)
   COMMIT ; other_id_part AND kill_age_cond ; COMMIT ; KILL SOFT CONNECTION @kill_id | # (1)
   COMMIT ; other_id_part                   ; COMMIT ; KILL SOFT QUERY      @kill_id | # (1)
            ROLLBACK RELEASE                                                         ;

own_id_part:
   SELECT     processlist_id  INTO @kill_id FROM rqg . rqg_sessions WHERE rqg_id  = _thread_id ;
other_id_part:
   SELECT MIN(processlist_id) INTO @kill_id FROM rqg . rqg_sessions WHERE rqg_id <> _thread_id AND processlist_id IS NOT NULL;
kill_50_cond:
   MOD(rqg_id,2) = 0;
kill_age_cond:
   UNIX_TIMESTAMP() - connect_time > 10;

fail_004:
   { $fail = 'my_fail_004' ; return undef }; SELECT * FROM $fail ;

correct_rqg_sessions_table:
   UPDATE rqg . rqg_sessions SET processlist_id = CONNECTION_ID() WHERE rqg_id = _thread_id ;

create_table:
   c_t_begin t1 c_t_mid ENGINE = InnoDB ROW_FORMAT = Dynamic ;
   c_t_begin t2 c_t_mid ENGINE = InnoDB ROW_FORMAT = Compressed ;
   c_t_begin t3 c_t_mid ENGINE = InnoDB ROW_FORMAT = Compact    ;
   c_t_begin t4 c_t_mid ENGINE = InnoDB ROW_FORMAT = Redundant  ;

c_t_begin:
   CREATE TABLE IF NOT EXISTS ;
c_t_mid:
   ( non_generated_cols generated_cols ) ;

table_names:
# Make it possible to use the same table_name multiple times in one query.
# This is currently not exploited.
   { $table_name = "t1" } |
   { $table_name = "t2" } |
   { $table_name = "t3" } |
   { $table_name = "t4" } ;

non_generated_cols:
   col1 INT PRIMARY KEY, col2 INT, col_int_properties $col_name $col_type , col_string_properties $col_name $col_type, col_varchar_properties $col_name $col_type, col_text_properties $col_name $col_type ;
generated_cols:
                                                                                                                                       |
   , col_int_g_properties $col_name $col_type, col_string_g_properties $col_name $col_type , col_text_g_properties $col_name $col_type ;

engine_settings:
   innodb_settings ;

innodb_settings:
   ENGINE = InnoDB ROW_FORMAT = Dynamic    |
   ENGINE = InnoDB ROW_FORMAT = Compressed |
   ENGINE = InnoDB ROW_FORMAT = Compact    |
   ENGINE = InnoDB ROW_FORMAT = Redundant  ;

fail_005:
   { $fail = 'my_fail_005' ; return undef }; SELECT * FROM $fail ;

query:
   set_dbug ; ddl ; set_dbug_null |
   set_dbug ; dml ; set_dbug_null |
   set_dbug ; dml ; set_dbug_null ;

dml:
   # Ensure that the table does not grow endless.                                                                                                              |
   delete ; COMMIT                                                                                                                                             |
   # Make likely: Get duplicate key based on the two row INSERT/REPLACE only.                                                                                  |
   enforce_duplicate1 ;                                                                                                                        commit_rollback |
   # Make likely: Get duplicate key based on two row UPDATE only.                                                                                              |
   enforce_duplicate2 ;                                                                                                                        commit_rollback |
   # Make likely: Get duplicate key based on the row INSERT and the already committed data.                                                                    |
   insert_part ( my_int , $my_int,     $my_int,     string_fill, fill_begin $my_int     fill_end );                                            commit_rollback |
   insert_part ( my_int , $my_int - 1, $my_int,     string_fill, fill_begin $my_int     fill_end );                                            commit_rollback |
   insert_part ( my_int , $my_int,     $my_int - 1, string_fill, fill_begin $my_int     fill_end );                                            commit_rollback |
   insert_part ( my_int , $my_int,     $my_int,     string_fill, fill_begin $my_int - 1 fill_end );                                            commit_rollback |
   # ON DUPLICATE KEY
   insert_part ( my_int , $my_int,     $my_int,     string_fill, fill_begin $my_int     fill_end ) ON DUPLICATE KEY UPDATE col1 = my_int + 1 ; commit_rollback |
   insert_part ( my_int , $my_int,     $my_int,     string_fill, fill_begin $my_int     fill_end ) ON DUPLICATE KEY UPDATE col1 = my_int - 1 ; commit_rollback ;

# CAST( 200 AS CHAR)                         ==> '200'
# SUBSTR(CAST( 200 AS CHAR),1,1)             ==> '2'
# REPEAT(SUBSTR(CAST( 200 AS CHAR),1,1), 10) ==> '2222222222'
fill_begin:
   REPEAT(SUBSTR(CAST( ;
fill_end:
   AS CHAR),1,1), @fill_amount) ;

enforce_duplicate1:
   delete ; insert_part  /* my_int */ some_record , some_record |
   delete ; replace_part /* my_int */ some_record , some_record ;

enforce_duplicate2:
   UPDATE table_names SET column_name_int = my_int ORDER BY col1 DESC LIMIT 2 ;

insert_part:
   INSERT INTO table_names (col1,col2,col_int_properties $col_name, col_string_properties $col_name, col_text_properties $col_name) VALUES ;

replace_part:
   REPLACE INTO table_names (col1,col2,col_int_properties $col_name, col_string_properties $col_name, col_text_properties $col_name) VALUES ;

some_record:
   ($my_int,$my_int,$my_int,string_fill,fill_begin $my_int fill_end ) ;

delete:
   DELETE FROM table_names WHERE column_name_int = my_int OR $column_name_int IS NULL                              ;
#   DELETE FROM table_names WHERE MATCH(col_text_properties $col_name) AGAINST (TRIM(' my_int ') IN BOOLEAN MODE) OR column_name_int IS NULL ;

my_int:
   # Maybe having some uneven distribution is of some value.
   { $my_int= 1                     } |
   { $my_int= $prng->int(  2,    8) } |
   { $my_int= $prng->int(  9,   64) } |
   { $my_int= $prng->int( 65,  512) } |
   { $my_int= $prng->int(513, 4096) } |
   { $my_int= 'NULL'                } ;

commit_rollback:
   COMMIT   |
   ROLLBACK ;

fail_006:
   { $fail = 'my_fail_006' ; return undef }; SELECT * FROM $fail ;

# FIXME:
# https://mariadb.com/kb/en/library/wait-and-nowait/
ddl:
   alter_table_part add_accelerator                     ddl_algorithm_lock_option |
   alter_table_part add_accelerator                     ddl_algorithm_lock_option |
   alter_table_part add_accelerator                     ddl_algorithm_lock_option |
   alter_table_part add_accelerator                     ddl_algorithm_lock_option |
   alter_table_part drop_accelerator                    ddl_algorithm_lock_option |
   alter_table_part drop_accelerator                    ddl_algorithm_lock_option |
   alter_table_part drop_accelerator                    ddl_algorithm_lock_option |
   alter_table_part drop_accelerator                    ddl_algorithm_lock_option |
   alter_table_part add_accelerator  , add_accelerator  ddl_algorithm_lock_option |
   alter_table_part drop_accelerator , drop_accelerator ddl_algorithm_lock_option |
   alter_table_part drop_accelerator , add_accelerator  ddl_algorithm_lock_option |
   rename_column                                        ddl_algorithm_lock_option |
   null_notnull_column                                  ddl_algorithm_lock_option |
   alter_table_part MODIFY modify_column                ddl_algorithm_lock_option |
   alter_table_part MODIFY modify_column                ddl_algorithm_lock_option |
   move_column                                          ddl_algorithm_lock_option |
   chaos_column                                         ddl_algorithm_lock_option |
   # ddl_algorithm_lock_option is within the replace_column sequence.
   replace_column                                                                 |
   # Some DDLs do not support ddl_algorithm_lock_option.
   check_table                                                                    |
#  TRUNCATE TABLE table_names                                                     |
#  alter_table_part enable_disable KEYS                                           |
   # It is some rather arbitrary decision to place kill* and block_stage here.
   # But both have like most DDL some heavy impact.
#  block_stage                                                                    |
   kill_query_or_session_or_release                                               ;

ignore:
          |
          |
          |
          |
   IGNORE ;

alter_table_part:
   ALTER ignore TABLE table_names ;

chaos_column:
# Basic idea
# - have a length in bytes = 3 which is not the usual 2, 4 or more
# - let the column stray like it exists/does not exist/gets moved to other position
   alter_table_part ADD    COLUMN IF NOT EXISTS col_date DATE DEFAULT CURDATE() |
   alter_table_part DROP   COLUMN IF EXISTS col_date                            |
   alter_table_part MODIFY COLUMN IF EXISTS col_date DATE column_position       ;

move_column:
# Unfortunately I cannot prevent that the column type gets maybe changed.
   random_column_properties alter_table_part MODIFY COLUMN $col_name $col_type column_position ;

null_notnull_column:
# Unfortunately I cannot prevent that the column type gets maybe changed.
   random_column_properties alter_table_part MODIFY COLUMN $col_name $col_type null_not_null ;
null_not_null:
   NULL     |
   NOT NULL ;

int_bigint:
   INT     |
   BIGINT  ;

enable_disable:
   ENABLE  |
   DISABLE ;

ddl_algorithm_lock_option:
#                             |
#  , ddl_algorithm            |
#  , ddl_lock                 |
   , ddl_algorithm , ddl_lock |
   , ddl_lock , ddl_algorithm ;

ddl_algorithm:
#  ALGORITHM = DEFAULT |
#  ALGORITHM = INSTANT |
   ALGORITHM = NOCOPY  ;
#  ALGORITHM = INPLACE |
#  ALGORITHM = COPY    ;

ddl_lock:
   LOCK = DEFAULT   |
   LOCK = NONE      |
   LOCK = SHARED    |
   LOCK = EXCLUSIVE ;

fail_007:
   { $fail = 'my_fail_007' ; return undef }; SELECT * FROM $fail ;


add_accelerator:
   ADD  UNIQUE   key_or_index if_not_exists_mostly  uidx_name ( column_name_list_for_key ) |
   ADD           key_or_index if_not_exists_mostly   idx_name ( column_name_list_for_key ) |
#  ADD  PRIMARY  KEY          if_not_exists_mostly            ( column_name_list_for_key ) |
   ADD  FULLTEXT key_or_index if_not_exists_mostly ftidx_name ( column_name_list_for_fts ) ;

drop_accelerator:
   DROP         key_or_index  uidx_name |
   DROP         key_or_index   idx_name |
   DROP         key_or_index ftidx_name ;
#  DROP PRIMARY KEY                     ;

key_or_index:
   INDEX |
   KEY   ;

check_table:
   CHECK TABLE table_names EXTENDED ;

column_position:
                            |
   FIRST                    |
   AFTER random_column_name ;

column_name_int:
   { $column_name_int= 'col1' }    |
   { $column_name_int= 'col2' }    |
   { $column_name_int= 'col_int' } ;

column_name_list_for_key:
   random_column_properties $col_idx direction                                              |
   random_column_properties $col_idx direction, random_column_properties $col_idx direction ;

column_name_list_for_fts:
   column_name_fts                   |
   column_name_fts , column_name_fts ;

column_name_fts:
   string_col_name $col_name |
   col_varchar               |
   col_text                  ;

direction:
   /*!100800 ASC */  |
   /*!100800 DESC */ ;

uidx_name:
   idx_name_prefix { $name = "`$idx_name_prefix" . "uidx1`";  return undef } name_convert |
   idx_name_prefix { $name = "`$idx_name_prefix" . "uidx2`";  return undef } name_convert |
   idx_name_prefix { $name = "`$idx_name_prefix" . "uidx3`";  return undef } name_convert ;
idx_name:
   idx_name_prefix { $name = "`$idx_name_prefix" . "idx1`";   return undef } name_convert |
   idx_name_prefix { $name = "`$idx_name_prefix" . "idx2`";   return undef } name_convert |
   idx_name_prefix { $name = "`$idx_name_prefix" . "idx3`";   return undef } name_convert ;
ftidx_name:
   idx_name_prefix { $name = "`$idx_name_prefix" . "ftidx1`"; return undef } name_convert |
   idx_name_prefix { $name = "`$idx_name_prefix" . "ftidx2`"; return undef } name_convert |
   idx_name_prefix { $name = "`$idx_name_prefix" . "ftidx3`"; return undef } name_convert ;

# The hope is that the 'ã' makes some stress.
idx_name_prefix:
   { $idx_name_prefix = ''        ; return undef } |
   { $idx_name_prefix = 'Marvão_' ; return undef } ;

random_column_name:
# The import differences to the rule 'random_column_properties' are
# 1. No replacing of content in the variables $col_name , $col_type , $col_idx
#    ==> No impact on text of remaining statement sequence.
# 2. The column name just gets printed(returned).
   col1         |
   col2         |
   col_int      |
   col_int_g    |
   col_varchar  |
   col_string   |
   col_string_g |
   col_text     |
   col_text_g   ;

fail_008:
   { $fail = 'my_fail_008' ; return undef }; SELECT * FROM $fail ;

#===========================================================
# Concept of "replace_column"
# ---------------------------
# Add a logical (maybe not the same data type but a compatible data type) copy of some column.
# Fill that new column with data taken from the original.
# Drop the original column.
# Rename the new column to the original one.
replace_column:
   random_column_properties   replace_column_add ; replace_column_update ; replace_column_drop ; replace_column_rename |
   random_column_g_properties replace_column_add ;                         replace_column_drop ; replace_column_rename ;

replace_column_add:
   alter_table_part ADD COLUMN if_not_exists_mostly {$forget= $col_name."_copy"} $col_type column_position ddl_algorithm_lock_option ;
replace_column_update:
   UPDATE table_names SET $forget = $col_name ;
replace_column_drop:
   alter_table_part DROP COLUMN if_exists_mostly $col_name ddl_algorithm_lock_option ;
replace_column_rename:
   # Unfortunately I cannot prevent that the column type gets maybe changed.
   alter_table_part CHANGE COLUMN if_exists_mostly $forget {$name = $col_name; return undef} name_convert $col_type ddl_algorithm_lock_option ;
#===========================================================
# Names should be compared case insensitive.
# Given the fact that the current test should hunt bugs in
# - storage engine only or
# - server -- storage engine relation
# I hope its sufficient to mangle column and index names within the column or index related DDL but
# not in other SQL.
rename_column:
   # Unfortunately I cannot prevent that the column type gets maybe changed.
   rename_column_begin {$name = $col_name; return undef} name_convert $col_name $col_type |
   rename_column_begin {$name = $col_name; return undef} $col_name name_convert $col_type ;
rename_column_begin:
   random_column_properties alter_table_part CHANGE COLUMN if_exists_mostly ;
name_convert:
   $name                                                                                                   |
   $name                                                                                                   |
   $name                                                                                                   |
   $name                                                                                                   |
   $name                                                                                                   |
   $name                                                                                                   |
   $name                                                                                                   |
   $name                                                                                                   |
   get_cdigit {if ($cdigit > length($name)) { $cdigit = length($name)} ; $val = substr($name, 0, $cdigit - 1) . uc(substr($name, $cdigit - 1, 1)) . substr($name, $cdigit) ; return $val} |
   get_cdigit {if ($cdigit > length($name)) { $cdigit = length($name)} ; $val = substr($name, 0, $cdigit - 1) . lc(substr($name, $cdigit - 1, 1)) . substr($name, $cdigit) ; return $val} |
   $name                                                                                                   ;
get_cdigit:
   {$cdigit = $prng->int(1,10); return undef} ;
#----------------------------------------------------------
# For https://jira.mariadb.org/browse/MDEV-16849 Extending indexed VARCHAR column should be instantaneous
# 1. Since 10.2.2 we get a instantaneous change of the maximum length of a VARCHAR column when the length is
#    increasing and not crossing the 255-byte boundary.
#    When the VARCHAR column was indexed than the indexes would be dropped and added again.
# 2. MDEV-16849 adds
#    The drop+add of indexes gets avoided.
# 3. If in ROW_FORMAT=REDUNDANT, we can also extend VARCHAR from any size to any size. The limitation
#    regarding the 255-byte maximum length only applies to other ROW_FORMAT.
# FIXME: Complete the implementation.
resize_varchar:
   col_varchar_properties alter_table_part MODIFY COLUMN $col_name $col_type |
                                                                           ;

# MDEV-5336 Implement LOCK FOR BACKUP
# ===================================
#
# New SQLs ordered by intended workflow for mariabackup
# -----------------------------------------------------
# BACKUP STAGE START (former stage 1)
#   Start service to log changed tables.
#   Block purge of redo files (needed at least for Aria, not needed for InnoDB).
#   Make a checkpoint for all transactional tables (to speed up recovery of backup).
#   Note that the checkpoint is not critical, just a minor optimization.
#
#   mariabackup can now copy all transactional tables and redo logs
#   Next lock is taken after all copying is done.
# BACKUP STAGE FLUSH (former stage 2)
#   FLUSH all changes for not active non transactional tables, except for statistics and log tables.
#   Close the tables, to ensure they are marked as closed after backup.
#   BLOCK all new write row locks for all non transactional tables (except statistics/log tables).
#   Mark all active non transactional tables (except statistics/log tables) to be flushed and closed
#   at end of statement. When last instance of a table is flushed (and the table is marked as read
#   only by all users, we should call handler->extra(EXTRA_MARK_CLOSED). This is needed to handle
#   the case that somone opens a tables as read only while the table is still in use, in which case
#   the table would never have been closed by everyone.
#   The following DDL's doesn't have to be blocked as they can't set the table in a
#   non consistent state: CREATE, RENAME, DROP
#   CREATE ... SELECT, TRUNCATE and ALTER should be blocked for non transactional tables.
#
#   Next lock can be taken directly after this lock.
#   While waiting for the next lock mariabackup can start copying all non transactional tables that
#   are not in use. This list of used tables can be found in information schema.
# BACKUP STAGE BLOCK_DDL (former stage 3)
#   Wait for all statements using write locked non-transactional tables to end. This should be
#   done as we do with FTWRL, which aborts any current locks.
#   This solves the deadlock that Sergei commented upon.
#   While waiting it could report to the client non-transactional tables as soon as they become
#   unused, so that the client could copy them while waiting for other tables.
#   Block TRUNCATE TABLE, CREATE TABLE, DROP TABLE and RENAME TABLE.
#   Block also start of a new ALTER TABLE and the final rename phase of ALTER TABLE.
#   Running ALTER TABLES are not blocked.
#   Inline ALTER TABLE'S should be blocked just before copying is completed.
#   This will probably require a callback from the InnoDB code.
#   Next lock can be taken directly after this lock.
#   While waiting for the next lock mariabackup tool can start copying:
#   The rest of the non-transactional tables (as found from information schema)
#   All .frm, .trn and other system files,
#   New tables created during stage 1-2. The file names can be read from the
#   new changed tables service. This log also allow the backup to do renames
#   of tables on which RENAME's where done instead of copying them.
#   Copy changes to system log tables (this is easy as these are append only)
#   If there is a lot of new tables to copy, one should be able to go back to BACKUP STAGE 2
#   from STAGE to allow ddl's to proceed while copying and then retrying stage 3.
# BACKUP STAGE BLOCK_COMMIT
#   Lock the binary log and commit/rollback to ensure that no changes are committed to any tables.
#   If there are active data copied to the binary log this will be copied before the lock is
#   granted. This doesn't lock temporary tables that are not used by replication.
#   Lock system log tables and statistics tables and close them.
#   When STAGE 4 returns, this is the 'backup time'.
#   Everything commited will be in the backup and everything not committed will roll back.
#   Transactional engines will continue to do changes to the redo log during stage 4, but this
#   is not important as all of these will roll back later.
#   mariabackup can now copy the last changes to the redo files for InnoDB and Aria, and the part
#   of the binary log that was not copied before.
#   End of system log tables and all statistics tables are also copied.
# BACKUP STAGE END
#   Call new handler call 'end_backup()' handler call, which will enable purge of redo files.
#
# Basic ideas:
# - A sequence of the SQL's above in the right order.  Small sleep between the SQL's?
# - One of the SQL's above diced. (== Wrong programmed backup tool). -- Use rare
# - Two sequence runner. == Use rare --> Check first in MTR
#
block_stage:
   block_stage_sequence        |
   block_stage_diced           ;

block_stage_sequence:
   BACKUP STAGE START ; small_sleep BACKUP STAGE FLUSH ; small_sleep BACKUP STAGE BLOCK_DDL ; small_sleep BACKUP STAGE BLOCK_COMMIT; small_sleep BACKUP STAGE END ;
block_stage_diced:
   BACKUP STAGE START           |
   BACKUP STAGE FLUSH           |
   BACKUP STAGE BLOCK_DDL       |
   BACKUP STAGE BLOCK_COMMIT    |
   BACKUP STAGE END             ;

small_sleep:
   { sleep 0.5 ; return undef } |
   { sleep 1.5 ; return undef } |
   { sleep 2.5 ; return undef } ;

fail_009:
   { $fail = 'my_fail_009' ; return undef }; SELECT * FROM $fail ;

#######################
# 1. Have the alternatives
#    a) <nothing>
#    b) IF NOT EXISTS
#    because https://mariadb.com/kb/en/library/alter-table/ mentions
#    ... queries will not report errors when the condition is triggered for that clause.
#    ... the ALTER will move on to the next clause in the statement (or end if finished).
#    So cause that in case of already existing objects all possible kinds of fate are generated.
# 2. "IF NOT EXISTS" gets more frequent generated because that reduces the fraction
#    of failing statements. --> "Nicer" output + most probably more stress
# 3. <nothing> as first alternative is assumed to be better for grammar simplification.
#
if_not_exists_mostly:
                 |
   IF NOT EXISTS |
   IF NOT EXISTS ;
if_exists_mostly:
                 |
   IF     EXISTS |
   IF     EXISTS ;

random_column_properties:
   col1_properties         |
   col2_properties         |
   col_int_properties      |
   col_string_properties   |
   col_text_properties     ;

random_column_g_properties:
   col_int_g_properties    |
   col_string_g_properties |
   col_text_g_properties   ;

###### col<number_or_type>_properties
# Get the properties for some random picked column.
#    $col_name -- column name like "col1"
#    $col_type -- column base type like "TEXT"
#    $col_idx  -- part of key definition related to the base column (Main question: Full column or prefix or both).
#
col1_properties:
             { $col_name= "col1"         ; $col_type= "INT"                                                                     ; return undef } col_to_idx ;
col2_properties:
             { $col_name= "col2"         ; $col_type= "INT"                                                                     ; return undef } col_to_idx ;

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------
# col_varchar and col_text could be/are used roughly the same way except that col_text could keep longer values.
col_varchar_properties:
             { $col_name= "col_varchar"  ; $col_type= "VARCHAR(500)"                                                            ; return undef } col_to_idx_both ;
col_varchar_g_properties:
   gcol_prop { $col_name= "col_varchar_g"; $col_type= "VARCHAR(500) GENERATED ALWAYS AS (SUBSTR(col_varchar,1,499)) $gcol_prop" ; return undef } col_to_idx_both ;

col_text_properties:
             { $col_name= "col_text"     ; $col_type= "TEXT"                                                                    ; return undef } col9_to_idx ;
col_text_g_properties:
   gcol_prop { $col_name= "col_text_g"   ; $col_type= "TEXT         GENERATED ALWAYS AS (SUBSTR(col_text,1,499))    $gcol_prop" ; return undef } col9_to_idx ;

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------
# col_string is dedicated to switching between CHAR and VARCHAR and size 19 and 20
# Base idea:
# - column value size = 10 --> no problem with the column size used (19 or 20)
# - column size (19 or 20) is all time a bit longer than the maybe used prefix size for index (9)
# - the purpose of the    if ( 1 < ( time() + 1 ) % 4 ) { ... } else { ... }
#   is to reduce the frequency of data type alternations so that we have some increased
#   likelihood for
#   - change column name but not the type
#   - change column position but not the type
#   ...
col_string_properties:
   string_col_name string_col_type col_to_idx_both ;

string_col_name:
   { $col_name= "col_string" ; return undef } ;
string_col_type:
   char_or_varchar size19_or_size20 ;
char_or_varchar:
   { $col_type = "VARCHAR" ; return undef } |
   { $col_type = "CHAR"    ; return undef } ;
size19_or_size20:
   { $col_size = 19 ; $col_type .= "($col_size)" ; return undef } |
   { $col_size = 20 ; $col_type .= "($col_size)" ; return undef } ;
string_fill:
   REPEAT(SUBSTR(CAST( $my_int AS CHAR),1,1), 10) ;

col_string_g_properties:
   string_g_col_name string_g_col_type col_to_idx_both ;
string_g_col_name:
   { $col_name= "col_string_g" ; return undef } ;
string_g_col_type:
   # RTRIM is required for preventing that the DDL fails with
   # ER_GENERATED_COLUMN_FUNCTION_IS_NOT_ALLOWED (1901) if col_string has type CHAR
   char_or_varchar size12_or_size13 gcol_prop { $col_type .= " GENERATED ALWAYS AS (SUBSTR(RTRIM(col_string),4,$col_size)) $gcol_prop" ; return undef } ;
size12_or_size13:
   { $col_size = 12 ; $col_type .= "($col_size)" ; return undef } |
   { $col_size = 13 ; $col_type .= "($col_size)" ; return undef } ;

col_to_idx_both:
   col_to_idx  |
   col9_to_idx ;

col_to_idx:
   { $col_idx= $col_name         ; return undef } ;
col9_to_idx:
   { $col_idx= $col_name . "(9)" ; return undef } ;

fail_010:
   { $fail = 'my_fail_010' ; return undef }; SELECT * FROM $fail ;



col_int_properties:
             { $col_name= "col_int"      ; $col_type= "INTEGER"                                                                 ; return undef } col_to_idx ;
col_int_g_properties:
   gcol_prop { $col_name= "col_int_g"    ; $col_type= "INTEGER      GENERATED ALWAYS AS (col_int)                   $gcol_prop" ; return undef } col_to_idx ;
col_int_idx:
   { $col_idx= $col_name          ; return undef } ;

col_float_properties:
             { $col_name= "col_float"    ; $col_type= "FLOAT"                                                                   ; return undef } col_to_idx ;
col_float_g_properties:
   gcol_prop { $col_name= "col_float_g"  ; $col_type= "FLOAT        GENERATED ALWAYS AS (col_float)                 $gcol_prop" ; return undef } col_to_idx ;

gcol_prop:
# The higher share of VIRTUAL is intentional because users might prefer that and VIRTUAL is per experience more error prone.
   { $gcol_prop = "PERSISTENT"    ; return undef }   |
   { $gcol_prop = "VIRTUAL"       ; return undef }   |
   { $gcol_prop = "VIRTUAL"       ; return undef }   ;

######
# For playing around with
#   SET DEBUG_DBUG='+d,ib_build_indexes_too_many_concurrent_trxs, ib_rename_indexes_too_many_concurrent_trxs, ib_drop_index_too_many_concurrent_trxs';
#   SET DEBUG_DBUG='+d,create_index_fail';
# and similar add a redefine file like
#   conf/mariadb/ts_dbug_innodb.yy
#
set_dbug:
   ;

set_dbug_null:
   ;

fail_011:
   { $fail = 'my_fail_011' ; return undef }; SELECT * FROM $fail ;

modify_column:
   column_name_int                  int_bigint                    |
   column_name_int                  int_bigint                    |
   column_name_int                  int_bigint                    |
   col_string_properties  $col_name $col_type alt_charset_collate |
   col_text_properties    $col_name $col_type alt_charset_collate |
   col_varchar_properties $col_name $col_type alt_charset_collate ;

alt_charset_collate:
   alt_charset_collate_allowed                                   |
   alt_charset_collate_allowed                                   |
   alt_charset_collate_allowed                                   |
   alt_charset_collate_allowed                                   |
   alt_charset_collate_allowed                                   |
   alt_charset_collate_allowed                                   |
   alt_charset_collate_allowed                                   |
   alt_charset_collate_allowed                                   |
   alt_charset_collate_allowed                                   |
   alt_charset_collate_allowed                                   |
   # Frequent disallowed combinations
   CHARACTER SET alt_character_set_all COLLATE alt_collation_all ;

alt_charset_collate_allowed:
   CHARACTER SET latin1                COLLATE alt_collation_latin1  |
   CHARACTER SET utf8                  COLLATE alt_collation_utf8    |
   CHARACTER SET utf8mb3               COLLATE alt_collation_utf8mb3 |
   CHARACTER SET utf8mb4               COLLATE alt_collation_utf8mb4 ;

alt_collation_latin1:
   latin1_bin  | latin1_general_cs | latin1_general_ci ;
alt_collation_utf8:
   utf8_bin    | utf8_nopad_bin    | utf8_general_ci ;
alt_collation_utf8mb3:
   utf8mb3_bin | utf8mb3_nopad_bin | utf8mb3_general_nopad_ci | utf8mb3_general_ci ;
alt_collation_utf8mb4:
   utf8mb4_bin | utf8mb4_nopad_bin | utf8mb4_general_nopad_ci | utf8mb4_general_ci ;
alt_collation_all:
   alt_collation_latin1  |
   alt_collation_utf8    |
   alt_collation_utf8mb3 |
   alt_collation_utf8mb4 ;

alt_character_set_all:
   latin1  |
   utf8    |
   utf8mb3 |
   utf8mb4 ;

