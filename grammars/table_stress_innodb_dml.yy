# Copyright (c) 2022 MariaDB Corporation
# Copyright (c) 2023 MariaDB plc
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

# The grammar is dedicated to stress tables with mostly DML and nearly not with DDL.
# The differences to some other grammars of the "table_stress" family is
# 1. DDL-DDL clashes cannot happen because any DDL is performed by thread1.
# 2. There is only one type of DDL-DML clash possible.
#    thread1 runs RENAME TABLE birth . <name> TO test . <same name>
#    thread<n> runs maybe some DML on test . <same name>
# 3. DDL algorithm and lock option are not in scope == Let the system take the defaults.
#
# _digit --> Range 0 till 9

fail_001:
   { $fail = 'my_fail_001' ; return undef }; SELECT * FROM $fail ;


# thread1 manages CREATE of the tables within the init phase.
# thread1 goes with big timeouts. This gives also some variation for the statements taken
# from the rule "query".
thread1_init:
   create_tables ;

thread1:
   check_table                      |
   kill_query_or_session_or_release |
   block_stage                      |
   query                            |
   query                            |
   query                            |
   query                            |
   query                            |
   query                            |
   query                            |
   query                            |
   query                            ;

fail_002:
   { $fail = 'my_fail_002' ; return undef }; SELECT * FROM $fail ;

thread1_connect:
   SET AUTOCOMMIT = 0; SET @fill_amount = (@@innodb_page_size / 2 ) + 1 ; set_big_timeouts ;

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
#   - the excution of a DML
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

correct_rqg_sessions_table:
   UPDATE rqg . rqg_sessions SET processlist_id = CONNECTION_ID() WHERE rqg_id = _thread_id ;

create_tables:
   CREATE SCHEMA birth ;
   c_t_begin t1 c_t_mid ENGINE = InnoDB ROW_FORMAT = Dynamic    ;
   c_t_begin t2 c_t_mid ENGINE = InnoDB ROW_FORMAT = Compressed ;
   c_t_begin t3 c_t_mid ENGINE = InnoDB ROW_FORMAT = Compact    ;
   c_t_begin t4 c_t_mid ENGINE = InnoDB ROW_FORMAT = Redundant  ;
   c_t_begin t5 c_t_mid ENGINE = InnoDB ROW_FORMAT = Compact ENCRYPTED=YES                   ENCRYPTION_KEY_ID=1  ;
   c_t_begin t6 c_t_mid ENGINE = InnoDB ROW_FORMAT = Compact PAGE_COMPRESSED=1                                    ;
   c_t_begin t7 c_t_mid ENGINE = InnoDB ROW_FORMAT = Compact PAGE_COMPRESSED=1 ENCRYPTED=YES ENCRYPTION_KEY_ID=33 ;
   # ddl picks a random table. Lets hope that the amount of DDL's + randomness help sufficient
   # for getting a nice variety of table definitions.
   ddl ; ddl ; ddl ; ddl ; ddl ; ddl ; ddl ; ddl ;
   RENAME TABLE birth . t1 TO test . t1 ;
   RENAME TABLE birth . t2 TO test . t2 ;
   RENAME TABLE birth . t3 TO test . t3 ;
   RENAME TABLE birth . t4 TO test . t4 ;
   RENAME TABLE birth . t5 TO test . t5 ;
   RENAME TABLE birth . t6 TO test . t6 ;
   RENAME TABLE birth . t7 TO test . t7 ;

c_t_begin:
   CREATE TABLE birth . ;
c_t_mid:
   ( non_generated_cols generated_cols ) ;

table_names:
   # Make it possible to use the same table_name multiple times in one query.
   # This is currently not exploited.
   { $table_name = "t1" } |
   { $table_name = "t2" } |
   { $table_name = "t3" } |
   { $table_name = "t4" } |
   { $table_name = "t5" } |
   { $table_name = "t6" } |
   { $table_name = "t7" } ;

non_generated_cols:
   col1 INT, col2 INT, col_int_properties $col_name $col_type , col_string_properties $col_name $col_type, col_varchar_properties $col_name $col_type, col_text_properties $col_name $col_type ;
generated_cols:
                                                                                                                                       |
   , col_int_g_properties $col_name $col_type, col_string_g_properties $col_name $col_type , col_text_g_properties $col_name $col_type ;

query:
   set_dbug ; dml ;         set_dbug_null ;

query_init:
   # Give thread1 some time for DDL.
   { sleep 5 ; return undef } ;

dml:
   # Ensure that the table does not grow endless.                                                                   |
   delete ; COMMIT                                                                                                  |
   # Make likely: Get duplicate key based on the two row INSERT/REPLACE only.                                       |
   enforce_duplicate1 ;                                                                             commit_rollback |
   # Make likely: Get duplicate key based on two row UPDATE only.                                                   |
   enforce_duplicate2 ;                                                                             commit_rollback |
   UPDATE table_names SET column_name_int = my_int ;                                                commit_rollback |
   UPDATE table_names SET column_name_int = my_int ;                                                commit_rollback |
   UPDATE table_names SET column_name_int = my_int ;                                                commit_rollback |
   UPDATE table_names SET col_string_properties $col_name = /* my_int */ string_fill ;              commit_rollback |
   UPDATE table_names SET col_text_properties   $col_name = fill_begin my_int fill_end ;            commit_rollback |
   # Make likely: Get duplicate key based on the row INSERT and the already committed data.                         |
   insert_part ( my_int , $my_int,     $my_int,     string_fill, fill_begin $my_int     fill_end ); commit_rollback |
   insert_part ( my_int , $my_int - 1, $my_int,     string_fill, fill_begin $my_int     fill_end ); commit_rollback |
   insert_part ( my_int , $my_int,     $my_int - 1, string_fill, fill_begin $my_int     fill_end ); commit_rollback |
   insert_part ( my_int , $my_int,     $my_int,     string_fill, fill_begin $my_int - 1 fill_end ); commit_rollback |
   insert_part ( my_int , $my_int, $my_int, string_fill, fill_begin $my_int fill_end ) on_duplicate_variant ; commit_rollback |
   PREPARE stmt FROM " insert_part ( ? , ? , ? , ? , ? ) on_duplicate_variant " ; execute_using ;   commit_rollback ;

on_duplicate_variant:
   ON DUPLICATE KEY UPDATE on_duplicate_variants                         |
   ON DUPLICATE KEY UPDATE on_duplicate_variants , on_duplicate_variants ;
on_duplicate_variants:
# INSERT ... ON DUPLICATE KEY UPDATE is a MariaDB/MySQL extension to the INSERT statement that, if it finds a duplicate unique or primary key,
# will instead perform an UPDATE.
# If more than one unique index is matched, only the first is updated. It is not recommended to use this statement on tables with more than one unique index.
#
# In an INSERT ... ON DUPLICATE KEY UPDATE statement, you can use the VALUES(col_name) function in the UPDATE clause to refer to column values from the
# INSERT portion of the statement. In other words, VALUES(col_name) in the UPDATE clause refers to the value of col_name that would be inserted,
# had no duplicate-key conflict occurred.
   column_name_int = my_int                                     |
   random_column_name_not_g = VALUES($random_column_name_not_g) |
   random_column_name_not_g = $random_column_name_not_g         ;

execute_using:
   EXECUTE stmt USING my_int , $my_int, $my_int, " $my_int ", " $my_int " ;


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
   DELETE FROM table_names WHERE column_name_int = my_int OR $column_name_int IS NULL ;

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
   COMMIT   |
   ROLLBACK ;

# FIXME:
# https://mariadb.com/kb/en/library/wait-and-nowait/
ddl:
   alter_table_part add_accelerator                      |
   alter_table_part add_accelerator                      |
   alter_table_part add_accelerator  , add_accelerator   |
   null_notnull_column                                   |
   move_column                                           |
   alter_table_part MODIFY modify_column                 ;

ignore:
          |
          |
          |
          |
   IGNORE ;

alter_table_part:
   ALTER ignore TABLE birth . table_names ;

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

add_accelerator:
   ADD  UNIQUE   key_or_index if_not_exists_mostly  uidx_name ( column_name_list_for_key ) |
   ADD           key_or_index if_not_exists_mostly   idx_name ( column_name_list_for_key ) |
   ADD  PRIMARY  KEY          if_not_exists_mostly            ( column_name_list_for_key ) |
   ADD  FULLTEXT key_or_index if_not_exists_mostly ftidx_name ( column_name_list_for_fts ) ;

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
   random_column_name_not_g |
   random_column_name_not_g |
   random_column_name_g     ;

random_column_name_not_g:
   { $random_column_name_not_g = 'col1' }          |
   { $random_column_name_not_g = 'col2' }          |
   { $random_column_name_not_g = 'col_int' }       |
   { $random_column_name_not_g = 'col_string' }    |
   { $random_column_name_not_g = 'col_varchar' }   |
   { $random_column_name_not_g = 'col_text' }      ;

random_column_name_g:
   { $random_column_name_g = 'col_int_g' }     |
   { $random_column_name_g = 'col_string_g' }  |
   { $random_column_name_g = 'col_varchar_g' } |
   { $random_column_name_g = 'col_text_g' }    ;

fail_008:
   { $fail = 'my_fail_008' ; return undef }; SELECT * FROM $fail ;

#===========================================================
# Names should be compared case insensitive.
# Given the fact that the current test should hunt bugs in
# - storage engine only or
# - server -- storage engine relation
# I hope its sufficient to mangle column and index names within the column or index related DDL but
# not in other SQL.
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
   col1_properties           |
   col2_properties           |
   col_int_properties        |
   col_string_properties     |
   col_varchar_properties    |
   col_text_properties       ;

random_column_g_properties:
   col_int_g_properties      |
   col_string_g_properties   |
   col_varchar__g_properties |
   col_text_g_properties     ;

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
   col_string_properties  $col_name $col_type alt_charset_collate |
   col_text_properties    $col_name $col_type alt_charset_collate |
   col_varchar_properties $col_name $col_type alt_charset_collate ;

alt_charset_collate:
   alt_charset_collate_allowed                                   ;
#  # Frequent disallowed combinations
#  CHARACTER SET alt_character_set_all COLLATE alt_collation_all ;

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

