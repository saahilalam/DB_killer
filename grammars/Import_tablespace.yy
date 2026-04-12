# Copyright (c) 2021 MariaDB Corporation
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

# The grammar is check ALTER TABLE ... IMPORT TABLESPACE and its impact on the consistency of
# table and index trees for the case that only ibd files but not cfg files are copied to the
# corresponding destination. See MDEV-20931.
# Basically:
# The Server/InnoDB can execute and pass everything or
# - deny the DDL operation
# - try it, fail and roll back
# - try it, commit and not crash on successing checks
# - try it, commit and declare during successing checks the table or indexes to be corrupt
# but never crash during execution of the IMPORT or during the checks.
#
# Attention
# ---------
# You will need some temporary modified lib/GenTest/Executor/MySQL.pm where nearly all mapping
# to STATUS_DATABASE_CORRUPTION has to be disabled.
# If not the IMPORT of logical not fitting or physical rotten tablespaces etc. could harvest errors
# which get mapped to STATUS_DATABASE_CORRUPTION and cause an abort of the RQG run.
# But we just want to test what would happen if the server stays under further DDL/DML load.
# Without DISCARD/IMPORT a missing tablespace is a serious bug except "playing" with partitions.
# With DISCARD, omitting of copy ibd file to destination followed by IMPORT attempt we will get
# criticized because of missing tablespace. But that is just some failure of the user.
#

query:
    # The next line
    #   set_names flush_for_export ; make_copy unlock_tables ; create_table ; alter_discard ; copy_around alter_import ; drop_table remove_used |
    # does not work like it looks because it
    # - counts as one query
    # - for a query all perl snippets inside of its components get executed first and than the SQL.
    # Observed impact in case of single thread scenario:
    # The CREATE TABLE fails because the ibd file is already in place.
    # And that is caused by the perl snippet in copy_around getting executed before the
    # CREATE TABLE statement.
    # It is also to be assumed that copying the ibd file happens when the table is not yet locked for export.
    #
    # copy_around will only copy if the targetfile does not exist because overwriting some ibd
    # file which is maybe in use is a too dirty operation.
    # Q: What is the impact of
    #    1. Copy an ibd file at some place when none of the existing tables uses that file.
    #    2  Run CREATE TABLE which would use that file.
    #    ?
    #    - refuse the CREATE
    #    or
    #    - remove the ibd file and than CREATE ?
    set_names copy_around   |
    set_names create_table  |
    set_names create_table  |
    set_names alter_discard |
    set_names alter_import  |
    set_names drop_table    ;
    # Disabled because the attempt to remove an ibd file without using DDL is a too dirty operation.
    # set_names remove_used   ;

set_names:
    table_name imp_table_name source_ibd used_ibd ;

table_name:
# The next line is sufficient and elegant
#   { $table_name = $prng->arrayElement(\@ta)    ; return undef } ;
# but it has some bad impact during grammar simplification.
    { $table_name = "table0_innodb" ;              return undef } |
    { $table_name = "table0_innodb_int" ;          return undef } |
    { $table_name = "table0_innodb_varchar_255" ;  return undef } |
    { $table_name = "table1_innodb" ;              return undef } |
    { $table_name = "table1_innodb_int" ;          return undef } |
    { $table_name = "table1_innodb_varchar_255" ;  return undef } |
    { $table_name = "table10_innodb" ;             return undef } |
    { $table_name = "table10_innodb_int" ;         return undef } |
    { $table_name = "table10_innodb_varchar_255" ; return undef } ;

imp_table_name:
    { $imp_table_name = "imp_" . $table_name ; return undef } ;

query_init:
    set_tmp set_table_array ;

thread1_init:
    set_tmp set_table_array ; FLUSH TABLES { $table_list = join(", ", @ta)  } FOR EXPORT ; unlock_tables ;

set_tmp:
    # The "our" is essential!
    { our $tmp = $ENV{TMP} ; return undef } ;

set_table_array:
    { our @ta = ( "table0_innodb", "table0_innodb_int", "table0_innodb_varchar_255", "table1_innodb", "table1_innodb_int", "table1_innodb_varchar_255", "table10_innodb", "table10_innodb_int", "table10_innodb_varchar_255" ) ; return undef } ;

source_ibd:
    { $source_ibd = $tmp . '/1/data/test/' . $table_name     . '.ibd'       ; return undef } ;
used_ibd:
    { $used_ibd   = $tmp . '/1/data/test/' . $imp_table_name . '.ibd'       ; return undef } ;

copy_around:
    # Is not fault tolerant
    { if ( not -e $used_ibd ) { if (not File::Copy::copy($source_ibd, $used_ibd)) { print("ERROR $! during copy_around $table_name .\n"); exit 200 } else { return "/* copy_around $table_name */" } } } ;
remove_used:
    # Is fault tolerant
    { unlink $used_ibd ; return "/* 'remove_ibd' $table_name */" };

create_table:
    CREATE TABLE IF NOT EXISTS $imp_table_name LIKE $table_name ; target_distortion ;

target_distortion:
     | | | | | | | | | | | | | | | | | |
     | | | | | | | | | | | | | | | | | |
    ALTER TABLE $imp_table_name CONVERT TO CHARACTER SET character_set                                ddl_algorithm_lock_option |
    ALTER TABLE $imp_table_name ADD KEY idx ( some_col_to_some_key )                                  ddl_algorithm_lock_option |
    ALTER TABLE $imp_table_name DROP KEY some_col_with_key                                            ddl_algorithm_lock_option |
    ALTER TABLE $imp_table_name ADD PRIMARY KEY ( some_col_to_some_key )                              ddl_algorithm_lock_option |
    # Does not exist in all source tables!
    ALTER TABLE $imp_table_name DROP PRIMARY KEY                                                      ddl_algorithm_lock_option |
    ALTER TABLE $imp_table_name ADD COLUMN col_extra some_type some_position                          ddl_algorithm_lock_option |
    ALTER TABLE $imp_table_name DROP COLUMN some_col                                                  ddl_algorithm_lock_option |
    ALTER TABLE $imp_table_name MODIFY COLUMN some_col some_type some_position                        ddl_algorithm_lock_option |
    ALTER TABLE $imp_table_name ENGINE = InnoDB ROW_FORMAT = row_format PAGE_COMPRESSED = compression ddl_algorithm_lock_option ;
character_set:
    ascii |
    utf8  ;

some_position:
                    |
    FIRST           |
    AFTER some_col  ;

# For DROP COLUMN, move to FIRST, move AFTER, modify type
some_col:
    some_col_with_key               |
    some_col_with_key               |
    some_col_without_key            |
    some_col_without_key            |
    # Does not exist in all source tables!
    pk                              ;

# For rule some_col, DROP KEY
some_col_with_key:
    col_int_key                |
    col_text_latin1_key        |
    col_text_utf8_key          |
    col_varchar_255_latin1_key |
    col_varchar_255_utf8_key   ;

# For rule some_col, ADD KEY
some_col_without_key:
    col_int                    |
    col_text_latin1            |
    col_text_utf8              |
    col_varchar_255_latin1     |
    col_varchar_255_utf8       ;

some_col_to_some_key:
    col_int                    |
    col_text_latin1(12)        |
    col_text_utf8(12)          |
    col_varchar_255_latin1     |
    col_varchar_255_utf8       ;

# For modify type, ADD COLUMN
some_type:
    FLOAT                       null_not_null |
    SMALLINT                    null_not_null |
    INTEGER                     null_not_null |
    BIGINT                      null_not_null |
    VARCHAR(255) latin1_or_utf8 null_not_null |
    VARCHAR(127) latin1_or_utf8 null_not_null |
    VARCHAR(511) latin1_or_utf8 null_not_null |
    TEXT         latin1_or_utf8 null_not_null |
    TEXT         latin1_or_utf8 null_not_null ;

latin1_or_utf8:
    CHARACTER SET latin1       |
    CHARACTER SET utf8         ;


null_not_null:
    # The default is NULL.
    | | | | | | | | | | | | | | | | | |
    NOT NULL |
    NULL     ;
row_format:
    REDUNDANT |
    COMPACT   |
    DYNAMIC   ;
compression:
    0 |
    1 ;
ddl_algorithm_lock_option:
                              |
   , ddl_algorithm            |
   , ddl_lock                 |
   , ddl_algorithm , ddl_lock |
   , ddl_lock , ddl_algorithm ;

ddl_algorithm:
   ALGORITHM = DEFAULT |
   ALGORITHM = INSTANT |
   ALGORITHM = NOCOPY  |
   ALGORITHM = INPLACE |
   ALGORITHM = COPY    ;

ddl_lock:
   LOCK = DEFAULT   |
   LOCK = NONE      |
   LOCK = SHARED    |
   LOCK = EXCLUSIVE ;

drop_table:
    DROP TABLE IF EXISTS $imp_table_name ;

flush_for_export:
    FLUSH TABLES $table_name FOR EXPORT ;
unlock_tables:
    UNLOCK TABLES ;

alter_discard:
    ALTER TABLE $imp_table_name DISCARD TABLESPACE ;

alter_import:
    ALTER TABLE $imp_table_name IMPORT TABLESPACE ;




