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

# The grammar is dedicated to stress tables having a foreign key relationship with concurrent
# - simple DML
# - TRUNCATE
# and was developed for checking patches for https://jira.mariadb.org/browse/MDEV-13564
# TRUNCATE TABLE and undo tablespace truncation are not compatible with Mariabackup.
# The table "unrelated" serves for revealing if some problem hit requires a foreign key
# relationship or not.
# Its not the task of the test to stress other DDL than just TRUNCATE.
#
# Problems replayed (2018-09):
# - not found in JIRA
#   mysqld: storage/innobase/row/row0mysql.cc:1724:
#   void init_fts_doc_id_for_ref(dict_table_t*, ulint*):
#   Assertion `foreign->foreign_table != __null' failed.
# - https://jira.mariadb.org/browse/MDEV-16664
#   InnoDB: Failing assertion: !other_lock || wsrep_thd_is_BF(lock->trx->mysql_thd, FALSE) ||
#           wsrep_thd_is_BF(other_lock->trx->mysql_thd, FALSE) for DELETE
#   and that even is "innodb_lock_schedule_algorithm=fcfs" was set.
#   The latter helped in some other replay test.
#
# 2018-09-05 10.4 : The grammar does not generate invalid SQL syntax.
#

thread1_init:
    create_unrelated ; create_parent ; create_child ;

create_unrelated:
    CREATE TABLE unrelated (a INT PRIMARY KEY) ENGINE = InnoDB ;
create_parent:
    CREATE TABLE parent (a INT PRIMARY KEY) ENGINE = InnoDB ;
create_child:
    CREATE TABLE child (a INT PRIMARY KEY, create_fk_snip ON UPDATE CASCADE) ENGINE = InnoDB ;
create_fk_snip:
    CONSTRAINT fk FOREIGN KEY (a) REFERENCES parent(a) ;

on_action:
    ON UPDATE cascade_restrict                            |
    ON DELETE cascade_restrict                            |
    ON UPDATE cascade_restrict ON DELETE cascade_restrict ;

cascade_restrict:
    CASCADE  |
    RESTRICT ;

thread_connect:
    short_mdl_wait ; SET SESSION innodb_lock_wait_timeout = 1 ;

query_init:
    start_delay ;
start_delay:
    # Avoid that worker threads cause a server crash before reporters are started.
    # This leads often to STATUS_ENVIRONMENT_ERROR though a crash happened.
    { sleep 5; return undef } ;

long_mdl_wait:
    SET SESSION lock_wait_timeout = 10 ;
short_mdl_wait:
    SET SESSION lock_wait_timeout = 2 ;

change_fk:
# Go with long MDL timeout so that the DDL's get a better chance to have success.
    long_mdl_wait ; drop_fk ; add_fk ; short_mdl_wait ;
drop_fk:
    ALTER TABLE child DROP FOREIGN KEY fk ;
add_fk:
    ALTER TABLE child ADD create_fk_snip on_action ;

thread1:
# 'truncate'  -- serve the main purpose of the test
# 'change_fk' -- give coverage for other FOREIGN KEY variants.
# 'dml'       -- prevent running too frequent DDL
    truncate  |
    change_fk |
    dml       |
    dml       |
    dml       |
    dml       |
    dml       ;

truncate:
    TRUNCATE TABLE unrelated     |
    TRUNCATE TABLE rand_fk_table ;

query:
    dml ;

dml:
# More INSERTs than DELETEs because the tables should mostly grow till TRUNCATE maybe shrinks them.
    update |
    insert |
    insert |
    delete ;

insert:
    INSERT INTO rand_table (a) VALUES rand_values ;

update:
    UPDATE rand_table SET a = my_int where ;

delete:
    DELETE FROM unrelated     where |
    DELETE FROM rand_fk_table where ;

where:
# I assume that affecting between 0 to 2 rows gives sufficient coverage.
    WHERE a = my_int               |
    WHERE a = my_int OR a = my_int ;

rand_values:
    ( my_int) |
    ( my_int) , ( my_int) ;

my_int:
# Maybe having some uneven distribution is of some value.
    { $my_int = 1                   } |
    { $my_int = $prng->int(  2,    8) } |
    { $my_int = $prng->int(  9,   64) } |
    { $my_int = $prng->int( 65,  512) } |
    { $my_int = $prng->int(513, 4096) } |
    { $my_int = 'NULL'              } ;


rand_table:
    unrelated |
    parent    |
    child     ;

rand_fk_table:
# The tablename is used for TRUNCATE and DELETE.
    child  |
    child  |
    child  |
    child  |
    child  |
    child  |
    parent ;

