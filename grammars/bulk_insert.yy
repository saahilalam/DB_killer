query_add:
  bulk_insert_load ;

bulk_insert_load:
    INSERT INTO _table SELECT * FROM _table |
    generate_outfile ;                  load_infile                 |
    # The optimizations made in MDEV-24621 require that we run LOAD DATA
    # when the checks are disabled.
    # The later enabling of the checks is for preventing to have some maybe
    # bad impact on the behavior of other SQL.
    generate_outfile ; disable_checks ; load_infile ; enable_checks |
    generate_outfile ; disable_checks ; load_infile ; enable_checks ;

bulk_replace_ignore:
  REPLACE |
  IGNORE  ;

generate_outfile:
    SELECT * FROM _table INTO OUTFILE { "'load_$last_table'" } ;
load_infile:
    LOAD DATA INFILE { "'load_$last_table'" } bulk_replace_ignore INTO TABLE { $last_table } ;

disable_checks:
    SET foreign_key_checks = 0, unique_checks = 0 ;

enable_checks:
    SET foreign_key_checks = 1, unique_checks = 1 ;
