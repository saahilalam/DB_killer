query_add:
    # By using the rule innodb_log_file_buffering_set it happens a bit less frequent.
    innodb_log_file_buffering_set ;

innodb_log_file_buffering_set:
    SET GLOBAL innodb_log_file_buffering =  default |
    SET GLOBAL innodb_log_file_buffering =  on      |
    SET GLOBAL innodb_log_file_buffering =  off     ;
