# For
# MDEV-30136 Map innodb_flush_method to new settable Booleans innodb_{log,data}_file_{buffering,write_through}

file_buffering_write_through_flipper:
    SET GLOBAL fbwt_parameter = fbwt_value ;

fbwt_value:
    OFF |
    ON  ;

fbwt_parameter:
    innodb_log_file_buffering 	   |
    innodb_log_file_write_through  |
    innodb_data_file_buffering     |
    innodb_data_file_write_through ;

query_add:
    file_buffering_write_through_flipper |
    query                                |
    query                                |
    query                                |
    query                                |
    query                                |
    query                                |
    query                                ;
