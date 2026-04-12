thread1_add:
    query |
    { $itt_refresh = time() if not defined $itt_refresh ; if ($itt_refresh + 15 < time()) { $itt_refresh = time(); return 'SET GLOBAL INNODB_TRUNCATE_TEMPORARY_TABLESPACE_NOW = 1' }};
