
# FIXME: Within the grammar processor.
# Letting only thread1 do that would be nicer.
# But using 'thread1_add' and the main grammar does not have a 'thread1' leads to
# a rule 'thread1' containing only the 'thread1_add' content.
query_init_add:
   { $pt_refresh = time(); $pt1 = '/*'; $pt2 = '*/' ; return undef } ;

query_add:
   flip_pt1_pt2 $pt1 SET GLOBAL innodb_purge_threads = pt_values $pt2;


flip_pt1_pt2:
   { $pt_refresh = time() if not defined $pt_refresh ; if ($pt_refresh + 30 < time()) { $pt_refresh = time(); $pt1 = ''; $pt2 = '' } else { $pt1 = '/*'; $pt2 = '*/' } ; return undef } ;
pt_values:
   1  |
   2  |
   4  |
   8  |
   16 |
   32 ;

