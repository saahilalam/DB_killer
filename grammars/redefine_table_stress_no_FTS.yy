
add_accelerator:
   ADD  UNIQUE   key_or_index if_not_exists_mostly  uidx_name ( column_name_list_for_key ) |
   ADD           key_or_index if_not_exists_mostly   idx_name ( column_name_list_for_key ) |
   ADD  PRIMARY  KEY          if_not_exists_mostly            ( column_name_list_for_key ) ;
   # ADD  FULLTEXT key_or_index if_not_exists_mostly ftidx_name ( col_text                 ) ;

