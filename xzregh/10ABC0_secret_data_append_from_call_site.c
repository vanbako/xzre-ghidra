// /home/kali/xzre-ghidra/xzregh/10ABC0_secret_data_append_from_call_site.c
// Function: secret_data_append_from_call_site @ 0x10ABC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_call_site(secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index, BOOL bypass)


BOOL secret_data_append_from_call_site
               (secret_data_shift_cursor_t shift_cursor,uint shift_count,uint operation_index,
               BOOL bypass)

{
  uint uVar1;
  u8 *unaff_retaddr;
  
  uVar1 = secret_data_append_singleton
                    ((u8 *)0x0,unaff_retaddr,shift_cursor,shift_count,operation_index);
  return uVar1 | bypass;
}

