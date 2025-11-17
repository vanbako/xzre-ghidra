// /home/kali/xzre-ghidra/xzregh/1032C0_elf_find_string_reference.c
// Function: elf_find_string_reference @ 0x1032C0
// Calling convention: __stdcall
// Prototype: u8 * __stdcall elf_find_string_reference(elf_info_t * elf_info, EncodedStringId encoded_string_id, u8 * code_start, u8 * code_end)


/*
 * AutoDoc: Single-shot helper for the string catalogue.
 * It repeatedly calls `elf_find_string` until it finds the requested `encoded_string_id`, and for each candidate occurrence it runs `find_string_reference` between `code_start` and `code_end`, returning the first instruction that materialises the literal.
 * Callers fall back to NULL when no xref exists in the supplied range.
 */

#include "xzre_types.h"

u8 * elf_find_string_reference
               (elf_info_t *elf_info,EncodedStringId encoded_string_id,u8 *code_start,u8 *code_end)

{
  BOOL decode_ok;
  char *string_ptr;
  u8 *xref;
  EncodedStringId string_id_cursor;
  
  string_id_cursor = encoded_string_id;
  decode_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xd2,4,0xd,FALSE);
  if (decode_ok != FALSE) {
    string_ptr = (char *)0x0;
    while (string_ptr = elf_find_string(elf_info,&string_id_cursor,string_ptr), string_ptr != (char *)0x0) {
      xref = find_string_reference(code_start,code_end,string_ptr);
      if (xref != (u8 *)0x0) {
        return xref;
      }
      string_ptr = string_ptr + 1;
    }
  }
  return (u8 *)0x0;
}

