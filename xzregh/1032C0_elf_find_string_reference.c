// /home/kali/xzre-ghidra/xzregh/1032C0_elf_find_string_reference.c
// Function: elf_find_string_reference @ 0x1032C0
// Calling convention: __stdcall
// Prototype: u8 * __stdcall elf_find_string_reference(elf_info_t * elf_info, EncodedStringId encoded_string_id, u8 * code_start, u8 * code_end)


/*
 * AutoDoc: Single-slot helper for the string catalogue. It emits a secret-data breadcrumb, then repeatedly calls `elf_find_string` (resuming from the last rodata pointer) until the requested `encoded_string_id` is encountered.
 * Each discovery is checked with `find_string_reference` inside `[code_start, code_end)`, and the first instruction that materialises the literal is returned so later passes can clamp function ranges around it. Telemetry failures or missing xrefs return NULL.
 */

#include "xzre_types.h"

u8 * elf_find_string_reference
               (elf_info_t *elf_info,EncodedStringId encoded_string_id,u8 *code_start,u8 *code_end)

{
  BOOL telemetry_ok;
  char *string_cursor;
  u8 *xref_site;
  EncodedStringId string_id_cursor;
  
  string_id_cursor = encoded_string_id;
  // AutoDoc: Abort the scan if we cannot log the breadcrumb—string hunts only run when the secret-data recorder is active.
  telemetry_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xd2,4,0xd,FALSE);
  if (telemetry_ok != FALSE) {
    string_cursor = (char *)0x0;
    // AutoDoc: Walk `.rodata`, resuming from the previous pointer so every occurrence of the encoded literal is examined.
    while (string_cursor = elf_find_string(elf_info,&string_id_cursor,string_cursor), string_cursor != (char *)0x0) {
      // AutoDoc: Return the first LEA/MOV inside the requested code window that materialises this literal.
      xref_site = find_string_reference(code_start,code_end,string_cursor);
      if (xref_site != (u8 *)0x0) {
        return xref_site;
      }
      string_cursor = string_cursor + 1;
    }
  }
  return (u8 *)0x0;
}

