// /home/kali/xzre-ghidra/xzregh/1032C0_elf_find_string_reference.c
// Function: elf_find_string_reference @ 0x1032C0
// Calling convention: __stdcall
// Prototype: u8 * __stdcall elf_find_string_reference(elf_info_t * elf_info, EncodedStringId encoded_string_id, u8 * code_start, u8 * code_end)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief finds an instruction that references the given string
 *
 *   @param elf_info the parsed ELF context
 *   @param encoded_string_id the string to search for, in encoded form
 *   @param code_start address to start searching from
 *   @param code_end address to stop searching at
 *   @return u8* the address of the first instruction that references the given string, or NULL if not found
 */

u8 * elf_find_string_reference
               (elf_info_t *elf_info,EncodedStringId encoded_string_id,u8 *code_start,u8 *code_end)

{
  BOOL BVar1;
  char *pcVar2;
  u8 *puVar3;
  EncodedStringId local_2c;
  
  local_2c = encoded_string_id;
  BVar1 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xd2,4,0xd,0);
  if (BVar1 != 0) {
    pcVar2 = (char *)0x0;
    while (pcVar2 = elf_find_string(elf_info,&local_2c,pcVar2), pcVar2 != (char *)0x0) {
      puVar3 = find_string_reference(code_start,code_end,pcVar2);
      if (puVar3 != (u8 *)0x0) {
        return puVar3;
      }
      pcVar2 = pcVar2 + 1;
    }
  }
  return (u8 *)0x0;
}

