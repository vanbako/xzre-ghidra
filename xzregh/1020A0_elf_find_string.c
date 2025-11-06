// /home/kali/xzre-ghidra/xzregh/1020A0_elf_find_string.c
// Function: elf_find_string @ 0x1020A0
// Calling convention: __stdcall
// Prototype: char * __stdcall elf_find_string(elf_info_t * elf_info, EncodedStringId * stringId_inOut, void * rodata_start_ptr)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Locates a string in the ELF .rodata section
 *
 *   @param elf_info the ELF context to use for the search
 *   @param stringId_inOut mandatory pointer to an encoded string ID.
 *   - if the referenced string ID is 0, the first matching string (in the string table) will stop the search,
 *   and the matching string ID will be written to the pointer.
 *   - if the referenced string ID is not 0, the search will look for that specific string ID,
 *   and the value will not be updated.
 *   @param rodata_start_ptr location in the rodata section to start the search from
 *   @return char* pointer to the string, or NULL if it couldn't be found
 */

char * elf_find_string(elf_info_t *elf_info,EncodedStringId *stringId_inOut,void *rodata_start_ptr)

{
  BOOL BVar1;
  EncodedStringId EVar2;
  char *string_begin;
  char *string_end;
  u64 local_30 [2];
  
  BVar1 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xb6,7,10,0);
  if (BVar1 != 0) {
    local_30[0] = 0;
    string_begin = (char *)elf_get_rodata_segment(elf_info,local_30);
    if ((string_begin != (char *)0x0) && (0x2b < local_30[0])) {
      string_end = string_begin + local_30[0];
      if (rodata_start_ptr != (void *)0x0) {
        if (string_end <= rodata_start_ptr) {
          return (char *)0x0;
        }
        if (string_begin < rodata_start_ptr) {
          string_begin = (char *)rodata_start_ptr;
        }
      }
      for (; string_begin < string_end; string_begin = string_begin + 1) {
        EVar2 = get_string_id(string_begin,string_end);
        if (EVar2 != 0) {
          if (*stringId_inOut == 0) {
            *stringId_inOut = EVar2;
            return string_begin;
          }
          if (*stringId_inOut == EVar2) {
            return string_begin;
          }
        }
      }
    }
  }
  return (char *)0x0;
}

