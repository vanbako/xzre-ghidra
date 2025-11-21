// /home/kali/xzre-ghidra/xzregh/100BA0_find_function.c
// Function: find_function @ 0x100BA0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_function(u8 * code_start, void * * func_start, void * * func_end, u8 * search_base, u8 * code_end, FuncFindType find_mode)


/*
 * AutoDoc: Wraps `find_function_prologue` to recover the full function bounds surrounding an instruction. When `func_start` is requested it walks backward from `code_start` toward `search_base`, probing each byte with the prologue helper until it finds a landing pad; hitting `search_base` without success aborts. When `func_end` is requested it scans forward until the next prologue (or `code_end`) and uses that offset as the end marker. Successful runs populate whichever out pointers the caller requested so later passes can reason about bounded regions instead of raw addresses.
 */

#include "xzre_types.h"

BOOL find_function(u8 *code_start,void **func_start,void **func_end,u8 *search_base,u8 *code_end,
                  FuncFindType find_mode)

{
  BOOL prologue_found;
  u8 *scan_cursor;
  u8 *prologue_result[2];
  
  prologue_result[0] = (u8 *)0x0;
  scan_cursor = code_start;
  if (func_start != (void **)0x0) {
    // AutoDoc: Walk backward byte-by-byte until we rediscover a prologue or hit the supplied floor.
    while ((search_base < scan_cursor &&
           (prologue_found = find_function_prologue(scan_cursor,code_end,prologue_result,find_mode), prologue_found == FALSE))) {
      scan_cursor = scan_cursor + -1;
    }
    scan_cursor = prologue_result[0];
    if ((prologue_result[0] == (u8 *)0x0) ||
       ((prologue_result[0] == search_base &&
        (prologue_found = find_function_prologue(search_base,code_end,(u8 **)0x0,find_mode), prologue_found == FALSE))
       )) {
      return FALSE;
    }
    *func_start = scan_cursor;
  }
  scan_cursor = code_start + 1;
  if (func_end != (void **)0x0) {
    // AutoDoc: Scan forward until the next landing pad so callers know where the function stops.
    for (; scan_cursor < code_end + -4; scan_cursor = scan_cursor + 1) {
      prologue_found = find_function_prologue(scan_cursor,code_end,(u8 **)0x0,find_mode);
      if (prologue_found != FALSE) goto LAB_00100c78;
    }
    if ((code_end + -4 != scan_cursor) ||
       (prologue_found = find_function_prologue(scan_cursor,code_end,(u8 **)0x0,find_mode), prologue_found != FALSE)) {
LAB_00100c78:
      code_end = scan_cursor;
    }
    *func_end = code_end;
  }
  return TRUE;
}

