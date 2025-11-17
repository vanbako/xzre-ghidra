// /home/kali/xzre-ghidra/xzregh/100BA0_find_function.c
// Function: find_function @ 0x100BA0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_function(u8 * code_start, void * * func_start, void * * func_end, u8 * search_base, u8 * code_end, FuncFindType find_mode)


/*
 * AutoDoc: Recovers function bounds around an instruction.
 * With `func_start` non-null it scans backward toward `search_base`, checking every byte with `find_function_prologue`; failing to find a match or hitting `search_base` without one aborts.
 * With `func_end` it scans forward to the next prologue (or `code_end`) and uses that address as the end marker, yielding dependable start/end pointers for later string/reloc walkers.
 */

#include "xzre_types.h"

BOOL find_function(u8 *code_start,void **func_start,void **func_end,u8 *search_base,u8 *code_end,
                  FuncFindType find_mode)

{
  BOOL prologue_found;
  u8 *scan_cursor;
  BOOL found;
  u8 *search_to;
  u8 *search_from;
  u8 *p;
  
  p = (u8 *)0x0;
  scan_cursor = code_start;
  if (func_start != (void **)0x0) {
    while ((search_base < scan_cursor &&
           (prologue_found = find_function_prologue(scan_cursor,code_end,&p,find_mode), prologue_found == FALSE))) {
      scan_cursor = scan_cursor + -1;
    }
    scan_cursor = p;
    if ((p == (u8 *)0x0) ||
       ((p == search_base &&
        (prologue_found = find_function_prologue(search_base,code_end,(u8 **)0x0,find_mode), prologue_found == FALSE))
       )) {
      return FALSE;
    }
    *func_start = scan_cursor;
  }
  scan_cursor = code_start + 1;
  if (func_end != (void **)0x0) {
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

