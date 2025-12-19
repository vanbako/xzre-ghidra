// /home/kali/xzre-ghidra/xzregh/101020_find_string_lea_xref.c
// Function: find_string_lea_xref @ 0x101020
// Calling convention: __stdcall
// Prototype: u8 * __stdcall find_string_lea_xref(u8 * code_start, u8 * code_end, char * str)


/*
 * AutoDoc: Bootstraps the LEA pointer scan used by the string-reference tables.
 * It wipes a scratch `dasm_ctx_t`, runs `find_riprel_lea` across `[code_start, code_end)`, and only considers hits whose computed pointer equals `str`.
 * Success returns the LEA's address so callers can treat that instruction as the reference site; otherwise NULL bubbles up.
 */

#include "xzre_types.h"

u8 * find_string_lea_xref(u8 *code_start,u8 *code_end,char *str)

{
  BOOL lea_found;
  u8 *lea_anchor;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  dasm_ctx_t scratch_ctx;
  
  ctx_clear_cursor = &scratch_ctx;
  // AutoDoc: Reset the scratch decoder before handing it to the LEA searcher.
  for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
    *(u32 *)&ctx_clear_cursor->instruction = 0;
    ctx_clear_cursor = (dasm_ctx_t *)((u8 *)ctx_clear_cursor + 4);
  }
  lea_found = find_riprel_lea(code_start,code_end,&scratch_ctx,str);
  lea_anchor = (u8 *)0x0;
  if (lea_found != FALSE) {
    lea_anchor = scratch_ctx.instruction;
    // AutoDoc: Return the successful LEA's address so string walkers can anchor the xref there.
  }
  return lea_anchor;
}

