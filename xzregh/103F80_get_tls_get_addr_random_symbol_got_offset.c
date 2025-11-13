// /home/kali/xzre-ghidra/xzregh/103F80_get_tls_get_addr_random_symbol_got_offset.c
// Function: get_tls_get_addr_random_symbol_got_offset @ 0x103F80
// Calling convention: unknown
// Prototype: undefined get_tls_get_addr_random_symbol_got_offset(void)


/*
 * AutoDoc: Seeds `ctx->got_ctx.got_ptr` and `ctx->got_ctx.got_offset` with the canned values associated
 * with the fake `__tls_get_addr` symbol. The loader uses those numbers as the starting point for
 * `update_got_address`, which refines them into the concrete GOT entry address.
 */
#include "xzre_types.h"


void get_tls_get_addr_random_symbol_got_offset(long param_1)

{
  *(undefined8 *)(param_1 + 8) = 0x2600;
  *(undefined8 *)(param_1 + 0x20) = elf_functions_offset;
  return;
}

