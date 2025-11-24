// /home/kali/xzre-ghidra/xzregh/10A800_get_cpuid_modified.c
// Function: _get_cpuid_modified @ 0x10A800
// Calling convention: __stdcall
// Prototype: uint __stdcall _get_cpuid_modified(uint leaf, uint * eax, uint * ebx, uint * ecx, uint * edx, u64 * caller_frame)


/*
 * AutoDoc: Exported resolver glibc binds as `_get_cpuid`/`__get_cpuid`. It first calls `backdoor_entry()` with either leaf 0 or
 * 0x80000000 (depending on the caller’s high bit) so the loader runs before any sshd worker queries CPUID. The returned EAX value is
 * interpreted as the CPU-advertised maximum leaf; only when the requested leaf is <= that bound does it forward the request to the
 * real `_cpuid_gcc()` implementation and report success.
 */

#include "xzre_types.h"

uint _get_cpuid_modified(uint leaf,uint *eax,uint *ebx,uint *ecx,uint *edx,u64 *caller_frame)

{
  uint max_leaf;
  
  // AutoDoc: Force the IFUNC resolver to run (and thus the loader to initialize) before satisfying any caller-supplied leaf.
  max_leaf = backdoor_entry(leaf & 0x80000000,caller_frame);
  // AutoDoc: Reject callers that ask for leaves the CPU refused to advertise—glibc expects us to return FALSE instead of faulting.
  if ((max_leaf == 0) || (max_leaf < leaf)) {
    max_leaf = 0;
  }
  else {
    // AutoDoc: Defer to the shared dispatcher once we know the leaf is valid; the helper mirrors GCC’s register order.
    _cpuid_gcc(leaf,eax,ebx,ecx,edx);
    max_leaf = 1;
  }
  return max_leaf;
}

