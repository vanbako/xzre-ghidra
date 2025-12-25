// /home/kali/xzre-ghidra/xzregh/10A800_get_cpuid_with_ifunc_bootstrap.c
// Function: get_cpuid_with_ifunc_bootstrap @ 0x10A800
// Calling convention: __stdcall
// Prototype: uint __stdcall get_cpuid_with_ifunc_bootstrap(cpuid_leaf_t leaf, uint * eax, uint * ebx, uint * ecx, uint * edx, u64 * caller_frame)


/*
 * AutoDoc: Exported resolver glibc binds as `_get_cpuid`/`__get_cpuid`. It first calls `cpuid_ifunc_resolver_entry()` with either leaf 0 or
 * `CPUID_LEAF_EXTENDED_MASK` (depending on the caller’s high bit) so the loader runs before any sshd worker queries CPUID. The returned EAX value is
 * interpreted as the CPU-advertised maximum leaf; only when the requested leaf is <= that bound does it forward the request to the
 * real `cpuid_query_and_unpack()` implementation and report success.
 */

#include "xzre_types.h"

uint get_cpuid_with_ifunc_bootstrap
               (cpuid_leaf_t leaf,uint *eax,uint *ebx,uint *ecx,uint *edx,u64 *caller_frame)

{
  uint max_leaf;
  uint leaf_supported;
  
  // AutoDoc: Force the IFUNC resolver to run (and thus the loader to initialize) before satisfying any caller-supplied leaf.
  max_leaf = cpuid_ifunc_resolver_entry(leaf & CPUID_LEAF_EXTENDED_MASK,caller_frame);
  // AutoDoc: Reject callers that ask for leaves the CPU refused to advertise—glibc expects us to return FALSE instead of faulting.
  if ((max_leaf == CPUID_LEAF_BASIC_INFO) || ((uint)max_leaf < (uint)leaf)) {
    leaf_supported = 0;
  }
  else {
    // AutoDoc: Defer to the shared dispatcher once we know the leaf is valid; the helper mirrors GCC’s register order.
    cpuid_query_and_unpack(leaf,eax,ebx,ecx,edx);
    leaf_supported = 1;
  }
  return leaf_supported;
}

