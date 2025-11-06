// /home/kali/xzre-ghidra/xzregh/10A800_get_cpuid_modified.c
// Function: _get_cpuid_modified @ 0x10A800
// Calling convention: __stdcall
// Prototype: uint __stdcall _get_cpuid_modified(uint leaf, uint * eax, uint * ebx, uint * ecx, uint * edx, u64 * caller_frame)


uint _get_cpuid_modified(uint leaf,uint *eax,uint *ebx,uint *ecx,uint *edx,u64 *caller_frame)

{
  uint uVar1;
  
  uVar1 = backdoor_entry(leaf & 0x80000000,caller_frame);
  if ((uVar1 == 0) || (uVar1 < leaf)) {
    uVar1 = 0;
  }
  else {
    _cpuid_gcc(leaf,eax,ebx,ecx,edx);
    uVar1 = 1;
  }
  return uVar1;
}

