// /home/kali/xzre-ghidra/xzregh/10A700_cpuid_gcc.c
// Function: _cpuid_gcc @ 0x10A700
// Calling convention: __stdcall
// Prototype: void __stdcall _cpuid_gcc(uint level, uint * a, uint * b, uint * c, uint * d)


/*
 * AutoDoc: GCC-style CPUID shim that dispatches through the individual helper thunks for every supported leaf (basic, cache, topology,
 * extended brand strings, etc.). Whatever leaf pointer it chooses has EAX/EBX/ECX/EDX copied into the provided outputs so callers
 * don’t need inline assembly.
 */

#include "xzre_types.h"

void _cpuid_gcc(uint level,uint *a,uint *b,uint *c,uint *d)

{
  uint *leaf_info;
  uint ebx_val;
  uint ecx_val;
  uint edx_val;
  
  if (level == 0) {
    leaf_info = (uint *)cpuid_basic_info(0);
  }
  else if (level == 1) {
    leaf_info = (uint *)cpuid_Version_info(1);
  }
  else if (level == 2) {
    leaf_info = (uint *)cpuid_cache_tlb_info(2);
  }
  else if (level == 3) {
    leaf_info = (uint *)cpuid_serial_info(3);
  }
  else if (level == 4) {
    leaf_info = (uint *)cpuid_Deterministic_Cache_Parameters_info(4);
  }
  else if (level == 5) {
    leaf_info = (uint *)cpuid_MONITOR_MWAIT_Features_info(5);
  }
  else if (level == 6) {
    leaf_info = (uint *)cpuid_Thermal_Power_Management_info(6);
  }
  else if (level == 7) {
    leaf_info = (uint *)cpuid_Extended_Feature_Enumeration_info(7);
  }
  else if (level == 9) {
    leaf_info = (uint *)cpuid_Direct_Cache_Access_info(9);
  }
  else if (level == 10) {
    leaf_info = (uint *)cpuid_Architectural_Performance_Monitoring_info(10);
  }
  else if (level == 0xb) {
    leaf_info = (uint *)cpuid_Extended_Topology_info(0xb);
  }
  else if (level == 0xd) {
    leaf_info = (uint *)cpuid_Processor_Extended_States_info(0xd);
  }
  else if (level == 0xf) {
    leaf_info = (uint *)cpuid_Quality_of_Service_info(0xf);
  }
  else if (level == 0x80000002) {
    leaf_info = (uint *)cpuid_brand_part1_info(0x80000002);
  }
  else if (level == 0x80000003) {
    leaf_info = (uint *)cpuid_brand_part2_info(0x80000003);
  }
  else if (level == 0x80000004) {
    leaf_info = (uint *)cpuid_brand_part3_info(0x80000004);
  }
  else {
    leaf_info = (uint *)cpuid(level);
  }
  ebx_val = leaf_info[1];
  ecx_val = leaf_info[2];
  edx_val = leaf_info[3];
  *a = *leaf_info;
  *b = ebx_val;
  *c = edx_val;
  *d = ecx_val;
  return;
}

