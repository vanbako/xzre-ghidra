// /home/kali/xzre-ghidra/xzregh/10A700_cpuid_gcc.c
// Function: _cpuid_gcc @ 0x10A700
// Calling convention: __stdcall
// Prototype: void __stdcall _cpuid_gcc(uint level, uint * a, uint * b, uint * c, uint * d)


void _cpuid_gcc(uint level,uint *a,uint *b,uint *c,uint *d)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  if (level == 0) {
    puVar1 = (uint *)cpuid_basic_info(0);
  }
  else if (level == 1) {
    puVar1 = (uint *)cpuid_Version_info(1);
  }
  else if (level == 2) {
    puVar1 = (uint *)cpuid_cache_tlb_info(2);
  }
  else if (level == 3) {
    puVar1 = (uint *)cpuid_serial_info(3);
  }
  else if (level == 4) {
    puVar1 = (uint *)cpuid_Deterministic_Cache_Parameters_info(4);
  }
  else if (level == 5) {
    puVar1 = (uint *)cpuid_MONITOR_MWAIT_Features_info(5);
  }
  else if (level == 6) {
    puVar1 = (uint *)cpuid_Thermal_Power_Management_info(6);
  }
  else if (level == 7) {
    puVar1 = (uint *)cpuid_Extended_Feature_Enumeration_info(7);
  }
  else if (level == 9) {
    puVar1 = (uint *)cpuid_Direct_Cache_Access_info(9);
  }
  else if (level == 10) {
    puVar1 = (uint *)cpuid_Architectural_Performance_Monitoring_info(10);
  }
  else if (level == 0xb) {
    puVar1 = (uint *)cpuid_Extended_Topology_info(0xb);
  }
  else if (level == 0xd) {
    puVar1 = (uint *)cpuid_Processor_Extended_States_info(0xd);
  }
  else if (level == 0xf) {
    puVar1 = (uint *)cpuid_Quality_of_Service_info(0xf);
  }
  else if (level == 0x80000002) {
    puVar1 = (uint *)cpuid_brand_part1_info(0x80000002);
  }
  else if (level == 0x80000003) {
    puVar1 = (uint *)cpuid_brand_part2_info(0x80000003);
  }
  else if (level == 0x80000004) {
    puVar1 = (uint *)cpuid_brand_part3_info(0x80000004);
  }
  else {
    puVar1 = (uint *)cpuid(level);
  }
  uVar2 = puVar1[1];
  uVar3 = puVar1[2];
  uVar4 = puVar1[3];
  *a = *puVar1;
  *b = uVar2;
  *c = uVar4;
  *d = uVar3;
  return;
}

