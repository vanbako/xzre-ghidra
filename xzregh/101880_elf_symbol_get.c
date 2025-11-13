// /home/kali/xzre-ghidra/xzregh/101880_elf_symbol_get.c
// Function: elf_symbol_get @ 0x101880
// Calling convention: unknown
// Prototype: undefined elf_symbol_get(void)


/*
 * AutoDoc: Symbol resolver that trusts the GNU hash table the loader extracted earlier. After setting a telemetry bit it walks each hash bucket, validates the bucket and chain addresses, and replays the classic GNU hash lookup to pull `Elf64_Sym` entries out of `.dynsym`. When a candidate symbol has a non-zero value and section index, the helper hashes the associated string with `get_string_id` and compares it against the requested encoded id.
 *
 * If a symbol version is supplied it additionally consults `.gnu.version`/`.gnu.version_d`: the version index is read from `versym`, then matched against the verifier definitions by walking the linked `verdef` list and comparing the underlying string id. Returning NULL means either the target symbol is missing, the module did not advertise GNU hash+version tables, or the string/relocation pointers failed validation.
 */
#include "xzre_types.h"


uint * elf_symbol_get(long param_1,int param_2,int param_3)

{
  byte bVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  long lVar5;
  uint *puVar6;
  ulong uVar7;
  ushort *puVar8;
  short *psVar9;
  uint uVar10;
  byte *local_40;
  uint local_34;
  
  iVar4 = secret_data_append_from_call_site(0x58,0xf,3,0);
  if ((iVar4 != 0) && ((param_3 == 0 || ((*(byte *)(param_1 + 0xd0) & 0x18) == 0x18)))) {
    for (uVar10 = 0; uVar10 < *(uint *)(param_1 + 0xd8); uVar10 = uVar10 + 1) {
      puVar6 = (uint *)(*(long *)(param_1 + 0xf0) + (ulong)uVar10 * 4);
      iVar4 = elf_contains_vaddr(param_1,puVar6,4,4);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      local_40 = (byte *)(*(long *)(param_1 + 0xf8) + (ulong)*puVar6 * 4);
      iVar4 = elf_contains_vaddr(param_1,local_40,8,4);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      do {
        uVar7 = (long)local_40 - *(long *)(param_1 + 0xf8) >> 2 & 0xffffffff;
        puVar6 = (uint *)(uVar7 * 0x18 + *(long *)(param_1 + 0x38));
        iVar4 = elf_contains_vaddr(param_1,puVar6,0x18,4);
        if (iVar4 == 0) {
          return (uint *)0x0;
        }
        if ((*(long *)(puVar6 + 2) != 0) && (*(short *)((long)puVar6 + 6) != 0)) {
          lVar5 = (ulong)*puVar6 + *(long *)(param_1 + 0x30);
          iVar4 = elf_contains_vaddr(param_1,lVar5,1,4);
          if (iVar4 == 0) {
            return (uint *)0x0;
          }
          iVar4 = get_string_id(lVar5,0);
          if (iVar4 == param_2) {
            if (param_3 == 0) {
              return puVar6;
            }
            puVar8 = (ushort *)(uVar7 * 2 + *(long *)(param_1 + 0x70));
            iVar4 = elf_contains_vaddr(param_1,puVar8,2,4);
            if (iVar4 == 0) {
              return (uint *)0x0;
            }
            uVar2 = *puVar8;
            if (((*(byte *)(param_1 + 0xd0) & 0x18) == 0x18) && ((uVar2 & 0x7ffe) != 0)) {
              psVar9 = *(short **)(param_1 + 0x60);
              local_34 = 0;
              do {
                if (((*(ulong *)(param_1 + 0x68) <= (ulong)local_34) ||
                    (iVar4 = elf_contains_vaddr(param_1,psVar9,0x14,4), iVar4 == 0)) ||
                   (*psVar9 != 1)) break;
                if ((uVar2 & 0x7fff) == psVar9[2]) {
                  uVar3 = *(uint *)(psVar9 + 6);
                  iVar4 = elf_contains_vaddr(param_1,(uint *)((ulong)uVar3 + (long)psVar9),8,4);
                  if (iVar4 == 0) break;
                  lVar5 = (ulong)*(uint *)((ulong)uVar3 + (long)psVar9) + *(long *)(param_1 + 0x30);
                  iVar4 = elf_contains_vaddr(param_1,lVar5,1,4);
                  if (iVar4 == 0) break;
                  iVar4 = get_string_id(lVar5,0);
                  if (param_3 == iVar4) {
                    return puVar6;
                  }
                }
                if (*(uint *)(psVar9 + 8) == 0) break;
                local_34 = local_34 + 1;
                psVar9 = (short *)((long)psVar9 + (ulong)*(uint *)(psVar9 + 8));
              } while( TRUE );
            }
          }
        }
        bVar1 = *local_40;
        local_40 = local_40 + 4;
      } while ((bVar1 & 1) == 0);
    }
  }
  return (uint *)0x0;
}

