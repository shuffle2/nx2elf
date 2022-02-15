#pragma once

#include "types.h"

struct ElfIdent {
  u32 magic;
#define ELF_MAGIC 0x464C457F  // litte endian \x7FELF
  u8 elf_class;
#define ELFCLASSNONE 0  // Invalid class
#define ELFCLASS32 1    // 32bit object
#define ELFCLASS64 2    // 64bit object
  u8 bytesex;
#define ELFDATANONE 0  // Invalid data encoding
#define ELFDATA2LSB 1  // low byte first
#define ELFDATA2MSB 2  // high byte first
  u8 version;          // file version
#define EV_CURRENT 1
  u8 osabi;              // Operating System/ABI indication
#define ELFOSABI_NONE 0  // UNIX System V ABI
  u8 abiversion;         // ABI version
  u8 pad[7];

  bool is_valid() const { return magic == ELF_MAGIC; }
  bool is_msb() const { return bytesex == ELFDATA2MSB; }
  bool is_64() const { return elf_class == ELFCLASS64; }
};

struct Elf64_Ehdr {
  ElfIdent e_ident;
  u16 e_type;
  u16 e_machine;
  u32 e_version;
  u64 e_entry;
  u64 e_phoff;
  u64 e_shoff;
  u32 e_flags;
  u16 e_ehsize;
  u16 e_phentsize;
  u16 e_phnum;
  u16 e_shentsize;
  u16 e_shnum;
  u16 e_shstrndx;
};

#define ET_NONE 0
#define ET_REL 1
#define ET_EXEC 2
#define ET_DYN 3
#define ET_CORE 4
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff

#define EM_AARCH64 183

struct Elf64_Phdr {
  u32 p_type;
  u32 p_flags;
  u64 p_offset;
  u64 p_vaddr;
  u64 p_paddr;
  u64 p_filesz;
  u64 p_memsz;
  u64 p_align;
};

#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_LOOS 0x60000000ul
#define PT_HIOS 0x6ffffffful
#define PT_LOPROC 0x70000000ul
#define PT_HIPROC 0x7ffffffful
#define PT_GNU_EH_FRAME (PT_LOOS + 0x474e550ul)
#define PT_GNU_STACK (PT_LOOS + 0x474e551ul)
#define PT_GNU_RELRO (PT_LOOS + 0x474e552)
#define PT_PAX_FLAGS (PT_LOOS + 0x5041580)

#define PF_X (1 << 0)
#define PF_W (1 << 1)
#define PF_R (1 << 2)

struct Elf64_Shdr {
  u32 sh_name;       // Section name, index in string tbl
  u32 sh_type;       // Type of section
  u64 sh_flags;      // Miscellaneous section attributes
  u64 sh_addr;       // Section virtual addr at execution
  u64 sh_offset;     // Section file offset
  u64 sh_size;       // Size of section in bytes
  u32 sh_link;       // Index of another section
  u32 sh_info;       // Additional section information
  u64 sh_addralign;  // Section alignment
  u64 sh_entsize;    // Entry size if section holds table
};

#define SHT_NULL 0                    /* Section header table entry unused */
#define SHT_PROGBITS 1                /* Program data */
#define SHT_SYMTAB 2                  /* Symbol table */
#define SHT_STRTAB 3                  /* String table */
#define SHT_RELA 4                    /* Relocation entries with addends */
#define SHT_HASH 5                    /* Symbol hash table */
#define SHT_DYNAMIC 6                 /* Dynamic linking information */
#define SHT_NOTE 7                    /* Notes */
#define SHT_NOBITS 8                  /* Program space with no data (bss) */
#define SHT_REL 9                     /* Relocation entries, no addends */
#define SHT_SHLIB 10                  /* Reserved */
#define SHT_DYNSYM 11                 /* Dynamic linker symbol table */
#define SHT_INIT_ARRAY 14             /* Array of constructors */
#define SHT_FINI_ARRAY 15             /* Array of destructors */
#define SHT_PREINIT_ARRAY 16          /* Array of pre-constructors */
#define SHT_GROUP 17                  /* Section group */
#define SHT_SYMTAB_SHNDX 18           /* Extended section indeces */
#define SHT_NUM 19                    /* Number of defined types.  */
#define SHT_LOOS 0x60000000           /* Start OS-specific.  */
#define SHT_GNU_ATTRIBUTES 0x6ffffff5 /* Object attributes.  */
#define SHT_GNU_HASH 0x6ffffff6       /* GNU-style hash table.  */
#define SHT_GNU_LIBLIST 0x6ffffff7    /* Prelink library list */
#define SHT_CHECKSUM 0x6ffffff8       /* Checksum for DSO content.  */
#define SHT_LOSUNW 0x6ffffffa         /* Sun-specific low bound.  */
#define SHT_SUNW_move 0x6ffffffa
#define SHT_SUNW_COMDAT 0x6ffffffb
#define SHT_SUNW_syminfo 0x6ffffffc
#define SHT_GNU_verdef 0x6ffffffd  /* Version definition section.  */
#define SHT_GNU_verneed 0x6ffffffe /* Version needs section.  */
#define SHT_GNU_versym 0x6fffffff  /* Version symbol table.  */
#define SHT_HISUNW 0x6fffffff      /* Sun-specific high bound.  */
#define SHT_HIOS 0x6fffffff        /* End OS-specific type */
#define SHT_LOPROC 0x70000000      /* Start of processor-specific */
#define SHT_HIPROC 0x7fffffff      /* End of processor-specific */
#define SHT_LOUSER 0x80000000      /* Start of application-specific */
#define SHT_HIUSER 0x8fffffff      /* End of application-specific */

#define SHF_WRITE (1 << 0)      /* Writable */
#define SHF_ALLOC (1 << 1)      /* Occupies memory during execution */
#define SHF_EXECINSTR (1 << 2)  /* Executable */
#define SHF_MERGE (1 << 4)      /* Might be merged */
#define SHF_STRINGS (1 << 5)    /* Contains nul-terminated strings */
#define SHF_INFO_LINK (1 << 6)  /* `sh_info' contains SHT index */
#define SHF_LINK_ORDER (1 << 7) /* Preserve order after combining */
#define SHF_OS_NONCONFORMING                                         \
  (1 << 8)                      /* Non-standard OS specific handling \
                                   required */
#define SHF_GROUP (1 << 9)      /* Section is member of a group.  */
#define SHF_TLS (1 << 10)       /* Section hold thread-local data.  */
#define SHF_MASKOS 0x0ff00000   /* OS-specific.  */
#define SHF_MASKPROC 0xf0000000 /* Processor-specific */
#define SHF_ORDERED                         \
  (1 << 30) /* Special ordering requirement \
               (Solaris).  */
#define SHF_EXCLUDE                       \
  (1 << 31) /* Section is excluded unless \
               referenced or allocated (Solaris).*/

/* special section indexes */
#define SHN_UNDEF 0
#define SHN_LORESERVE 0xff00
#define SHN_LOPROC 0xff00
#define SHN_HIPROC 0xff1f
#define SHN_LIVEPATCH 0xff20
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2
#define SHN_HIRESERVE 0xffff

struct Elf64_Sym {
  u32 st_name;
  u8 st_info;
  u8 st_other;
  u16 st_shndx;
  u64 st_value;
  u64 st_size;
};

typedef struct {
  u32      st_name;
  u32      st_value;
  u32      st_size;
  u8       st_info;
  u8       st_other;
  u16      st_shndx;
} Elf32_Sym;

typedef struct {
  s32 d_tag;
  s32 d_un;
} Elf32_Dyn;

typedef struct {
  u32    r_offset;
  u32    r_info;
  s32   r_addend;
} Elf32_Rela;

#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)

#define ELF64_ST_BIND(info) ((info) >> 4)
#define ELF64_ST_TYPE(info) ((info)&0xf)
#define ELF64_ST_INFO(bind, type) (((bind) << 4) + ((type)&0xf))

#define ELF64_ST_VISIBILITY(o) ((o)&0x3)

#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STB_WEAK 2

#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4
#define STT_COMMON 5
#define STT_TLS 6

struct Elf64_Rela {
  u64 r_offset;
  u64 r_info;
  s64 r_addend;
};

#define ELF64_R_SYM(i) u32((i) >> 32)
#define ELF64_R_TYPE(i) u32(i)

/* Dynamic relocations */
#define R_AARCH64_COPY 1024
#define R_AARCH64_GLOB_DAT 1025  /* Create GOT entry.  */
#define R_AARCH64_JUMP_SLOT 1026 /* Create PLT entry.  */
#define R_AARCH64_RELATIVE 1027  /* Adjust by program base.  */
#define R_AARCH64_TLS_TPREL64 1030
#define R_AARCH64_TLS_DTPREL32 1031
#define R_AARCH64_IRELATIVE 1032

struct Elf64_Dyn {
  u64 d_tag;
  u64 d_un;
};

#define DT_NULL 0             /* Marks end of dynamic section */
#define DT_NEEDED 1           /* Name of needed library */
#define DT_PLTRELSZ 2         /* Size in bytes of PLT relocs */
#define DT_PLTGOT 3           /* Processor defined value */
#define DT_HASH 4             /* Address of symbol hash table */
#define DT_STRTAB 5           /* Address of string table */
#define DT_SYMTAB 6           /* Address of symbol table */
#define DT_RELA 7             /* Address of Rela relocs */
#define DT_RELASZ 8           /* Total size of Rela relocs */
#define DT_RELAENT 9          /* Size of one Rela reloc */
#define DT_STRSZ 10           /* Size of string table */
#define DT_SYMENT 11          /* Size of one symbol table entry */
#define DT_INIT 12            /* Address of init function */
#define DT_FINI 13            /* Address of termination function */
#define DT_SONAME 14          /* Name of shared object */
#define DT_RPATH 15           /* Library search path (deprecated) */
#define DT_SYMBOLIC 16        /* Start symbol search here */
#define DT_REL 17             /* Address of Rel relocs */
#define DT_RELSZ 18           /* Total size of Rel relocs */
#define DT_RELENT 19          /* Size of one Rel reloc */
#define DT_PLTREL 20          /* Type of reloc in PLT */
#define DT_DEBUG 21           /* For debugging; unspecified */
#define DT_TEXTREL 22         /* Reloc might modify .text */
#define DT_JMPREL 23          /* Address of PLT relocs */
#define DT_BIND_NOW 24        /* Process relocations of object */
#define DT_INIT_ARRAY 25      /* Array with addresses of init fct */
#define DT_FINI_ARRAY 26      /* Array with addresses of fini fct */
#define DT_INIT_ARRAYSZ 27    /* Size in bytes of DT_INIT_ARRAY */
#define DT_FINI_ARRAYSZ 28    /* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH 29         /* Library search path */
#define DT_FLAGS 30           /* Flags for the object being loaded */
#define DT_ENCODING 32        /* Start of encoded range */
#define DT_PREINIT_ARRAY 32   /* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ 33 /* size in bytes of DT_PREINIT_ARRAY */
#define DT_NUM 34             /* Number used */
#define DT_LOOS 0x6000000d    /* Start of OS-specific */
#define DT_HIOS 0x6ffff000    /* End of OS-specific */
#define DT_LOPROC 0x70000000  /* Start of processor-specific */
#define DT_HIPROC 0x7fffffff  /* End of processor-specific */
#define DT_ADDRRNGLO 0x6ffffe00
#define DT_GNU_HASH 0x6ffffef5 /* GNU-style hash table.  */
#define DT_TLSDESC_PLT 0x6ffffef6
#define DT_TLSDESC_GOT 0x6ffffef7
#define DT_GNU_CONFLICT 0x6ffffef8 /* Start of conflict section */
#define DT_GNU_LIBLIST 0x6ffffef9  /* Library list */
#define DT_CONFIG 0x6ffffefa       /* Configuration information.  */
#define DT_DEPAUDIT 0x6ffffefb     /* Dependency auditing.  */
#define DT_AUDIT 0x6ffffefc        /* Object auditing.  */
#define DT_PLTPAD 0x6ffffefd       /* PLT padding.  */
#define DT_MOVETAB 0x6ffffefe      /* Move table.  */
#define DT_SYMINFO 0x6ffffeff      /* Syminfo table.  */
#define DT_ADDRRNGHI 0x6ffffeff
#define DT_RELACOUNT 0x6ffffff9
#define DT_RELCOUNT 0x6ffffffa

struct Elf64_Nhdr {
  u32 n_namesz; /* Length of the note's name.  */
  u32 n_descsz; /* Length of the note's descriptor.  */
  u32 n_type;   /* Type of the note.  */
};

struct GnuBuildId {
  Elf64_Nhdr header;
  std::array<char, 4> owner;
  union {
    std::array<u8, 32> build_id_raw;
    md5_digest build_id_md5;
    sha1_digest build_id_sha1;
  };
};
