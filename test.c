#define OSTD_IMPL
#define OSTD_HEADLESS
#include "One-Std/one-headers/one_system.h"


#define DECLARE_ENUM_WITH_STRINGIFY(name, list_macro)          \
    typedef enum name {                                        \
        list_macro(DECLARE_ENUM_ENTRY)                         \
    } name;                                                    \
                                                               \
    string stringify_##name(name value) {                 \
        switch (value) {                                       \
            list_macro(DECLARE_ENUM_STRING_CASE)               \
            default: return STR("UNKNOWN");                         \
        }                                                      \
    }

#define DECLARE_ENUM_ENTRY(name, value) name = value,
#define DECLARE_ENUM_STRING_CASE(name, value) case name: return STR(#name);

#define FILE_TYPE_LIST(X) \
    X(FILE_TYPE_NONE,   0x00) \
    X(FILE_TYPE_REL,    0x01) \
    X(FILE_TYPE_EXEC,   0x02) \
    X(FILE_TYPE_DYN,    0x03) \
    X(FILE_TYPE_CORE,   0x04) \
    X(FILE_TYPE_LOOS,   0xFE00) \
    X(FILE_TYPE_HIOS,   0xFEFF) \
    X(FILE_TYPE_LOPROC, 0xFF00) \
    X(FILE_TYPE_HIPROC, 0xFFFF00)
DECLARE_ENUM_WITH_STRINGIFY(File_Type, FILE_TYPE_LIST)

#define SECTION_HEADER_TYPE_LIST(X) \
    X(SECTION_HEADER_NULL,   0x00) \
    X(SECTION_HEADER_PROGBITS,   0x01) \
    X(SECTION_HEADER_SYMTAB,   0x02) \
    X(SECTION_HEADER_STRTAB,   0x03) \
    X(SECTION_HEADER_RELA,   0x04) \
    X(SECTION_HEADER_HASH,   0x05) \
    X(SECTION_HEADER_DYNAMIC,   0x06) \
    X(SECTION_HEADER_NOTE,   0x07) \
    X(SECTION_HEADER_NOBITS,   0x08) \
    X(SECTION_HEADER_REL,   0x09) \
    X(SECTION_HEADER_SHLIB,   0x0A) \
    X(SECTION_HEADER_DYNSYM,   0x0B) \
    X(SECTION_HEADER_INIT_ARRAY,   0x0E) \
    X(SECTION_HEADER_FINI_ARRAY,   0x0F) \
    X(SECTION_HEADER_PREINIT_ARRAY,   0x10) \
    X(SECTION_HEADER_GROUP,   0x11) \
    X(SECTION_HEADER_SYMTAB_SHNDX,   0x12) \
    X(SECTION_HEADER_NUM,   0x13) \
    X(SECTION_HEADER_LOOS,   0x60000000)
DECLARE_ENUM_WITH_STRINGIFY(Section_Header_Type, SECTION_HEADER_TYPE_LIST)

#define SECTION_HEADER_FLAGS_LIST(X) \
    X(SECTION_HEADER_FLAG_WRITE,   0x01) \
    X(SECTION_HEADER_FLAG_ALLOC,   0x02) \
    X(SECTION_HEADER_FLAG_EXECINSTR,   0x04) \
    X(SECTION_HEADER_FLAG_MERGE,   0x10) \
    X(SECTION_HEADER_FLAG_STRINGS,   0x20) \
    X(SECTION_HEADER_FLAG_INFO_LINK,   0x40) \
    X(SECTION_HEADER_FLAG_LINK_ORDER,   0x80) \
    X(SECTION_HEADER_FLAG_OS_NONCONFORMING,   0x100) \
    X(SECTION_HEADER_FLAG_GROUP,   0x200) \
    X(SECTION_HEADER_FLAG_TLS,   0x400) \
    X(SECTION_HEADER_FLAG_MASKOS,   0x0FF00000) \
    X(SECTION_HEADER_FLAG_MASKPROC,   0xF0000000) \
    X(SECTION_HEADER_FLAG_ORDERED,   0x4000000) \
    X(SECTION_HEADER_FLAG_EXCLUDE,   0x8000000)

DECLARE_ENUM_WITH_STRINGIFY(Section_Header_Flags, SECTION_HEADER_FLAGS_LIST)

typedef struct __attribute__((packed)) Elf_Header64 {
    u8 endianess; // 1 == little, 2 == big
    u8 version;
    u8 abi; // 0x03 == linux
    u8 abi_version;
    u8 padding[7];
    u16 file_type;
    u16 isa; // 0x03 == x86, 0x3E == amd64, 0xF3 == RISC-V
    u32 another_version;
    u64 entry_address;
    u64 program_header_offset; // 0x34 for 32-bit, 0x40 for 64-bit
    u64 section_headers_offset;
    u32 flags; // "Interpretation of this field depends on the target architecture. "
    u16 size_of_this_header;
    u16 program_header_entry_size;
    u16 program_header_entry_count;
    u16 section_header_entry_size;
    u16 section_header_entry_count;
    u16 index_of_section_header_entry_which_contains_section_names;
    
} Elf_Header64;

typedef struct __attribute__((packed)) Section_Header64 {
    u32 name_shstrtab_offset;
    u32 header_type;
    u64 header_flags;
    u64 loaded_sections_virtual_address;
    u64 file_image_offset;
    u64 size;
    u32 link;
    u32 info;
    u64 required_alignment;
    u64 size_of_fixed_size_entries;
} Section_Header64;

typedef struct __attribute__((packed)) Elf_Header_Header {
    u8 magic[4];
    u8 class; // 1 == 32 bit, 2 == 64 bit
    Elf_Header64 impl;
} Elf_Header_Header;

static size_t decode_x86_64_len(const u8 *p, const u8 *end) {
    const u8 *start = p;

    while (p < end && 
           ((*p & 0xF0) == 0x40 || 
            *p == 0xF0 || *p == 0xF2 || *p == 0xF3 ||
            *p == 0x2E || *p == 0x36 || *p == 0x3E || *p == 0x26 ||
            *p == 0x64 || *p == 0x65 || *p == 0x66 || *p == 0x67)) {
        p++;
    }
    if (p >= end) return p - start;

    u8 opcode = *p++;
    bool two_byte = false;
    if (opcode == 0x0F) {
        two_byte = true;
        if (p >= end) return p - start;
        opcode = *p++;
    }

    bool needs_modrm = true;
    if ((!two_byte && (opcode >= 0xB8 && opcode <= 0xBF)) || // MOV r64, imm32
        (!two_byte && (opcode >= 0x70 && opcode <= 0x7F)) || // Jcc rel8
        (!two_byte && opcode == 0xEB) ||                     // JMP rel8
        (!two_byte && opcode == 0xE8) ||                     // CALL rel32
        (!two_byte && opcode == 0xE9))                       // JMP rel32
    {
        needs_modrm = false;
    }

    if (needs_modrm && p < end) {
        u8 modrm = *p++;
        u8 mod = (modrm >> 6) & 3;
        u8 rm  = modrm & 7;

        if (mod != 3 && rm == 4 && p < end) {
            p++;
        }

        if (mod == 1 && p + 1 <= end) {
            p += 1;
        } else if (mod == 2 && p + 4 <= end) {
            p += 4;
        } else if (mod == 0 && rm == 5 && p + 4 <= end) {
            p += 4;
        }
    }

    if (!needs_modrm) {
        if (opcode >= 0x70 && opcode <= 0x7F) {
            if (p < end) p += 1;
        } else if (opcode == 0xEB) {
            if (p < end) p += 1;
        } else if (opcode == 0xE8 || opcode == 0xE9) {
            if (p + 4 <= end) p += 4;
        } else if (opcode >= 0xB8 && opcode <= 0xBF) {
            if (p + 4 <= end) p += 4;
        }
    } else {
        if (!two_byte && (opcode == 0x83 || opcode == 0xC7)) {
            if (opcode == 0x83 && p < end)         p += 1;
            if (opcode == 0xC7 && p + 4 <= end)   p += 4;
        }
    }

    return p - start;
}

int main(void) {
    
    assert(sizeof(Section_Header64) == 0x40);
    
    string file = STR("example.o");
    
    string elf;
    bool ok = sys_read_entire_file(get_temp(), file, &elf);
    assert(ok);
    
    Elf_Header_Header *header_header = (Elf_Header_Header*)elf.data;
    
    assertmsg(header_header->magic[0] == 0x7F, "Invalid elf file, bad magic");
    assertmsg(header_header->magic[1] == 0x45, "Invalid elf file, bad magic");
    assertmsg(header_header->magic[2] == 0x4c, "Invalid elf file, bad magic");
    assertmsg(header_header->magic[3] == 0x46, "Invalid elf file, bad magic");
    
    assert(header_header->class == 2) ; // not 64 bit
    
    Elf_Header64 *header = (Elf_Header64*)&header_header->impl;
    
    print("Endianess: %i (1 == little, 2 == big)\n", header->endianess);
    print("version: %i\n", header->version);
    print("abi: %i\n", header->abi);
    print("abi_version: %i\n", header->abi_version);
    string ft = stringify_File_Type(header->file_type);
    print("File type: %s\n", ft);
    print("ISA: 0x%x\n", header->isa);
    print("another_version: %u\n", header->another_version);
    print("entry_address: %u\n", header->entry_address);
    print("program_header_offset: %u\n", header->program_header_offset);
    print("section_headers_offset: %u\n", header->section_headers_offset);
    print("flags: %u\n", header->flags);
    print("size_of_this_header: %u\n", header->size_of_this_header);
    print("program_header_entry_size: %u\n", header->program_header_entry_size);
    print("program_header_entry_count: %u\n", header->program_header_entry_count);
    print("section_header_entry_size: %u\n", header->section_header_entry_size);
    print("section_header_entry_count: %u\n", header->section_header_entry_count);
    print("index_of_section_header_entry_which_contains_section_names: %u\n", header->index_of_section_header_entry_which_contains_section_names);
    
    u16 sh_count   = header->section_header_entry_count;
    u16 sh_entsize = header->section_header_entry_size;
    u64 sh_offset  = header->section_headers_offset;

    // find the section header for the string-table of section names
    u16 shstrndx = header->index_of_section_header_entry_which_contains_section_names;
    Section_Header64 *shstr_sh =
        (Section_Header64*)(elf.data + sh_offset + shstrndx * sh_entsize);
    u8 *shstrtab = (u8*)(elf.data + shstr_sh->file_image_offset);

    for (u16 i = 0; i < sh_count; i++) {
        Section_Header64 *sh =
            (Section_Header64*)(elf.data + sh_offset + i * sh_entsize);

        // lookup name in .shstrtab
        string name = STR(shstrtab + sh->name_shstrtab_offset);
        print("\n%s\n", name);

        // type
        string ht = stringify_Section_Header_Type(sh->header_type);
        print("  Type: %s\n", ht);

        // flags: loop through each defined flag
        u64 flags = sh->header_flags;
        print("  Flags:\n");
    #define X(name, val) \
        if (flags & (val)) print("    %s\n", STR(#name));
        SECTION_HEADER_FLAGS_LIST(X)
    #undef X

        print("  loaded_sections_virtual_address: 0x%x\n",
              sh->loaded_sections_virtual_address);
        print("  file_image_offset: 0x%x\n",
              sh->file_image_offset);
        print("  size: 0x%x\n",
              sh->size);

        print("  link: %u\n", sh->link);
        print("  info: %u\n", sh->info);
        print("  required_alignment: %u\n", sh->required_alignment);
        print("  size_of_fixed_size_entries: %u\n",
              sh->size_of_fixed_size_entries);
              
              
        if (sh->header_flags & SECTION_HEADER_FLAG_EXECINSTR) {
            u8 *pcode = elf.data + sh->file_image_offset;
            u8 *end = pcode + sh->size;
            
            u8 *p = pcode;
            
            while (p < end) {
                print("    I: ");
                size_t len = decode_x86_64_len(p, end);
                for (size_t i = 0; i < len; i++)
                    print("0x%x ", p[i]);
                print("\n");
        
                p += len;
            }
            
        }
    }
    
    return 0;
}
