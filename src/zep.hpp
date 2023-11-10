#pragma once
#include <cstddef>
#include <iostream>
#include <cstdint>
#include <cstdio>
#include <array>
#include <format>
#include <concepts>
#include <iterator>

namespace elf {

class Elf;

// ---------
// ElfHeader

constexpr std::array<unsigned char, 4> MAGIC = {0x7F, 'E', 'L', 'F'};

enum ElfClass: unsigned char {
    BIT_32 = 1,
    BIT_64 = 2,
};

enum ElfEndianness: unsigned char {
    EN_LE = 1,
    EN_BE = 2,
};

// NOTE: incomplete
enum ElfOSABI: unsigned char {
    ABI_System_V = 0x00,
    ABI_HP_UX = 0x01,
    ABI_NetBSD = 0x02,
    ABI_Linux = 0x03,
    ABI_GNU_HURD = 0x04,
    ABI_Solaris = 0x06,
    ABI_FreeBSD = 0x09,
    ABI_OpenBSD = 0x0C,
};

struct ElfEIdent {
    std::array<unsigned char, 4> magic;
    ElfClass eclass;
    ElfEndianness endianness;
    unsigned char version;
    ElfOSABI osabi;
    std::array<unsigned char, 8> padding;

};
static_assert(sizeof(ElfEIdent) == 16);

// NOTE: maybe incomplete
enum ElfType: uint16_t {
    ET_NONE = 0x00,
    ET_REL = 0x01,
    ET_EXEC = 0x02,
    ET_DYN = 0x03,
    ET_CORE = 0x04
};

// Basically the ISA
// NOTE: certainly incomplete. (only the most common ones)
enum ElfMachine: uint16_t {
    EM_NONE = 0x00,
    EM_SPARC = 0x02,
    EM_x86 = 0X03,
    EM_80860 = 0x07,
    EM_MIPS = 0x08,
    EM_POWERPC = 0x14,
    EM_POWERPC64 = 0x15,
    EM_ARM = 0x28,
    EM_AMD_x86_64 = 0X3E,
    EM_ARM64 = 0xB7,
    EM_RISC_V = 0xF3
};

// Only 64-bit for now, could maybe be templated into 32 and 64 bit versions.
// NOTE: this struct provides no error checking/validation of the elf file. It's just an schema for interpreting bytes.
// You probably want to use class Elf.
struct ElfHeader {
    ElfEIdent ident;
    ElfType type;
    ElfMachine machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff; // program header offset
    uint64_t shoff; // section header offset
    uint32_t flags;
    uint16_t ehsize; // size of this header
    uint16_t phentsize; // size of a single program header entry
    uint16_t phnum; // number of program header entries
    uint16_t shentsize; // size of a single section header entry
    uint16_t shnum; // number of section header entries
    uint16_t shstrndx; // the index of the section header entry containing ascii encoded section names

    static ElfHeader *from_addr(void *addr);
};
static_assert(sizeof(ElfHeader) == 0x40);

// -------------
// ProgramHeader

enum ProgHeaderType: uint32_t {
    PT_NULL = 0x00,
    PT_LOAD = 0x01,
    PT_DYNAMIC = 0x02,
    PT_INTERP = 0x03,
    PT_NOTE = 0x04,
    PT_SHLIB = 0x05,
    PT_PHDR = 0x06,
    PT_TLS = 0x07,
    PT_LOPROC = 0x70000000,
    PT_HIPROC = 0x7fffffff,
};

enum ProgHeaderFlags: uint32_t {
    PF_X = 0x01,
    PF_W = 0x02,
    PF_R = 0x04
};

// Similar to ElfHeader, just an interpretation of bytes with no validation of its own.
struct ProgramHeader {
    ProgHeaderType type;
    ProgHeaderFlags flags; 
    uint64_t offset; // offset int the file image
    uint64_t vaddr; // virtual addr
    uint64_t paddr; // physical addr
    uint64_t filesz; // size in file
    uint64_t memsz; // size in memory
    uint64_t align;

    static ProgramHeader *from_addr(void *addr);
};
static_assert(sizeof(ProgramHeader) == 0x38);


// -------------
// SectionHeader 

enum SectionType: uint32_t {
    SHT_NULL = 0x00,
    SHT_PROGBITS = 0x01,
    SHT_SYMTAB = 0x02,
    SHT_STRTAB = 0x03,
    SHT_RELA = 0x04,
    SHT_HASH = 0x05,
    SHT_DYNAMIC = 0x06,
    SHT_NOTE = 0x07,
    SHT_NOBITS = 0x08,
    SHT_REL = 0x09,
    SHT_SHLIB = 0x0A,
    SHT_DYNSYM = 0x0B,
    SHT_INIT_ARRAY = 0x0E,
    SHT_FINI_ARRAY = 0x0F,
    SHT_PREINIT_ARRAY = 0x10,
    SHT_LOPROC = 0x70000000,
    SHT_HIPROC = 0x7fffffff,
    SHT_LOUSER = 0x80000000,
    SHT_HIUSER = 0xffffffff,
};

enum SectionFlags: uint64_t {
    SHF_WRITE = 0x01,
    SHF_ALLOC = 0x02,
    SHF_EXECINSTR = 0x04,
};

// Similar to ElfHeader, just an interpretation of bytes with no validation of its own.
struct SectionHeader {
    uint32_t name; // offset into string table
    SectionType type;
    SectionFlags flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;

    std::optional<std::string_view> str_name(const Elf& elf) const; // this.name -> string from string table
    
    static SectionHeader *from_addr(void *addr);
};
static_assert(sizeof(SectionHeader) == 0x40);

// -------------
// Symbols 

enum SymbolBinding {
    STB_LOCAL = 0,
    STB_GLOBAL = 1,
    STB_WEAK = 2,
    STB_LOOS = 10,
    STB_HIOS = 12,
    STB_LOPROC = 13,
    STB_HIPROC = 15
};

enum SymbolType {
    STT_NOTYPE = 0,
    STT_OBJECT = 1,
    STT_FUNC = 2,
    STT_SECTION = 3,
    STT_FILE = 4,
    STT_LOOS = 10,
    STT_HIOS = 12,
    STT_LOPROC = 13,
    STT_HIPROC = 15
};

struct Symbol {
    uint32_t name; // offset into string table
    unsigned char info; // Type and Binding attributes
    unsigned char other;
    uint16_t shndx; // Section table index
    uint64_t value;
    uint64_t size;

    std::optional<std::string_view> str_name(const Elf& elf) const; // this.name -> string from string table
    SymbolBinding binding() const;
    SymbolType type() const;

    static Symbol *from_addr(void *addr);
};
static_assert(sizeof(Symbol) == 0x18);

// -------------
// TODO: Dynamic  


// Abstracts over a single ELF file. It _must_ have a backing ELF file and takes responsibility for managing its image in memory.
// In the simplest use case, given a file name, it uses mmap to map the file contents into memory. After doing so, it does basic 
// validation to ensure the file is indeed an ELF.
// It provides functions and iterators for working with individual portions of the file.
// The destructor 'munmap's the backing file from memory, regardless of whether it was instantiated using a file path or a pointer
// to already mapped memory.
class Elf {
public:
    Elf() = delete; // disallow Elf object without backing file

    // No copying, same rationale as unique_ptr
    Elf(const Elf& other) = delete;
    Elf operator=(const Elf& other) = delete;

    // no std::string view because it is not guaranteed to be null terminated and we need a c-string.
    Elf(const std::string& file_path);
    Elf(const char* file_path);
    Elf(void *ptr, size_t size);

    ~Elf();

    ElfHeader *header;

    // Generic iterator over various ELF structures
    template <typename ValueType>
    requires    std::same_as<ValueType, ProgramHeader>
             || std::same_as<ValueType, SectionHeader>
             || std::same_as<ValueType, Symbol>
    class ElfIterator {
    public:
        ElfIterator() = delete;

        explicit ElfIterator(const Elf& outer)
        : m_outer(outer) {}

        struct Iterator {
            using iterator_category = std::forward_iterator_tag;
            using difference_type = std::ptrdiff_t;
            using value_type = ValueType;
            using pointer = value_type*;
            using reference = value_type&;

            Iterator() = default;
            Iterator(const Iterator&) = default;

            Iterator(pointer ptr): m_ptr(ptr) {}

            reference operator*() const { return *m_ptr; }
            pointer operator->() const { return m_ptr; }

            Iterator& operator++() { m_ptr++; return *this; }  
            Iterator operator++(int) { Iterator tmp = *this; ++(*this); return tmp; }

            friend bool operator== (const Iterator& a, const Iterator& b) { return a.m_ptr == b.m_ptr; }
            friend bool operator!= (const Iterator& a, const Iterator& b) { return !(a == b); }
        private:
            pointer m_ptr; 
        };
        static_assert(std::forward_iterator<Iterator>);

        Iterator begin() const;
        Iterator end() const;

        ValueType* at(size_t idx);
    private:
        const Elf& m_outer;
    };

    ElfIterator<ProgramHeader> prog_headers() const;
    ElfIterator<SectionHeader> sections() const;
    ElfIterator<Symbol> symbols() const;

    // these functions return the string corresponding to offset `off` in the section or symbol string table
    std::optional<std::string_view> str_section(uint32_t off) const;
    std::optional<std::string_view> str_symbol(uint32_t off) const;

    // returns the pointer to underlying mapped memory for the ELF file
    unsigned char *fileptr() const { return m_fileptr; }
private:
    unsigned char *m_fileptr;
    size_t m_filesize;

    // validates (checks magic) and finishes initialization. called by constructors.
    void elf_common_init();

    // finds the symbol table in the sections and saves its offset and size inside the structure
    void init_symtab_info() noexcept;
    // pair<offset, size>
    std::optional<std::pair<uint64_t, uint64_t>> m_symtab_info;
};


// Exceptions

class invalid_magic : std::exception {
public:
    invalid_magic(const std::array<unsigned char, 4>& magic)
    {
        m_msg = std::format("Invalid magic: [{:x}, {:x}, {:x}, {:x}]", 
                               magic[0], magic[1], magic[2], magic[3]);
    };

    virtual const char *what() const noexcept {
        return m_msg.c_str();
    };
private:
    std::string m_msg;
};

} // namespace elf
