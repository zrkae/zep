#pragma once
#include <cstddef>
#include <iostream>
#include <cstdint>
#include <cstdio>
#include <array>
#include <format>
#include <concepts>
#include <iterator>
#include <functional>


namespace elf {
class Elf;

// boilerplate macros
#define FN_FROM_ADDR(type) [[nodiscard]] static type* from_addr(void *addr) { return reinterpret_cast<type*>(addr); }

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
    uint64_t phoff; // program header table offset
    uint64_t shoff; // section header table offset
    uint32_t flags;
    uint16_t ehsize; // size of this header
    uint16_t phentsize; // size of a single program header entry
    uint16_t phnum; // number of program header entries
    uint16_t shentsize; // size of a single section header entry
    uint16_t shnum; // number of section header entries
    uint16_t shstrndx; // the index of the section header entry containing ascii encoded section names

    FN_FROM_ADDR(ElfHeader)
};
static_assert(sizeof(ElfHeader) == 64);

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

    FN_FROM_ADDR(ProgramHeader)
};
static_assert(sizeof(ProgramHeader) == 56);


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

    [[nodiscard]] std::optional<std::string_view> str_name(const Elf& elf) const; // this.name -> string from string table
    
    FN_FROM_ADDR(SectionHeader)
};
static_assert(sizeof(SectionHeader) == 64);

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

    [[nodiscard]] std::optional<std::string_view> str_name(const Elf& elf) const; // this.name -> string from string table
    [[nodiscard]] SymbolBinding binding() const;
    [[nodiscard]] SymbolType type() const;

    FN_FROM_ADDR(Symbol)
};
static_assert(sizeof(Symbol) == 24);

// -------------
// Relocations 

// https://refspecs.linuxbase.org/elf/x86_64-abi-0.98.pdf
enum RelocationType: uint64_t {
    R_X86_64_NONE = 0,
    R_X86_64_64 = 1,
    R_X86_64_PC32 = 2,
    R_X86_64_GOT32 = 3,
    R_X86_64_PLT32 = 4,
    R_X86_64_COPY = 5,
    R_X86_64_GLOB_DAT = 6,
    R_X86_64_JUMP_SLOT = 7,
    R_X86_64_RELATIVE = 8,
    R_X86_64_GOTPCREL = 9,
    R_X86_64_32 = 10,
    R_X86_64_32S = 11,
    R_X86_64_16 = 12,
    R_X86_64_PC16 = 13,
    R_X86_64_8 = 14,
    R_X86_64_PC8 = 15,
    R_X86_64_DPTMOD64 = 16,
    R_X86_64_DTPOFF64 = 17,
    R_X86_64_TPOFF64 = 18,
    R_X86_64_TLSGD = 19,
    R_X86_64_TLSLD = 20,
    R_X86_64_DTPOFF32 = 21,
    R_X86_64_GOTTPOFF = 22,
    R_X86_64_TPOFF32 = 23,
    R_X86_64_PC64 = 24,
    R_X86_64_GOTOFF64 = 25,
    R_X86_64_GOTPC32 = 26,
    R_X86_64_SIZE32 = 32,
    R_X86_64_SIZE64 = 33
};

struct Rela {
    uint64_t offset;
    uint64_t info;
    uint64_t addend;

    [[nodiscard]] uint64_t symbol_idx() const { return info >> 32; };
    [[nodiscard]] RelocationType type() const { return RelocationType(info & 0xffffffffL); };
    [[nodiscard]] uint64_t info_value() const { return (symbol_idx() << 32) + ((type()) & 0xffffffffL); };

    FN_FROM_ADDR(Rela)
};
static_assert(sizeof(Symbol) == 24);

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
    explicit Elf(const std::string& file_path);
    explicit Elf(const char* file_path);
    Elf(void *ptr, size_t size);

    ~Elf();

    ElfHeader *header;

    // Generic iterator for stuff like Sections, ProgramHeaders and Symbols.
    // (assumes contiguity of memory etc. etc.)
    template<typename ValueType>
    struct ElfIterator {
        using iterator_category = std::forward_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = ValueType;
        using pointer = value_type*;
        using reference = value_type&;

        ElfIterator(): m_ptr(nullptr) {};
        ElfIterator(const ElfIterator&) = default;

        explicit ElfIterator(pointer ptr): m_ptr(ptr) {}

        reference operator*() const { return *m_ptr; }
        pointer operator->() const { return m_ptr; }

        ElfIterator& operator++() { m_ptr++; return *this; }  
        ElfIterator operator++(int) { ElfIterator tmp = *this; ++(*this); return tmp; }

        friend bool operator== (const ElfIterator& a, const ElfIterator& b) { return a.m_ptr == b.m_ptr; }
        friend bool operator!= (const ElfIterator& a, const ElfIterator& b) { return !(a == b); }
    private:
        pointer m_ptr; 
    };

    class ElfRefHolder {
    public:
        ElfRefHolder() = delete;
        explicit ElfRefHolder(const Elf& elf): m_outer(elf) {};
        [[maybe_unused]] const Elf& m_outer;
    };

    class SectionInfo: ElfRefHolder {
    public:
        explicit SectionInfo(const Elf& elf): ElfRefHolder(elf) {} 

        [[nodiscard]] SectionHeader* at(size_t idx) const;

        ElfIterator<SectionHeader> begin() const;
        ElfIterator<SectionHeader> end() const;
        static_assert(std::forward_iterator<ElfIterator<SectionInfo>>);
    };

    class ProgramHeaderInfo: ElfRefHolder {
    public:
        explicit ProgramHeaderInfo(const Elf& elf): ElfRefHolder(elf) {};

        [[nodiscard]] ProgramHeader* at(size_t idx) const;

        ElfIterator<ProgramHeader> begin() const;
        ElfIterator<ProgramHeader> end() const;
        static_assert(std::forward_iterator<ElfIterator<ProgramHeaderInfo>>);
    };

    class SymbolInfo: ElfRefHolder {
    public:
        explicit SymbolInfo(const Elf& elf): ElfRefHolder(elf) {};

        [[nodiscard]] Symbol* at(size_t idx) const;

        ElfIterator<Symbol> begin() const;
        ElfIterator<Symbol> end() const;
        static_assert(std::forward_iterator<ElfIterator<SymbolInfo>>);

        friend class Elf;
    private:
        // NOTE! this is initialized in Elf::elf_common_init() instead of the constructor of this object! (ordering reasons)
        struct m_symtabinfo_t {
            uint64_t offset; // offset in file
            uint64_t size;   // size in file 
        }; std::optional<m_symtabinfo_t> m_symtab;
    };

    // RelocationInfo's only constructors requires a string, which will be used to choose among the RELA type sections.
    class RelocationInfo: ElfRefHolder {
    public:
        explicit RelocationInfo(const Elf& elf, std::string_view name);

        ElfIterator<Rela> begin() const;
        ElfIterator<Rela> end() const;
        static_assert(std::forward_iterator<ElfIterator<ProgramHeaderInfo>>);
    private:
        const std::string m_name;
        struct m_relasection_t {
            uint64_t offset; // offset in file
            uint64_t size;   // size in file 
        }; std::optional<m_relasection_t> m_section;
    };

    ProgramHeaderInfo prog_headers { *this };
    SectionInfo sections { *this };
    SymbolInfo symbols { *this };

    std::function<RelocationInfo(std::string_view)> relocations = 
                [this](std::string_view name) { return RelocationInfo(*this, name); };

    // these functions return the string corresponding to offset `off` in the section or symbol string table
    [[nodiscard]] std::optional<std::string_view> str_section(uint32_t off) const;
    [[nodiscard]] std::optional<std::string_view> str_symbol(uint32_t off) const;

    // returns the pointer to underlying mapped memory for the ELF file
    [[nodiscard]] unsigned char *fileptr() const { return m_fileptr; }

    [[nodiscard]] void *vaddr_to_fileptr(void *addr) const;
    [[nodiscard]] void *fileoffset_to_vaddr(void *fileptr) const;
private:
    struct m_strtabinfo_t {
        uint64_t offset; // offset in file
        uint64_t size;   // size in file 
    }; std::optional<m_strtabinfo_t> m_strtab;

    unsigned char *m_fileptr;
    size_t m_filesize;

    // validates (checks magic) and finishes initialization. called by constructors.
    void elf_common_init();
};

// Exceptions
class invalid_magic : std::exception {
public:
    explicit invalid_magic(const std::array<unsigned char, 4>& magic)
    : m_msg(std::format("Invalid magic: [{:x}, {:x}, {:x}, {:x}]", 
                               magic[0], magic[1], magic[2], magic[3])) {};

    virtual const char *what() const noexcept 
    {
        return m_msg.c_str();
    };
private:
    std::string m_msg;
};

class invalid_file_size : std::exception {
public:
    explicit invalid_file_size(const char *msg): m_msg(msg) {};

    virtual const char *what() const noexcept 
    {
        return m_msg;
    };
private:
    const char *m_msg;
};

#undef FN_FROM_ADDR
} // namespace elf
