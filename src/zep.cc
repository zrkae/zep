#include "zep.hpp"

#include <algorithm>
#include <iostream>
#include <format>

#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>

namespace elf {

ElfHeader* ElfHeader::from_addr(void *addr)
{
    return reinterpret_cast<ElfHeader*>(addr);
}

ProgramHeader* ProgramHeader::from_addr(void *addr) 
{
    return reinterpret_cast<ProgramHeader*>(addr);
}

SectionHeader* SectionHeader::from_addr(void *addr) 
{
    return reinterpret_cast<SectionHeader*>(addr);
}

Symbol* Symbol::from_addr(void *addr) 
{
    return reinterpret_cast<Symbol*>(addr);
}

Rela* Rela::from_addr(void *addr) 
{
    return reinterpret_cast<Rela*>(addr);
}

// At this point m_fileptr and m_filesize are guranteed to be initialized, this is the 'second stage' initialization
// common for all constructors.
void Elf::elf_common_init()
{
    header = ElfHeader::from_addr(m_fileptr);
    if (header->ident.magic != elf::MAGIC) {
        munmap(m_fileptr, m_filesize);
        throw invalid_magic(header->ident.magic); 
    }

    if (header->ident.eclass != ElfClass::BIT_64) {
        munmap(m_fileptr, m_filesize);
        throw std::runtime_error("Non-64bit elf files are not supported yet."); 
    }

    for (const SectionHeader& sh : sections) {
        if (sh.str_name(*this) == ".strtab") {
            m_strtab = {
                .offset = sh.offset,
                .size = sh.size,
            };
        } else if (sh.type == SHT_SYMTAB) {
            symbols.m_symtab = {
                .offset = sh.offset,
                .size = sh.size,
            };
        }
    }
}

Elf::Elf(const std::string& file_path): Elf(file_path.c_str()) {}

Elf::Elf(const char* file_path)
{
    int fd = open(file_path, O_RDONLY);
    if (fd < 0)
        throw std::runtime_error(std::format("Failed to open '{}': {}", file_path, strerror(errno)));

    struct stat statbuf;
    if (fstat(fd, &statbuf) < 0)
        throw std::runtime_error(std::format("Failed to fstat '{}': {}", file_path, strerror(errno)));

    void *file_addr = mmap(nullptr, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_addr == MAP_FAILED)
        throw std::runtime_error(std::format("'mmap'ing file '{}' failed: {}", file_path, strerror(errno)));

    m_fileptr = static_cast<unsigned char*>(file_addr);
    m_filesize = statbuf.st_size;

    elf_common_init();
}

Elf::Elf(void *ptr, size_t size)
: m_fileptr(static_cast<unsigned char*>(ptr)), m_filesize(size) 
{
    elf_common_init();
}

Elf::~Elf() 
{
    munmap(m_fileptr, m_filesize);
}

// Iterators for the Elf class
// !TODO: add checks like for the Symbol specialization for others (they are not guaranteed to be present in the binary I think)
//        Or maybe just return empty iterator for all of them? idk
template<typename T>
using ElfIterator = Elf::ElfIterator<T>;

// ------------
// ProgramHeaders
ElfIterator<ProgramHeader> Elf::ProgramHeaderInfo::begin() const
{
    return ElfIterator(ProgramHeader::from_addr(m_outer.m_fileptr + m_outer.header->phoff));
}

ElfIterator<ProgramHeader> Elf::ProgramHeaderInfo::end() const
{
    return ElfIterator(ProgramHeader::from_addr(m_outer.m_fileptr + m_outer.header->phoff) + m_outer.header->phnum);
}

ProgramHeader* Elf::ProgramHeaderInfo::at(size_t idx) const
{
    if (idx > m_outer.header->shnum)
        return nullptr; 

    return ProgramHeader::from_addr(
        m_outer.m_fileptr + m_outer.header->shoff + sizeof(ProgramHeader)*idx
    ); 
}

// ------------
// Sections
ElfIterator<SectionHeader> Elf::SectionInfo::begin() const
{
    return ElfIterator(SectionHeader::from_addr(m_outer.m_fileptr + m_outer.header->shoff));
}

ElfIterator<SectionHeader> Elf::SectionInfo::end() const
{
    return ElfIterator(SectionHeader::from_addr(m_outer.m_fileptr + m_outer.header->shoff) + m_outer.header->shnum);
}

SectionHeader* Elf::SectionInfo::at(size_t idx) const
{
    if (idx > m_outer.header->shnum)
        return nullptr;

    return SectionHeader::from_addr(
        m_outer.m_fileptr + m_outer.header->shoff + sizeof(SectionHeader)*idx
    ); 
}

std::optional<std::string_view> Elf::str_section(uint32_t off) const
{
    SectionHeader* strtab = this->sections.at(this->header->shstrndx);
    if (!strtab)
        return std::nullopt;

    assert(strtab->type == SectionType::SHT_STRTAB);

    const char *str = reinterpret_cast<const char*>(this->m_fileptr + strtab->offset + off);
    return std::string_view(str);
}

std::optional<std::string_view> SectionHeader::str_name(const Elf& elf) const
{
    return elf.str_section(this->name);
}

// ------------
// Symbols
std::optional<std::string_view> Elf::str_symbol(uint32_t off) const
{
    if (!m_strtab || off > m_strtab->offset)
        return std::nullopt;

    const char *str = reinterpret_cast<const char*>(this->m_fileptr + m_strtab->offset + off);
    return std::string_view(str);
}

ElfIterator<Symbol> Elf::SymbolInfo::begin() const
{
    if (!m_symtab)
        throw std::runtime_error("Attempted to iterate over symbols on an executable without a symbol table! (is it stripped?)");

    return ElfIterator(Symbol::from_addr(m_outer.m_fileptr + m_symtab->offset));
}

ElfIterator<Symbol> Elf::SymbolInfo::end() const
{
    if (!m_symtab)
        throw std::runtime_error("Attempted to iterate over symbols on an executable without a symbol table! (is it stripped?)");

    return ElfIterator(Symbol::from_addr(m_outer.m_fileptr + m_symtab->offset + m_symtab->size));
}

Symbol* Elf::SymbolInfo::at(size_t idx) const
{
    if (!m_symtab)
        throw std::runtime_error("Attempted to iterate over symbols on an executable without a symbol table! (is it stripped?)");

    size_t symbol_count = m_symtab->size / sizeof(Symbol);
    if (idx > symbol_count)
        return nullptr;

    return Symbol::from_addr(
        m_outer.m_fileptr + m_symtab->offset + sizeof(Symbol)*idx
    ); 
}

std::optional<std::string_view> Symbol::str_name(const Elf& elf) const
{
    return elf.str_symbol(this->name);
}

SymbolBinding Symbol::binding() const
{
    return SymbolBinding(this->info >> 4);
}

SymbolType Symbol::type() const
{
    return SymbolType(this->info & 0x0F);
}

// -----------
// Relocations

Elf::RelocationInfo::RelocationInfo(const Elf& elf, std::string_view name)
: ElfRefHolder(elf), m_name(name) 
{
    auto it = std::find_if(elf.sections.begin(), elf.sections.end(), 
                           [&](const SectionHeader& s) {
                             auto str_name = s.str_name(elf).value_or("");
                             return str_name.starts_with(".rela") && str_name.ends_with(name);
                           });

    if (it == elf.sections.end())
        throw std::runtime_error(std::format("No matching RELA sections found for: '{}'", name));

    m_section = {
        .offset = it->offset,
        .size = it->size,
    };
}

ElfIterator<Rela> Elf::RelocationInfo::begin() const
{
    auto info = m_section.value_or(m_relasection_t{0,0});
    return ElfIterator(Rela::from_addr(m_outer.fileptr() + info.offset));
}

ElfIterator<Rela> Elf::RelocationInfo::end() const
{
    auto info = m_section.value_or(m_relasection_t{0,0});
    return ElfIterator(Rela::from_addr(m_outer.fileptr() + info.offset + info.size));
}

// -----------
// Misc elf
void *Elf::vaddr_to_fileptr(void *addr) const
{
    uint64_t iaddr = (uint64_t)addr;
    auto it = std::find_if(prog_headers.begin(), prog_headers.end(), 
                           [iaddr](const ProgramHeader& ph) { return iaddr > ph.vaddr && iaddr < (ph.vaddr + ph.memsz); });

    if (it == prog_headers.end())
        return nullptr; 

    return m_fileptr + iaddr - it->vaddr + it->offset;
}

void *Elf::fileoffset_to_vaddr(void *) const
{
    assert(0 && "TODO: Not implemented");
}

} // namespace elf
