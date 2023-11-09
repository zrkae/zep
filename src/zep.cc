#include "zep.hpp"

#include <algorithm>
#include <iostream>
#include <format>

#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>

namespace elf {

// TODO: maybe these functions should do bounds checking on the addr?
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

    init_symtab_info();
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

// ElfIterator specializations
// !TODO: add checks like for the Symbol specialization for others (they are not guaranteed to be present in the binarty I think)
//        Or maybe just return empty iterator for all of them? idk
template <typename T>
using ElfIterator = Elf::ElfIterator<T>;

// ProgramHeader iterator
ElfIterator<ProgramHeader> Elf::prog_headers() const
{
    return ElfIterator<ProgramHeader>(*this);
}

template<> 
ElfIterator<ProgramHeader>::Iterator ElfIterator<ProgramHeader>::begin() const
{
    return Iterator(ProgramHeader::from_addr(m_outer.m_fileptr + m_outer.header->phoff));
}

template<> 
ElfIterator<ProgramHeader>::Iterator ElfIterator<ProgramHeader>::end() const
{
    return Iterator(ProgramHeader::from_addr(m_outer.m_fileptr + m_outer.header->phoff) + m_outer.header->phnum);
}

template<>
ProgramHeader* ElfIterator<ProgramHeader>::at(size_t idx)
{
    if (idx > m_outer.header->shnum)
        return nullptr; 

    return ProgramHeader::from_addr(
        m_outer.m_fileptr + m_outer.header->shoff + sizeof(ProgramHeader)*idx
    ); 
}

// SectionHeader iterator
ElfIterator<SectionHeader> Elf::sections() const
{
    return ElfIterator<SectionHeader>(*this);
}

template<> 
ElfIterator<SectionHeader>::Iterator ElfIterator<SectionHeader>::begin() const
{
    return Iterator(SectionHeader::from_addr(m_outer.m_fileptr + m_outer.header->shoff));
}

template<> 
ElfIterator<SectionHeader>::Iterator ElfIterator<SectionHeader>::end() const
{
    return Iterator(SectionHeader::from_addr(m_outer.m_fileptr + m_outer.header->shoff) + m_outer.header->shnum);
}

template<>
SectionHeader* ElfIterator<SectionHeader>::at(size_t idx)
{
    if (idx > m_outer.header->shnum)
        return nullptr;

    return SectionHeader::from_addr(
        m_outer.m_fileptr + m_outer.header->shoff + sizeof(SectionHeader)*idx
    ); 
}

// Symbol iterator
ElfIterator<Symbol> Elf::symbols() const
{
    return ElfIterator<Symbol>(*this);
}

template<>
ElfIterator<Symbol>::Iterator ElfIterator<Symbol>::begin() const
{
    if (!m_outer.m_symtab_info)
        throw std::runtime_error("Attempted to iterate over symbols on an executable without a symbol table! (is it stripped?)");

    return Iterator(Symbol::from_addr(m_outer.m_fileptr + m_outer.m_symtab_info->first));
}

template<>
ElfIterator<Symbol>::Iterator ElfIterator<Symbol>::end() const
{
    if (!m_outer.m_symtab_info)
        throw std::runtime_error("Attempted to iterate over symbols on an executable without a symbol table! (is it stripped?)");

    return Iterator(Symbol::from_addr(m_outer.m_fileptr + m_outer.m_symtab_info->first + m_outer.m_symtab_info->second));
}

template<>
Symbol* ElfIterator<Symbol>::at(size_t idx)
{
    if (!m_outer.m_symtab_info)
        throw std::runtime_error("Attempted to iterate over symbols on an executable without a symbol table! (is it stripped?)");

    size_t symbol_count = m_outer.m_symtab_info->second / sizeof(Symbol);
    if (idx > symbol_count)
        return nullptr;

    return Symbol::from_addr(
        m_outer.m_fileptr + m_outer.m_symtab_info->first + sizeof(Symbol)*idx
    ); 
}

// other Struct/Class member functions (mostly declared below because of some template specialization bs)
std::optional<std::string_view> SectionHeader::str_name(const Elf& elf) const
{
    return elf.str_section(this->name);
}

std::optional<std::string_view> Symbol::str_name(const Elf& elf) const
{
    return elf.str_symbol(this->name);
}

std::optional<std::string_view> Elf::str_section(uint32_t off) const
{
    SectionHeader* strtab = this->sections().at(this->header->shstrndx);
    if (!strtab)
        return std::nullopt;

    assert(strtab->type == SectionType::SHT_STRTAB);

    const char *str = reinterpret_cast<const char*>(this->m_fileptr + strtab->offset + off);
    return std::string_view(str);
}

std::optional<std::string_view> Elf::str_symbol(uint32_t off) const
{
    auto it = std::find_if(sections().begin(), sections().end(), 
                           [this](const SectionHeader& sh) {  return sh.str_name(*this) == ".strtab"; });

    if (it == sections().end())
        return std::nullopt;

    const char *str = reinterpret_cast<const char*>(this->m_fileptr + it->offset + off);
    return std::string_view(str);
}

void Elf::init_symtab_info() noexcept
{
    auto it = std::find_if(sections().begin(), sections().end(), 
                           [](SectionHeader sh) { return sh.type == SHT_SYMTAB; });

    if (it == sections().end()) {
        m_symtab_info = std::nullopt;
        return;
    }

    m_symtab_info = std::make_pair(it->offset, it->size);
}

} // namespace elf
