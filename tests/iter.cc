#include <iostream>
#include <assert.h>
#include "../src/zep.hpp"

using namespace elf;

int main()
{
    Elf elf { TEST_FILE_DIR"hello-world" };

    uint64_t ph_offsets[] = {64, 792, 0, 4096, 8192, 11728, 11744, 824, 888, 824, 8212, 0, 11728};

    std::string_view section_names[] = {"", ".interp", ".note.gnu.property", ".note.gnu.build-id", ".note.ABI-tag", ".gnu.hash", 
        ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r", ".rela.dyn", ".rela.plt", ".init", ".plt", ".text", ".fini", 
        ".rodata", ".eh_frame_hdr", ".eh_frame", ".init_array", ".fini_array", ".dynamic", ".got", ".got.plt", ".data", ".bss", 
        ".comment", ".symtab", ".strtab", ".shstrtab" };

    std::string_view symbols[] = {"", "hello-world.c", "", "_DYNAMIC", "__GNU_EH_FRAME_HDR", "_GLOBAL_OFFSET_TABLE_", "__libc_start_main@GLIBC_2.34", "_ITM_deregisterTMCloneTable", "data_start", "puts@GLIBC_2.2.5", "_edata", "_fini", "__data_start", "__gmon_start__", "__dso_handle", "_IO_stdin_used", "_end", "_start", "__bss_start", "main", "__TMC_END__", "_ITM_registerTMCloneTable", "__cxa_finalize@GLIBC_2.2.5", "_init" };

    int i = 0;
    for (const auto& ph : elf.prog_headers) {
        assert(ph.offset == ph_offsets[i]); 
        i++;
    }

    i = 0;
    for (const auto& section : elf.sections) {
        assert(section.str_name(elf).value() == section_names[i]); 
        i++;
    }

    i = 0;
    for (const auto& symbol : elf.symbols) {
        assert(symbol.str_name(elf).value() == symbols[i]); 
        i++;
    }

    return 0;
}
