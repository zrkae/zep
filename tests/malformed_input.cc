#include <iostream>
#include <format>
#include <cstring>
#include <assert.h>

#include "../src/zep.hpp"

using namespace elf;

void expect_invalid_size(const char *file_name, const char *expected_message="")
{
    try {
        Elf elf { file_name };
    } catch(invalid_file_size& e) {
        if (expected_message[0] != 0)
            assert(!std::strcmp(expected_message, e.what()));
        return;
    }
    std::cerr << "File: " << file_name << "expected invalid_file_size but got no exception\n";
    std::exit(1);
}

int main()
{
    // TODO: don't compare strings, instead use seperate classes for the exceptions
    expect_invalid_size("../tests/files/malformed_too_small", "Supplied ELF too small!");
    expect_invalid_size("../tests/files/malformed_preserved_header", "Header table offset larger than file size.");
    expect_invalid_size("../tests/files/malformed_offset_outofbounds", "Header table offset larger than file size.");

    return 0;
}
