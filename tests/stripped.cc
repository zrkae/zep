#include <iostream>
#include <assert.h>
#include "../src/zep.hpp"

using namespace elf;

int main()
{
    Elf elf { TEST_FILE_DIR"stripped" };
    assert(elf.sections.begin() == elf.sections.end());
    assert(elf.symbols.begin() == elf.symbols.end());
}
