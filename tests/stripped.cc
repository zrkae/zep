#include <iostream>
#include <assert.h>
#include "../src/zep.hpp"

using namespace elf;

int main()
{
    Elf elf { "../tests/files/stripped" };
    assert(elf.sections.begin() == elf.sections.end());
    assert(elf.symbols.begin() == elf.symbols.end());
}
