#include <iostream>
#include <assert.h>
#include "../src/zep.hpp"

using namespace elf;

int main()
{
    Elf elf { TEST_FILE_DIR"stripped" };
    assert(!elf.has_sections());
    assert(!elf.has_symbols());
}
