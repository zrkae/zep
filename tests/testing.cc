#include <iostream>
#include <vector>
#include "../src/elf-parser.hpp"

using namespace elf;

int main()
{
    Elf elf { "files/hello-world" };

    std::cout << "PROG HEADERS: \n";
    
    for (const auto& ph : elf.prog_headers()) 
        std::cout << ph.offset << "\n";

    std::cout << "\n\nSECTIONS: \n";

    for (const auto& sh : elf.sections()) 
        std::cout << sh.str_name(elf).value() << "\n";

    std::cout << "\n\nSYMBOLS: \n";

    for (const auto& sym : elf.symbols()) 
        std::cout << sym.str_name(elf).value() << "\n";
}
