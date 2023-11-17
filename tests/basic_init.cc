#include <iostream>
#include <format>
#include "../src/zep.hpp"

using namespace elf;

int main()
{
    try {
        Elf elf { "../tests/files/hello-world" };
    } catch(invalid_magic& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    try {
        Elf elf { "../tests/files/stripped" };
    } catch(std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}
