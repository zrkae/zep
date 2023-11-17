# zep
Yet another Executable and Linkable Format parser.
Requires a c++20 compliant compiler, makes use of features like concepts and std::format.

### safety
As far as safety is concerned, zep does its best to guarantee that the program doesn't access invalid memory or otherwise crash when _using library provided functions_,
that is, just iterating over the sections of a malformed ELF file should not SEGV, because zep does basic checks to ensure that. What it doesn't do is verify the validity of
struct fields like vaddr or offset, because it doesn't use them directly. It exposes all the necessary information for this kind of bounds checking to the user of the library though.

### build
```
meson setup build
cd build
ninja
```
### test
```
ninja test
```
### cppcheck
```
ninja check
```
