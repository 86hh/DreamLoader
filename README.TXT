DreamLoader by hh86

some of its features:
- simple cross-platform PE loader, x86/x64 compatible code in a single execution path
- supports both Intel 386 and AMD64 Portable Executable files
- supports files with/without import table
- supports files with/without reloc table
- uses CRCs instead of API names to reduce code size

yes, this is HLDR32/HLDR64 from PE2SHC by hasherezade, but combined!
it's an idea I had when I proposed HLDR32 but it was discarded. :( now I have it. :)
it needs more testing, if a bug is found, let me know.


to build this thing:
yasm
----
yasm -f bin dreamldr.asm -o dreamldr.bin
add dreamldr to your code and call like this: dreamldr(ptr to PE file)
