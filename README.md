# GhidraVtableStructGenerator

A simple struct generator for C++ class vtables in ghidra.  Currently only works for 32 bit programs but should be easily modifyable to work with 64 bit ones.

To run: enable the script in the script manager, then go to Tools -> Misc -> Make Vtable Struct

Input the address of the first entry of the vtable, the program will automatically find the end.

Then Input the name you want of the newly generated struct, it will then appear in your Data Type Manager
