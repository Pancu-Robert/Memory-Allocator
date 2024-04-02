# Memory Allocator

## Statement

Build a minimalistic memory allocator that can be used to manually manage virtual memory.
The goal is to have a reliable library that accounts for explicit allocation, reallocation, and initialization of memory.


## Building Memory Allocator

To build `libosmem.so`, run `make` in the `src/` directory:

## Testing and Grading

The testing is automated and performed with the `checker.py` script from the `tests/` directory.

Before running `checker.py`, you first have to build `libosmem.so` in the `src/` directory and generate the test binaries in `tests/bin`.
Run `make` in the `tests/` directory and then python checker.py
