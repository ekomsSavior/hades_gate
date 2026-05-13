# ⛧ Hades Gate — Makefile
#
# Targets:
#   all        — Build library and all examples
#   lib        — Build hades_gate.o only
#   simple     — Build simple_use.exe
#   injector   — Build injector.exe
#   clean      — Remove build artifacts
#
# Requirements:
#   x86_64-w64-mingw32-gcc (MinGW cross-compiler)
#   or MSVC tools via 'make CC=cl'
#
# Cross-compile for Windows from Linux:
#   apt install mingw-w64
#   make CC=x86_64-w64-mingw32-gcc

CC      ?= x86_64-w64-mingw32-gcc
CFLAGS  ?= -Os -masm=intel -fno-asynchronous-unwind-tables
LDFLAGS ?= -nostdlib -lkernel32 -lntdll
RM      ?= rm -f

SRC_DIR = src
EXA_DIR = examples
BLD_DIR = build

SRC = $(SRC_DIR)/hades_gate.c
OBJ = $(BLD_DIR)/hades_gate.o
LIB = $(BLD_DIR)/hades_gate.lib

.PHONY: all lib simple injector clean dirs

all: dirs lib simple injector

dirs:
	@mkdir -p $(BLD_DIR)

# Library object
lib: dirs
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

# Static library (MinGW .a format)
$(LIB): lib
	$(AR) rcs $(LIB) $(OBJ)

# Simple usage example
simple: dirs lib
	$(CC) $(CFLAGS) $(SRC) $(EXA_DIR)/simple_use.c -o $(BLD_DIR)/simple_use.exe $(LDFLAGS)

# Full injector example
injector: dirs lib
	$(CC) $(CFLAGS) $(SRC) $(EXA_DIR)/injector.c -o $(BLD_DIR)/injector.exe $(LDFLAGS)

# Clean everything
clean:
	$(RM) -r $(BLD_DIR)
