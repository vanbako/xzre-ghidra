CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

SRCS := main.c ../../ghidra_scripts/generated/string_rodata.c
TARGET := decode_strings

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
