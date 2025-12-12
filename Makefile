# libtdwarf - DWARF-based Memory Dump Library
# Makefile for Linux (RHEL 7+ compatible)

CC = gcc
AR = ar
CFLAGS = -Wall -Wextra -fPIC -O2 -g -std=gnu99 -Iinclude
LDFLAGS = -ldwarf -lelf

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
LIB_DIR = lib
EXAMPLES_DIR = examples

# Library
LIB_NAME = libtdwarf
LIB_STATIC = $(LIB_DIR)/$(LIB_NAME).a
LIB_SHARED = $(LIB_DIR)/$(LIB_NAME).so

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Examples
EXAMPLE_USAGE = $(EXAMPLES_DIR)/example_usage
SAMPLE_TARGET = $(EXAMPLES_DIR)/sample_target
EXAMPLE_BACKTRACE = $(EXAMPLES_DIR)/example_backtrace

.PHONY: all clean install examples help

all: dirs $(LIB_STATIC) $(LIB_SHARED)
	@echo ""
	@echo "Build complete!"
	@echo "  Static library: $(LIB_STATIC)"
	@echo "  Shared library: $(LIB_SHARED)"
	@echo ""
	@echo "To build examples: make examples"

dirs:
	@mkdir -p $(BUILD_DIR) $(LIB_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/tdwarf.h
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_STATIC): $(OBJS)
	$(AR) rcs $@ $^

$(LIB_SHARED): $(OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

examples: all $(EXAMPLE_USAGE) $(SAMPLE_TARGET)
	@echo ""
	@echo "Examples built!"
	@echo "  $(EXAMPLE_USAGE)"
	@echo "  $(SAMPLE_TARGET)"

$(EXAMPLE_USAGE): $(EXAMPLES_DIR)/example_usage.c $(LIB_STATIC)
	$(CC) -g -O0 -std=gnu99 $< -o $@ -I$(INC_DIR) -L$(LIB_DIR) -ltdwarf $(LDFLAGS)

$(SAMPLE_TARGET): $(EXAMPLES_DIR)/sample_target.c
	$(CC) -rdynamic -g -O0 -fno-omit-frame-pointer $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR)
	rm -f $(EXAMPLE_USAGE) $(SAMPLE_TARGET)

install: all
	@echo "Installing to /usr/local..."
	install -d /usr/local/include
	install -d /usr/local/lib
	install -m 644 $(INC_DIR)/tdwarf.h /usr/local/include/
	install -m 644 $(LIB_STATIC) /usr/local/lib/
	install -m 755 $(LIB_SHARED) /usr/local/lib/
	ldconfig
	@echo "Installation complete!"

uninstall:
	rm -f /usr/local/include/tdwarf.h
	rm -f /usr/local/lib/$(LIB_NAME).a
	rm -f /usr/local/lib/$(LIB_NAME).so
	ldconfig

help:
	@echo "libtdwarf - DWARF-based Memory Dump Library"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build static and shared libraries (default)"
	@echo "  examples  - Build example programs"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to /usr/local (requires root)"
	@echo "  uninstall - Remove installed files (requires root)"
	@echo "  help      - Show this message"
	@echo ""
	@echo "Usage after build:"
	@echo "  export LD_LIBRARY_PATH=./lib:\$$LD_LIBRARY_PATH"
	@echo "  ./examples/sample_target 5 &"
	@echo "  ./examples/example_usage dump \$$!"
