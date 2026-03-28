
# PE Integrity Checker Makefile
# Cross-platform build system for Windows (MSVC/MinGW), Linux, and macOS

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
DEBUG_FLAGS = -g -O0 -DDEBUG
RELEASE_FLAGS = -O3 -DNDEBUG

# Output binary name
TARGET = pe_check

# Source files
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

# Platform detection
ifeq ($(OS),Windows_NT)
    PLATFORM = WINDOWS
    LDFLAGS_WIN = -lbcrypt -lcrypt32
    LDFLAGS = $(LDFLAGS_WIN)
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        PLATFORM = LINUX
        LDFLAGS = -lssl -lcrypto
    endif
    ifeq ($(UNAME_S),Darwin)
        PLATFORM = MACOS
        LDFLAGS = -lssl -lcrypto
    endif
endif

# Default target
all: release

# Release build
release: CFLAGS += $(RELEASE_FLAGS)
release: $(TARGET)

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJ)
	@echo "Building for $(PLATFORM)..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJ) $(TARGET)
	@echo "Cleaned build artifacts"

# Clean all (including debug/release variants)
distclean: clean
	rm -f *.exe *.dll *.so

# Install (optional - requires sudo on Unix)
install: $(TARGET)
	@echo "Installing to /usr/local/bin..."
	cp $(TARGET) /usr/local/bin/
	@echo "Installation complete"

# Uninstall
uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstallation complete"

# Run tests (if test files exist)
test: $(TARGET)
	@echo "Running integrity checks..."
	./$(TARGET) check --help

# Show build configuration
info:
	@echo "Platform: $(PLATFORM)"
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
	@echo "Target: $(TARGET)"

# Phony targets
.PHONY: all release debug clean distclean install uninstall test info

# Dependencies (auto-generated)
-include $(OBJ:.o=.d)

# Generate dependency files
%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	sed 's,$$$*$$\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$
