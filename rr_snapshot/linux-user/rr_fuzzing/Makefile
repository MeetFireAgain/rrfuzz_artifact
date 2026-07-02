# RR-Fuzz Module Makefile
# Used to build RR-Fuzz related object files

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -O2 -g -std=gnu99
CFLAGS += -I./include -I.. -I.
CFLAGS += $(shell pkg-config --cflags glib-2.0)
LDFLAGS += $(shell pkg-config --libs glib-2.0)

# Define RR_DEBUG to enable debug logging
CFLAGS += -DRR_DEBUG

# Source files
SOURCES := src/core/rr_main.c src/engine/rr_record.c src/engine/rr_replay.c src/runtime/rr_ipc.c src/runtime/rr_fork_server.c src/engine/rr_fuzz_engine.c src/runtime/rr_snapshot.c
OBJECTS := $(SOURCES:.c=.o)
HEADERS := include/rr_framework.h

# Target: compile all object files
all: $(OBJECTS)

# Pattern rule: compile .c files to .o files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean object files
clean:
	rm -f $(OBJECTS)

# Install target (copy header files to include directory)
install: $(HEADERS)
	mkdir -p ../../include/fuzzing
	cp $(HEADERS) ../../include/fuzzing/

# Help information
help:
	@echo "RR-Fuzz Build System"
	@echo "Available targets:"
	@echo "  all     - Build all object files"
	@echo "  clean   - Remove all object files"
	@echo "  install - Install headers to include directory"
	@echo "  help    - Show this help message"

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists glib-2.0 || (echo "Error: glib-2.0 not found" && exit 1)
	@echo "All dependencies satisfied"

.PHONY: all clean install help check-deps
