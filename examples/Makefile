# Makefile for compiling local and protocol tests

# Directories
INCLUDE_DIR = ../include
PROTOCOL_DIR = ../protocol
SRC_DIR = ../src

# Compiler and flags
CC = gcc
CFLAGS = -I$(INCLUDE_DIR) -I$(PROTOCOL_DIR)
LIBS = -lcrypto -lssl

# Sources
SRC_FILES = $(wildcard $(SRC_DIR)/dhke*.c)

# Targets
.PHONY: all local protocol clean help

all: local protocol

local: main.c $(SRC_FILES)
	$(CC) $(CFLAGS) $(SRC_FILES) main.c -o local $(LIBS)

protocol: protocol_test.c $(SRC_FILES) $(PROTOCOL_DIR)/protocol.c
	$(CC) $(CFLAGS) $(SRC_FILES) $(PROTOCOL_DIR)/protocol.c protocol_test.c -o protocol $(LIBS)

clean:
	rm -f local protocol

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all             Build both main_test and protocol_test"
	@echo "  local       Compile the local test (main.c)"
	@echo "  protocol   Compile the protocol test (protocol_test.c)"
	@echo "  clean           Remove compiled binaries"
	@echo "  help            Show this help message"

