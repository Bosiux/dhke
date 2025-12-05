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

all: local protocol server client

local: main.c $(SRC_FILES)
	$(CC) $(CFLAGS) $(SRC_FILES) main.c -o local $(LIBS)

protocol: protocol_test.c $(SRC_FILES) $(PROTOCOL_DIR)/protocol.c
	$(CC) $(CFLAGS) $(SRC_FILES) $(PROTOCOL_DIR)/protocol.c protocol_test.c -o protocol $(LIBS)

server: server.c $(SRC_FILES) $(PROTOCOL_DIR)/protocol.c
	$(CC) $(CFLAGS) $(SRC_FILES) $(PROTOCOL_DIR)/protocol.c server.c -o server $(LIBS)

client: client.c $(SRC_FILES) $(PROTOCOL_DIR)/protocol.c
	$(CC) $(CFLAGS) $(SRC_FILES) $(PROTOCOL_DIR)/protocol.c client.c -o client $(LIBS)
clean:
	rm -f local protocol server client



