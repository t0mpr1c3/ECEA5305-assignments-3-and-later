SHELL := /bin/sh
CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Werror -Og -ggdb
TARGET := aesdsocket
SRC := aesdsocket.c
OBJ := $(SRC:.c=.o)
DESTDIR := $(dirname $0)/..

.PHONY: all default
all default: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJ)

.PHONY: install
install:
	mv $(TARGET) $(DESTDIR)/server
