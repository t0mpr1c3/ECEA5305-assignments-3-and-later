CC := $(CROSS_COMPILE)gcc
CFLAGS := -Wall -Werror
TARGET := writer
SRC := writer.c
OBJ := $(SRC:.c=.o)

.PHONY: all default
all default: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJ)
