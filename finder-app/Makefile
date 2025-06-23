writer all: writer.o
	$(CC) $(CFLAGS) writer.o -o writer $(LDFLAGS)

writer.o: writer.c
	$(CC) $(CFLAGS) -c writer.c -o writer.o

.PHONY: clean
clean:
	rm -f writer writer.o
