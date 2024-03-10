CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -lpcap
DIR = src/
TEST_DIR = tests/

ipk-sniffer: $(DIR)error.o $(DIR)arguments.o $(DIR)interfaces.o $(DIR)filter.o $(DIR)sniffer.o
	$(CC) $(CFLAGS) $^ $(DIR)main.c -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f $(DIR)*.o ipk-sniffer $(TEST_DIR)*.out
