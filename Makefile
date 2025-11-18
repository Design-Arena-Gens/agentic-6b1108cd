CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -O2
LDFLAGS =

SRC_DIR = src
TEST_DIR = tests

SRCS = $(wildcard $(SRC_DIR)/*.c)
APP_SRCS = $(filter-out $(SRC_DIR)/main.c,$(SRCS))
OBJS = $(SRCS:.c=.o)

TARGET = qrng_encrypt

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

test: $(TARGET)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -DTESTING -o $(TEST_DIR)/test_runner \
		$(TEST_DIR)/test_runner.c \
		$(TEST_DIR)/test_input.c \
		$(TEST_DIR)/test_file_ops.c \
		$(TEST_DIR)/test_crypto.c \
		$(APP_SRCS) $(LDFLAGS)
	./$(TEST_DIR)/test_runner

clean:
	rm -f $(TARGET) $(SRC_DIR)/*.o $(TEST_DIR)/test_runner
