CC       = gcc
STD      = -std=gnu17
WARNINGS = -Wall -Wextra -Wpedantic

# Source files
SRCS     = sha256.c sha256_arm.c main.c
TEST_SRC = sha256.c sha256_arm.c sha256_unit_test.c

TARGET   = sha256
TEST_BIN = sha256_unit_test

.PHONY: all dev asan clean

# Default: production (no -DNDEBUG — asserts remain active)
all: CFLAGS = $(STD) -O2
all: $(TARGET) $(TEST_BIN)

# Dev build: debug + warnings + unit test
dev: CFLAGS = $(STD) -O0 -g3 $(WARNINGS)
dev: $(TARGET) $(TEST_BIN)

# AddressSanitizer + UndefinedBehaviourSanitizer — build and run tests
asan: CFLAGS = $(STD) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer $(WARNINGS)
asan: LDFLAGS = -fsanitize=address,undefined
asan: $(TEST_BIN)
	./$(TEST_BIN)

$(TARGET): $(SRCS:.c=.o)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(TEST_BIN): $(TEST_SRC:.c=.o)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(TARGET) $(TEST_BIN)
