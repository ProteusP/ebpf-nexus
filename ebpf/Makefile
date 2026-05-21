CC       = clang
CFLAGS   = -O2 -target bpf -g -I src
BUILD_DIR = build
SRC_DIR   = src

SRCS = $(wildcard $(SRC_DIR)/*.bpf.c)
OBJS = $(patsubst $(SRC_DIR)/%.bpf.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean check

all: $(BUILD_DIR) $(OBJS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.bpf.c $(SRC_DIR)/common.h
	$(CC) $(CFLAGS) -c $< -o $@

check:
	@which clang > /dev/null || (echo "ERROR: clang not found" && exit 1)
	@echo "All tools found"

clean:
	rm -rf $(BUILD_DIR)