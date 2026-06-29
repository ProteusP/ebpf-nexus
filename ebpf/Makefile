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

ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    ARCH_FLAG = -D__TARGET_ARCH_aarch64
else ifeq ($(ARCH),x86_64)
    ARCH_FLAG = -D__TARGET_ARCH_x86_64
else
    $(error Unsupported architecture: $(ARCH))
endif

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.bpf.c $(SRC_DIR)/common.h
	$(CC) $(ARCH_FLAG) $(CFLAGS) -c $< -o $@

check:
	@which clang > /dev/null || (echo "ERROR: clang not found" && exit 1)
	@echo "All tools found"

clean:
	rm -rf $(BUILD_DIR)