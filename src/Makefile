KERNELDIR ?= /lib/modules/$(shell uname -r)/build

# 开启EXTRA_CFLAGS=-g-O0，可以得到包含调试信息的模块。
EXTRA_CFLAGS = -DDEBUG -g -O0 -std=gnu11 -Wno-unused-variable -Wno-unused-function

# 若想包含安全部份功能则 make SEC=true
ifdef SEC
	EXTRA_CFLAGS += -D SEC
endif

BUILD_DIR ?= /home/ippp/ippp/ippp_stack_linux/build

obj-m += ippp.o

# 自动包含目录下所有源文件，避免手动管理源文件的麻烦。
SRC_FILES := $(patsubst $(PWD)/%,%,$(shell find $(PWD) -type f -name '*.c'))
OBJ_FILES := $(patsubst %.c, %.o, $(SRC_FILES))
ippp-objs := $(OBJ_FILES)

# -C 表示让 make 命令进入指定的内核源代码目录
# 用KBUILD_EXTMOD_OUTPUT参数指定目标文件存放于另外的单独目录下，以便于管理。
all:
	make -C $(KERNELDIR) M=$(PWD) KBUILD_EXTMOD_OUTPUT=$(BUILD_DIR) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) KBUILD_EXTMOD_OUTPUT=$(BUILD_DIR) clean