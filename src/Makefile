obj-m+=gryphon.o

gryphon-objs+=gryphon_dpi.o gryphon_buffer_management.o

ifeq ($(GRY_MARK),y)
CFLAGS_gryphon_dpi.o += -DENABLE_GRY_MARK
endif

ifeq ($(GRY_DEBUG),y)
CFLAGS_gryphon_dpi.o += -DDEBUG
CFLAGS_gryphon_buffer_management.o += -DDEBUG
endif

all: 
	make -C $(LINUX_DIR) M=$(PWD) modules

clean:
	make -C $(LINUX_DIR) M=$(PWD) clean
