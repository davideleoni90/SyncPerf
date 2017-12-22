#OBJS = nptl-init.o 
CPU_MAX_FREQ=$(shell cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)
CC = gcc
CFLAGS= -g -Og -fno-omit-frame-pointer -I. -D_GNU_SOURCE -fPIC -DWITH_TRYLOCK  -DCPU_FREQ=$(CPU_MAX_FREQ) #-DREPORT_LINE_INFO #-DVERBOSE_OUTPUT #-DGET_STATISTICS -DCONTEXT_SORT #-DUSE_BINDING -DMY_DEBUG -DWITH_COND -DCOMBINED_REPORT


LD = $(CC)
LDFLAGS = -rdynamic -lpthread -ldl  -shared -lstdc++

TARGET = liblockperf.so 

SRCS = $(wildcard *.c)
CPP_SRCS = $(wildcard *.cpp)
OBJS = $(patsubst %.c,%.o,$(SRCS))
CPP_OBJS = $(patsubst %.cpp,%.o,$(CPP_SRCS))

#OBJECTS_AS := $(patsubst %.s,%.o,$(wildcard *.S))
OBJECTS_AS = lowlevellock.o
all: $(TARGET) 

$(TARGET) : $(OBJS) $(OBJECTS_AS) $(CPP_OBJS)
#$(TARGET) : $(OBJS) 
	$(LD) -o $@ $^ $(LDFLAGS)
%.o : %.c
	$(CC) $(CFLAGS) -c $<
%.o : %.cpp
	$(CC) $(CFLAGS) -fpermissive -c $<
%.o : %.S
	$(CC) $(CFLAGS) -c $<

#CSCOPE:
#	`find -name '*.c' -o -name '*.cpp' -o -name '*.h' -name '*.hh'> cscope.files`
#	`cscope -b -q -k`

clean:
	rm -f liblockperf.so *.o
