
.SUFFIXES : .c .o

CC = gcc

INCDIR = ../INCLUDE
SRCDIR1 = ../ARP 
SRCDIR2 = ../PCAP
SRCDIR3 = ../UTIL
SRCDIR4 = ../SCAN
SRCDIR5 = ../MAIN
SRCDIR6 = ../DNS
SRCDIR7 = ../DRDOS

VPATH = $(SRCDIR1) $(SRCDIR2) $(SRCDIR3) $(SRCDIR4) $(SRCDIR5) $(SRCDIR6) $(SRCDIR7)

CFLAGS = -O2 -I$(INCDIR)

LIBS = -lpcap

TARGET = cameleon

SRCS = $(foreach dir, $(SRCDIR1) $(SRCDIR2) $(SRCDIR3) $(SRCDIR4) $(SRCDIR5) $(SRCDIR6) $(SRCDIR7), $(wildcard $(dir)/*.c))
SRCS := $(notdir $(SRCS))

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $^ -o $(TARGET) $(LIBS)
	mv $(TARGET) ../

clean:
	-rm -rf $(OBJS)
	-rm -f ../$(TARGET)
