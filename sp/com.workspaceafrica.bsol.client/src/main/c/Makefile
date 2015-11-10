include ../../../Makefile.inc

CXXFLAGS =	-O2 -g -Wall -fmessage-length=0 -Iinclude/

OBJS =		main.o

LIBS =

TARGET =	client


%.o: %.c 
	$(CC) $(CFLAGS) $(DEFS) -c $<

$(TARGET):	$(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LIBS)



all:	$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
