CC=gcc
LIB=-lssl

DEBUG?=0
ifeq (${DEBUG}, 1)
    CFLAGS=-c -Wall -DDEBUG -g
    LDFLAGS=-Wall -g
else
    CFLAGS=-c -Wall -o3
    LDFLAGS=-Wall
endif

SOURCES=lisod.c log.c fifo.c http.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=lisod

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIB)

.c.o:
	$(CC) $(CFLAGS) $< -o $@ 

clean:
	@rm -rf lisod *.o
