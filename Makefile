CFLAGS=-g -Wall -Wpedantic -Isrc
LFLAGS=
objects=src/iaddrtrace.o

.PHONY: all clean

all: iaddrtrace

clean:
	rm -f mw_render
	rm -f src/*.o

iaddrtrace: $(objects)
	${CC} ${LFLAGS} -o iaddrtrace $(objects)
