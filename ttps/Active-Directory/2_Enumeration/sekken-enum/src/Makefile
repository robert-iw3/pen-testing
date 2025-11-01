CC_x86 := i686-w64-mingw32-gcc
CC_x64 := x86_64-w64-mingw32-gcc
STRIP_x86 := i686-w64-mingw32-strip
STRIP_x64 := x86_64-w64-mingw32-strip
CFLAGS := -Os -masm=intel -DBOF

all: sekken-enum

sekken-enum: sekken-enum.c
	$(CC_x64) $(CFLAGS) -o ../sekken-enum.x64.o -c sekken-enum.c
	$(STRIP_x64) --strip-unneeded ../sekken-enum.x64.o

	$(CC_x86) $(CFLAGS) -o ../sekken-enum.x86.o -DWOW64 -fno-leading-underscore -c sekken-enum.c
	$(STRIP_x86) --strip-unneeded ../sekken-enum.x86.o

clean:
	rm -f ../*.o