CMAKE_OPTIONS = -DDEBUG=1 -DCMAKE_VERBOSE_MAKEFILE=0

all: build/Makefile
	make -C build all

build/Makefile:
	[ -d build ] || mkdir build; \
	cd build && cmake $(CMAKE_OPTIONS) ..

clean:
	rm -rf build

.PHONY: all clean
