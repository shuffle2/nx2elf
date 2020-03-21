all: *.cpp *.c *.h
	g++ -m64 -o nx2elf *.cpp *.c -lstdc++fs -std=c++14
