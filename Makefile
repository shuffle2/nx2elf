all: *.cpp *.c *.h
	g++ -o nx2elf *.cpp *.c -lstdc++fs -std=c++14
