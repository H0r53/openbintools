#Author:	Jacob Mills
#Date:		11/18/2018
#Description:	This Makefile build the accessnotify.x client for monitoring concurrent file accesses on a system
#		The clean option will remove .pyc bytecode along with the accessnotify client and object code
#


CC = g++
OBJS = accessnotify.o
ARGS = -Wall -pedantic -std=c++11

all: accessnotify
	@echo "Building accessnotify client!"

accessnotify: accessnotify.o
	$(CC) accessnotify.o -o accessnotify.x $(ARGS)

accessnotify.o: accessnotify.cpp
	$(CC) -c accessnotify.cpp $(ARGS)

clean:
	@echo "Cleaning files..."
	rm -f *.o accessnotify.x *.pyc
