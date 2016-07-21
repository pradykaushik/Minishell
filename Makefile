OBJS = minish.o
CC = gcc
DEBUG = -g
CFLAGS = -c $(DEBUG)

shell : $(OBJS)
	$(CC) $(OBJS) -o shell

Execute.o : minish.c
	$(CC) $(CFLAGS) minish.c -o minish.o

clean:
	-rm -f *.o shell

