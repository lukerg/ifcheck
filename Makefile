
OBJS=ifcheck.o filedata.o

all: ifcheck

ifcheck: $(OBJS)
	gcc -g -o $@ $^ -lnetsnmp

%.o: %.c
	gcc -g -o $@ -c $^

clean:
	rm *.o
	rm ifcheck

