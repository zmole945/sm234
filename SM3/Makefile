CC=gcc -g  $(CFLAGS) -DLINUX -w
SHARED_FLAG = -fPIC -shared

PROJECT = sm3test

INC  = -I./
OBJ = sm3.o sm3test.o

MODULE =  -lcrypto

all : ${OBJ} $(PROJECT)

$(PROJECT) : ${OBJ}
	$(CC) ${OBJ} -o $(PROJECT) $(INC) $(MODULE)

run :
	./$(PROJECT)

clean:
	rm -rf *.o *.a *.so
	rm -rf sm3test

%.o : %.cpp
	$(CC) $(SHARED_FLAG) -c $< $(INC)
%.o : %.c
	$(CC) $(SHARED_FLAG) -c $< $(INC)
