CC=gcc -g  $(CFLAGS) -DLINUX -w
SHARED_FLAG = -fPIC -shared

PROJECT = sm2test

INC  = -I./
OBJ = sm2.o sm2test.o

MODULE =  -lcrypto

all : ${OBJ} $(PROJECT)

$(PROJECT) : ${OBJ}
	$(CC) ${OBJ} -o $(PROJECT) $(INC) $(MODULE)

clean:
	rm -rf *.o *.a *.so
	rm -rf sm2test

%.o : %.cpp
	$(CC) $(SHARED_FLAG) -c $< $(INC)
%.o : %.c %.h
	$(CC) $(SHARED_FLAG) -c $< $(INC)
