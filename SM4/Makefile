CC=gcc -g  $(CFLAGS) -DLINUX -w
SHARED_FLAG = -fPIC -shared

PROJECT = sm4test

INC  = -I./
OBJ = sm4.o sm4test.o

MODULE =  -lcrypto

all : ${OBJ} $(PROJECT)

$(PROJECT) : ${OBJ}
	$(CC) ${OBJ} -o $(PROJECT) $(INC) $(MODULE)

run :
	./${PROJECT}

clean:
	rm -rf *.o *.a *.so
	rm ${PROJECT}

%.o : %.cpp
	$(CC) $(SHARED_FLAG) -c $< $(INC)
%.o : %.c
	$(CC) $(SHARED_FLAG) -c $< $(INC)
