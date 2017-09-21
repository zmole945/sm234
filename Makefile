CC=gcc -g  $(CFLAGS) -DLINUX -w
SHARED_FLAG = -fPIC -shared

INC = -I./
OBJ =

MODULE =  -lcrypto

all : doxygen

doxygen :
	doxygen Doxyfile

run :

clean:
	rm -rf ./doc

%.o : %.cpp
	$(CC) $(SHARED_FLAG) -c $< $(INC)
%.o : %.c
	$(CC) $(SHARED_FLAG) -c $< $(INC)
