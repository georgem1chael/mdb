CC     = gcc
CFLAGS = -Wall -Wextra -g
LIBS   = -lelf -lcapstone

TARGET = mdb
SRC    = mdb.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# allows: make run ./binary
run: $(TARGET)
	@test -n "$(filter-out run, $(MAKECMDGOALS))" || (echo "[mdb] usage: make run <binary>"; exit 1)
	./$(TARGET) $(filter-out run, $(MAKECMDGOALS))

%:
	@:

clean:
	rm -f $(TARGET)
