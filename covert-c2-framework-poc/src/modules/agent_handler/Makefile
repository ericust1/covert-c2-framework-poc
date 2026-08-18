CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lcurl -lssl -lcrypto

TARGET = agent
SRC = agent.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
