
ifndef OPTIMIZE
	OPTIMIZE = -O2
endif
CFLAGS = -Wall -Wextra -ggdb3 $(OPTIMIZE) -fno-stack-protector -fpic -fPIC
LDFLAGS = -ggdb3 $(OPTIMIZE)
LIBS = -lpthread
DEPFLAGS = -MMD -MP -MF $@.d
LDFLAGS_SHARED = $(LDFLAGS) -e main -shared -fpic -fPIC

ifeq ($(SANITIZE),1)
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address -fsanitize=undefined
endif

ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG
else
	CFLAGS += -DNDEBUG
endif

ifeq ($(LTO),1)
	CFLAGS += -flto
	LDFLAGS += -flto
endif

ifeq ($(STATIC),1)
	LDFLAGS += -static
endif

GWPROXY_TARGET = gwproxy
GWPROXY_CC_SOURCES = gwproxy.c
GWPROXY_OBJECTS = $(GWPROXY_CC_SOURCES:%.c=%.c.o)

LIBGWPSOCKS5_TARGET = libgwpsocks5.so
LIBGWPSOCKS5_CC_SOURCES = socks5.c
LIBGWPSOCKS5_OBJECTS = $(LIBGWPSOCKS5_CC_SOURCES:%.c=%.c.o)

ALL_OBJECTS = $(GWPROXY_OBJECTS) $(LIBGWPSOCKS5_OBJECTS)

all: $(GWPROXY_TARGET) $(LIBGWPSOCKS5_TARGET)

$(GWPROXY_TARGET): $(GWPROXY_OBJECTS) $(ALL_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(LIBGWPSOCKS5_TARGET): $(LIBGWPSOCKS5_OBJECTS)
	$(CC) $(LDFLAGS_SHARED) -o $@ $^ $(LIBS)

%.c.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

clean:
	rm -f $(GWPROXY_OBJECTS) $(LIBGWPSOCKS5_OBJECTS) \
		$(GWPROXY_TARGET) $(LIBGWPSOCKS5_TARGET) \
		*.d

test: $(LIBGWPSOCKS5_TARGET)
	/lib64/ld-linux-x86-64.so.2 ./$(LIBGWPSOCKS5_TARGET)

.PHONY: all clean test
