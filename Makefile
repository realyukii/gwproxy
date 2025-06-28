
ifndef OPTIMIZE
	OPTIMIZE = -O2
endif
CFLAGS = -Wall -Wextra -ggdb3 $(OPTIMIZE)
LDFLAGS = -ggdb3
LIBS = -lpthread
DEPFLAGS = -MMD -MP -MF $@.d

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

TARGET = gwproxy
CC_SOURCES = \
	gwproxy.c

OBJECTS = $(CC_SOURCES:%.c=%.c.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

-include $(OBJECTS:.o=.d)

%.c.o: %.c Makefile
	$(CC) $(CFLAGS) $(DEPFLAGS) -o $@ -c $<

clean:
	rm -vf $(TARGET) *.o *.d

.PHONY: all clean
