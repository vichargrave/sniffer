CC			= gcc
CFLAGS		= -c -Wall -D_GNU_SOURCE
LDFLAGS		= -lpcap
SOURCES		= sniffer.c
INCLUDES	= -I.
OBJECTS		= $(SOURCES:.c=.o)
TARGET		= sniffer

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -rf $(OBJECTS) $(TARGET)
