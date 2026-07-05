CC = gcc
CFLAGS = -Wall -Wextra -O2
LDLIBS = -lpcap

TARGET = pcap_packet_printer
SRC = pcap_packet_printer.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDLIBS)

run: $(TARGET)
	sudo ./$(TARGET) enp0s3 10 "tcp"

clean:
	rm -f $(TARGET)
