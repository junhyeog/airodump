LDLIBS=-lpcap
TARGET=airodump

all: $(TARGET)

$(TARGET): main.o airodump.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f  *.o $(TARGET)
