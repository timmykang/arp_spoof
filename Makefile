all: arp_spoof

arp_spoof: main.o arp.o
	g++ -o arp_spoof main.o arp_spoof.o -lpcap

arp.o: arp.cpp arp.h
	g++ -c -o arp_spoof.o arp_spoof.cpp

main.o: main.cpp arp.h
	g++ -c -o main.o main.cpp

clean:
	rm -f arp_spoof *.o
