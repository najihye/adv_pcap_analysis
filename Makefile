all : adv_pcap_analysis


adv_pcap_analysis: main.o
	g++ -g -o adv_pcap_analysis main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f adv_pcap_analysis
	rm -f *.o


