all:
	mkdir -p bin
	g++ main.cpp --std=c++11 -o bin/firewall -lnetfilter_queue
