CXX      ?= g++
CXXFLAGS ?= -O3 -Wall -std=c++17

all: port_infer

port_infer: port_infer.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< -pthread -ltins

run: port_infer
	sudo ./port_infer

clean:
	rm -f port_infer

.PHONY: all run clean
