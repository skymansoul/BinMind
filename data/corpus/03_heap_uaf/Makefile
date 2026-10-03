# Auto-generated fuzzing Makefile for 03_heap_uaf
CXX ?= clang++
CXXFLAGS += -g -O1 -fsanitize=fuzzer,address

harness: harness.cpp
	$(CXX) $(CXXFLAGS) -o harness harness.cpp -LC:\Users\Administrator\Desktop\BinMind\deemo\samples\teaching\03_heap_uaf -l03_heap_uaf

run: harness
	./harness -max_total_time=300 ./data/corpus\03_heap_uaf/

clean:
	rm -f harness *.o
