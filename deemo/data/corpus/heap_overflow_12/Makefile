# Auto-generated fuzzing Makefile for heap_overflow_12
CXX ?= clang++
CXXFLAGS += -g -O1 -fsanitize=fuzzer,address

harness: harness.cpp
	$(CXX) $(CXXFLAGS) -o harness harness.cpp -LC:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_binaries -lheap_overflow_12

run: harness
	./harness -max_total_time=300 ./data/corpus\heap_overflow_12/

clean:
	rm -f harness *.o
