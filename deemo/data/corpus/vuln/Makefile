# Auto-generated fuzzing Makefile for vuln
CXX ?= clang++
CXXFLAGS += -g -O1 -fsanitize=fuzzer,address

harness: harness.cpp
	$(CXX) $(CXXFLAGS) -o harness harness.cpp -LC:\Users\Administrator\Desktop\BinMind\deemo\tests\samples\int_overflow\io_loop_counter -lvuln

run: harness
	./harness -max_total_time=300 ./data/corpus\vuln/

clean:
	rm -f harness *.o
