# Auto-generated fuzzing Makefile for 01_stack_overflow
CXX ?= clang++
CXXFLAGS += -g -O1 -fsanitize=fuzzer,address

harness: harness.cpp
	$(CXX) $(CXXFLAGS) -o harness harness.cpp -LC:\Users\Administrator\Desktop\BinMind\deemo\samples\teaching\01_stack_overflow -l01_stack_overflow

run: harness
	./harness -max_total_time=300 ./data/corpus\01_stack_overflow/

clean:
	rm -f harness *.o
