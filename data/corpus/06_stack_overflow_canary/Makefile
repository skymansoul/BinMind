# Auto-generated fuzzing Makefile for 06_stack_overflow_canary
CXX ?= clang++
CXXFLAGS += -g -O1 -fsanitize=fuzzer,address

harness: harness.cpp
	$(CXX) $(CXXFLAGS) -o harness harness.cpp -LC:\Users\Administrator\Desktop\BinMind\deemo\samples\teaching\06_stack_overflow_canary -l06_stack_overflow_canary

run: harness
	./harness -max_total_time=300 ./data/corpus\06_stack_overflow_canary/

clean:
	rm -f harness *.o
