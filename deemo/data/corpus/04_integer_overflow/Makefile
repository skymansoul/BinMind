# Auto-generated fuzzing Makefile for 04_integer_overflow
CXX ?= clang++
CXXFLAGS += -g -O1 -fsanitize=fuzzer,address

harness: harness.cpp
	$(CXX) $(CXXFLAGS) -o harness harness.cpp -LC:\Users\Administrator\Desktop\BinMind\deemo\samples\teaching\04_integer_overflow -l04_integer_overflow

run: harness
	./harness -max_total_time=300 ./data/corpus\04_integer_overflow/

clean:
	rm -f harness *.o
