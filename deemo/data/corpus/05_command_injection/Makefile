# Auto-generated fuzzing Makefile for 05_command_injection
CXX ?= clang++
CXXFLAGS += -g -O1 -fsanitize=fuzzer,address

harness: harness.cpp
	$(CXX) $(CXXFLAGS) -o harness harness.cpp -LC:\Users\Administrator\Desktop\BinMind\deemo\samples\teaching\05_command_injection -l05_command_injection

run: harness
	./harness -max_total_time=300 ./data/corpus\05_command_injection/

clean:
	rm -f harness *.o
