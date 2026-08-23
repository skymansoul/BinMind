# Auto-generated fuzzing Makefile for 02_format_string
CXX ?= clang++
CXXFLAGS += -g -O1 -fsanitize=fuzzer,address

harness: harness.cpp
	$(CXX) $(CXXFLAGS) -o harness harness.cpp -LC:\Users\Administrator\Desktop\BinMind\deemo\samples\teaching\02_format_string -l02_format_string

run: harness
	./harness -max_total_time=300 ./data/corpus\02_format_string/

clean:
	rm -f harness *.o
