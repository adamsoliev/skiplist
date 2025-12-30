CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g

SRC = src/main.cpp
TARGET = mini-lsm

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: all clean
