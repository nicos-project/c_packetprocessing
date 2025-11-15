CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11 -O2
TARGET = bucket_test
SRCDIR = src
OBJS = main.o $(SRCDIR)/network.o $(SRCDIR)/packet.o $(SRCDIR)/flow_table.o $(SRCDIR)/utils.o $(SRCDIR)/pingpong.o $(SRCDIR)/test_cases.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

main.o: main.cpp $(SRCDIR)/config.h $(SRCDIR)/network.h $(SRCDIR)/flow_table.h $(SRCDIR)/test_cases.h
	$(CXX) $(CXXFLAGS) -c main.cpp

$(SRCDIR)/network.o: $(SRCDIR)/network.cpp $(SRCDIR)/network.h
	$(CXX) $(CXXFLAGS) -c $(SRCDIR)/network.cpp -o $(SRCDIR)/network.o

$(SRCDIR)/packet.o: $(SRCDIR)/packet.cpp $(SRCDIR)/packet.h $(SRCDIR)/config.h $(SRCDIR)/flow_table.h
	$(CXX) $(CXXFLAGS) -c $(SRCDIR)/packet.cpp -o $(SRCDIR)/packet.o

$(SRCDIR)/flow_table.o: $(SRCDIR)/flow_table.cpp $(SRCDIR)/flow_table.h
	$(CXX) $(CXXFLAGS) -c $(SRCDIR)/flow_table.cpp -o $(SRCDIR)/flow_table.o

$(SRCDIR)/utils.o: $(SRCDIR)/utils.cpp $(SRCDIR)/utils.h
	$(CXX) $(CXXFLAGS) -c $(SRCDIR)/utils.cpp -o $(SRCDIR)/utils.o

$(SRCDIR)/pingpong.o: $(SRCDIR)/pingpong.cpp $(SRCDIR)/pingpong.h $(SRCDIR)/packet.h $(SRCDIR)/flow_table.h
	$(CXX) $(CXXFLAGS) -c $(SRCDIR)/pingpong.cpp -o $(SRCDIR)/pingpong.o

$(SRCDIR)/test_cases.o: $(SRCDIR)/test_cases.cpp $(SRCDIR)/test_cases.h $(SRCDIR)/pingpong.h $(SRCDIR)/flow_table.h
	$(CXX) $(CXXFLAGS) -c $(SRCDIR)/test_cases.cpp -o $(SRCDIR)/test_cases.o

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
