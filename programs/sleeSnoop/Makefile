###############################################################################
#
# Makefile for sleeSnoop (Standalone)
#
###############################################################################

SUBSYSTEM=sleeSnoop

# Standalone version only needs standard C++ and system libs
LIBS=-lpthread

# Source files
SRCS=sleeSnoop.cc
OBJS=$(SRCS:.cc=.o)

CXXFLAGS += -Wall -O2 -I. -I$(NCC_SDK_HOME)/include

$(SUBSYSTEM): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(SUBSYSTEM)
