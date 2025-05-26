CXX = clang++
CXXFLAGS = -std=gnu++14 -std=c++20
INCLUDES = -I/opt/homebrew/opt/openssl/include
LDFLAGS = -framework PCSC -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

TARGET = x
SRCDIR = .
SRCFILE = $(SRCDIR)/x.cpp
OUTFILE = $(SRCDIR)/$(TARGET)

all:	$(TARGET)

$(TARGET): $(SRCFILE)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $(OUTFILE) $(LDFLAGS)

clean:
	rm -f $(OUTFILE)

.PHONY: all clean
