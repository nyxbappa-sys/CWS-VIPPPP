CC = clang
CFLAGS = -O3 -Wall -I./core -pthread -lm -ldl
TARGET = bin/cws
SRCS = cws.c \
       core/memory.c \
       core/security.c \
       core/crypto.c \
       core/network.c \
       core/filesystem.c \
       core/process.c \
       core/threading.c

all: $(TARGET)

$(TARGET): $(SRCS)
	mkdir -p bin
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -rf bin/* build/*

install:
	cp bin/cws $(PREFIX)/bin/
	chmod +x $(PREFIX)/bin/cws
	mkdir -p $(PREFIX)/share/cws/lib
	mkdir -p $(PREFIX)/share/cws/examples
	mkdir -p $(PREFIX)/share/cws/tests
	mkdir -p $(PREFIX)/share/cws/docs
	cp -r lib/* $(PREFIX)/share/cws/lib/
	cp -r examples/* $(PREFIX)/share/cws/examples/
	cp -r tests/* $(PREFIX)/share/cws/tests/
	cp -r docs/* $(PREFIX)/share/cws/docs/

uninstall:
	rm -f $(PREFIX)/bin/cws
	rm -rf $(PREFIX)/share/cws

test:
	./bin/cws run tests/test_lexer.cws
	./bin/cws run tests/test_parser.cws
	./bin/cws run tests/test_compiler.cws
	./bin/cws run tests/test_vm.cws

secure-test:
	./bin/cws run --secure tests/test_secure.cws

debug-test:
	./bin/cws run --debug tests/test_debug.cws

.PHONY: all clean install uninstall test secure-test debug-test
