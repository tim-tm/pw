CC=gcc
CFLAGS=-Wall -Wextra -pedantic -std=c11 -g -ggdb2
DEFINES=
INCLUDES=
LIBS=
MAKEFLAGS=-j$(shell nproc)

SRCDIR=src
BUILDDIR=build

SRC=$(wildcard $(SRCDIR)/*.c)
OBJ=$(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SRC))

BINARYNAME=pw
BINARY=$(BUILDDIR)/$(BINARYNAME)

.PHONY: all setup clean destroy

all: $(BINARY)

$(BINARY): $(BUILDDIR)/$(OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJ) -o $(BINARY) $(LIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -c $< -o $@

setup:
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BINARY)
	rm -rf $(OBJ)

destroy:
	rm -rf $(BUILDDIR)
