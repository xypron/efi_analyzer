# SPDX-License-Identifier: BSD-2-Clause

prefix?=/usr/local

# Reproducable build
CFLAGS = -O2 -ffile-prefix-map=$(shell pwd)=.

# Fortification
CFLAGS += \
	-Wall -Wextra -Werror \
	-fno-omit-frame-pointer \
	-mno-omit-leaf-frame-pointer \
	-fstack-protector-strong \
	-fstack-clash-protection \
	-fcf-protection

all:
	gcc efianalyze.c $(CFLAGS) -o efianalyze

check:
	./efianalyze -h

clean:
	rm -f efianalyze

install:
	mkdir -p $(DESTDIR)$(prefix)/bin/
	cp efianalyze $(DESTDIR)$(prefix)/bin/

uninstall:
	rm -f $(DESTDIR)$(prefix)/bin/efianalyze
