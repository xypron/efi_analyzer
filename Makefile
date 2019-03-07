# SPDX-License-Identifier: BSD-2-Clause

prefix?=/usr/local

all:
	gcc efianalyze.c -o efianalyze

check:
	./efianalyze -h

clean:
	rm -f efianalyze

install:
	mkdir -p $(DESTDIR)$(prefix)/bin/
	cp efianalyze $(DESTDIR)$(prefix)/bin/
