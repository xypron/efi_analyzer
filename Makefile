all:
	gcc main.c -o efianalyze

check:
	./efianalyze -h

clean:
	rm -f efianalyze

install:
	mkdir -p $(DESTDIR)/usr/local/bin/
	cp efianalyze $(DESTDIR)/usr/local/bin/
