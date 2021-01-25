programs = sort
CFLAGS = -O0 -g # -Wall

all: $(programs)

clean:
	rm -f $(programs)

$(programs): %: %.c
	gcc $(CFLAGS) $< -o $@ -lm
