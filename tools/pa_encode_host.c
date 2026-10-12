/* Host driver for plugin/pa_encode.c, used by check_pa_encode.py.
 * stdin lines:  in CPU TIME PID TID PRIO | out CPU TIME PID TID STATUS | pc CPU PC
 * writes the PA buffer to argv[1]. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../plugin/pa_encode.h"

int main(int argc, char **argv)
{
	static unsigned char buf[64 << 20];
	PaWriter w;
	char op[8];
	unsigned long long t;
	unsigned int cpu, a, b, c;
	unsigned int n;
	FILE *f;

	if (argc < 2)
		return 2;
	pa_init(&w, buf, sizeof(buf));
	while (scanf("%7s", op) == 1) {
		if (!strcmp(op, "in") && scanf("%u %llu %x %x %u", &cpu, &t, &a, &b, &c) == 5)
			pa_switch_in(&w, (int)cpu, t, a, b, (int)c);
		else if (!strcmp(op, "out") && scanf("%u %llu %x %x %u", &cpu, &t, &a, &b, &c) == 5)
			pa_switch_out(&w, (int)cpu, t, a, b, (int)c);
		else if (!strcmp(op, "pc") && scanf("%u %x", &cpu, &a) == 2)
			pa_pc_sample(&w, (int)cpu, a);
		else
			return 3;
	}
	n = pa_finish(&w);
	f = fopen(argv[1], "wb");
	fwrite(buf, 1, n, f);
	fclose(f);
	fprintf(stderr, "bytes=%u bookmarks=%u samples=%u intervals=%u overflow=%d\n",
	        n, w.bookmarks, w.samples, w.intervals, w.overflow);
	return 0;
}
