all:
	gcc -o xdp_stats -g xdp_stats.c -static -I.output .output/libbpf.a -lelf -lz
clean:
	rm xdp_stats
