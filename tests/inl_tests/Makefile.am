EXTRA_DIST = \
  config.py iptables.py mysocket.py remote_process.py rpc_client.py \
  subprocess_python25.py __init__.py  log.py process.py \
  replace_file.py rpc_server.py tools.py nobuffer.c

all: libnobuffer.so

libnobuffer.so: nobuffer.c
	gcc -o $@ -shared nobuffer.c $(CFLAGS) -fPIC

clean:
	rm -f libnobuffer.so

