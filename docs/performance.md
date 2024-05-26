## Performance

CPU: M2

### Nginx no access log

```bash
wrk 'http://127.0.0.1:9080/' --latency

Running 10s test @ http://127.0.0.1:9080/
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   393.55us    2.39ms  32.81ms   97.72%
    Req/Sec    72.68k     5.98k   86.25k    87.13%
  Latency Distribution
     50%   65.00us
     75%   71.00us
     90%   78.00us
     99%   14.87ms
  1460643 requests in 10.10s, 208.95MB read
Requests/sec: 144598.99
Transfer/sec:     20.69MB
```


### Pingap no accces log

```bash
wrk 'http://127.0.0.1:6188/ping' --latency

Running 10s test @ http://127.0.0.1:6188/ping
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    66.18us   28.39us   2.30ms   85.24%
    Req/Sec    74.43k     1.75k   76.25k    97.03%
  Latency Distribution
     50%   70.00us
     75%   77.00us
     90%   83.00us
     99%  100.00us
  1495363 requests in 10.10s, 195.37MB read
Requests/sec: 148056.28
Transfer/sec:     19.34MB
```

### Pingap proxy to nginx

```bash
wrk 'http://127.0.0.1:6188/proxy-nginx'  --latency

Running 10s test @ http://127.0.0.1:6188/proxy-nginx
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   206.46us  151.03us   7.28ms   98.62%
    Req/Sec    25.06k     1.16k   29.07k    87.13%
  Latency Distribution
     50%  211.00us
     75%  224.00us
     90%  239.00us
     99%  391.00us
  503591 requests in 10.10s, 72.04MB read
Requests/sec:  49862.65
Transfer/sec:      7.13MB
```

### Pingap static serve 8kb html

```bash
wrk 'http://127.0.0.1:6188/downloads/index.html' --latency

Running 10s test @ http://127.0.0.1:6188/downloads/index.html
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   225.84us   59.47us   1.83ms   78.04%
    Req/Sec    22.17k     1.94k   25.25k    87.13%
  Latency Distribution
     50%  222.00us
     75%  247.00us
     90%  286.00us
     99%  418.00us
  445764 requests in 10.10s, 3.16GB read
Requests/sec:  44134.06
Transfer/sec:    320.01MB
```

### Compression

TODO

### Cache

TODO
