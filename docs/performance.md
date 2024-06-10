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

Threads: 1

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

Threads: 2

```bash
wrk 'http://127.0.0.1:6188/proxy-nginx'  --latency

Running 10s test @ http://127.0.0.1:6188/proxy-nginx
 2 threads and 10 connections
 Thread Stats   Avg      Stdev     Max   +/- Stdev
   Latency   161.04us  753.69us  19.29ms   99.23%
   Req/Sec    44.96k     2.73k   48.65k    73.76%
 Latency Distribution
    50%  107.00us
    75%  125.00us
    90%  143.00us
    99%  299.00us
 903504 requests in 10.10s, 129.25MB read
Requests/sec:  89449.37
Transfer/sec:     12.80MB
```

Threads: 3 (test result is bad, there may be something wrong)

```bash
wrk 'http://127.0.0.1:6188/proxy-nginx'  --latency

Running 10s test @ http://127.0.0.1:6188/proxy-nginx
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   111.73us  277.33us  10.84ms   99.54%
    Req/Sec    48.06k     3.35k   74.58k    87.56%
  Latency Distribution
     50%   95.00us
     75%  115.00us
     90%  134.00us
     99%  193.00us
  961184 requests in 10.10s, 137.50MB read
Requests/sec:  95160.18
Transfer/sec:     13.61MB
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

Threads: 1

```bash
wrk -H 'Accept-Encoding: gzip, deflate, br, zstd' 'http://localhost:6118/cache'
Running 10s test @ http://localhost:6118/cache
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   183.82us   62.06us   2.30ms   86.60%
    Req/Sec    27.27k   554.92    28.68k    92.57%
  548062 requests in 10.10s, 2.07GB read
Requests/sec:  54263.03
Transfer/sec:    209.89MB
```

Threads: 2

```bash
wrk -H 'Accept-Encoding: gzip, deflate, br, zstd' 'http://localhost:6118/cache'
Running 10s test @ http://localhost:6118/cache
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    98.40us   47.66us   2.52ms   79.75%
    Req/Sec    50.40k     4.23k   53.03k    91.58%
  1013154 requests in 10.10s, 3.83GB read
Requests/sec: 100318.26
Transfer/sec:    388.01MB
```
