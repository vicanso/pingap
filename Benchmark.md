# Benchmark

CPU: M4 Pro

## Nginx

```bash
wrk 'http://127.0.0.1:6200/ping' --latency

Running 10s test @ http://127.0.0.1:6200/ping
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    54.01us   81.22us   3.82ms   99.65%
    Req/Sec    94.87k     7.42k  103.28k    68.32%
  Latency Distribution
     50%   49.00us
     75%   56.00us
     90%   64.00us
     99%   84.00us
  1905832 requests in 10.10s, 272.62MB read
Requests/sec: 188702.55
Transfer/sec:     26.99MB
```

## Pingap

```bash
wrk 'http://127.0.0.1:6100/ping' --latency

Running 10s test @ http://127.0.0.1:6100/ping
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    59.87us   20.27us   1.00ms   81.00%
    Req/Sec    82.12k     3.04k   85.77k    90.59%
  Latency Distribution
     50%   63.00us
     75%   69.00us
     90%   76.00us
     99%   97.00us
  1650275 requests in 10.10s, 215.61MB read
Requests/sec: 163396.17
Transfer/sec:     21.35MB
```


## Pingap --> Nginx

```bash
wrk 'http://127.0.0.1:6101/ping' --latency

Running 10s test @ http://127.0.0.1:6101/ping
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   158.72us   75.33us   4.02ms   97.93%
    Req/Sec    31.85k     1.28k   33.36k    92.57%
  Latency Distribution
     50%  163.00us
     75%  178.00us
     90%  193.00us
     99%  233.00us
  639993 requests in 10.10s, 91.55MB read
Requests/sec:  63368.81
Transfer/sec:      9.06MB
```
