# Benchmark

## Nginx

```bash
wrk 'http://127.0.0.1:6200/ping' --latency

Running 10s test @ http://127.0.0.1:6200/ping
 2 threads and 10 connections
 Thread Stats   Avg      Stdev     Max   +/- Stdev
   Latency   140.44us  705.01us  16.07ms   98.80%
   Req/Sec    65.13k     2.92k   72.33k    85.15%
 Latency Distribution
    50%   73.00us
    75%   80.00us
    90%   86.00us
    99%    1.97ms
 1309147 requests in 10.10s, 187.27MB read
Requests/sec: 129597.70
Transfer/sec:     18.54MB
```

## Pingap

```bash
wrk 'http://127.0.0.1:6100/ping' --latency

Running 10s test @ http://127.0.0.1:6100/ping
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    83.14us   25.54us   1.18ms   82.07%
    Req/Sec    59.22k     1.13k   62.14k    94.06%
  Latency Distribution
     50%   89.00us
     75%   96.00us
     90%  103.00us
     99%  122.00us
  1190455 requests in 10.10s, 155.54MB read
Requests/sec: 117876.05
Transfer/sec:     15.40MB
```


## Pingap --> Nginx

```bash
wrk 'http://127.0.0.1:6101/ping' --latency

Running 10s test @ http://127.0.0.1:6101/ping
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   221.18us  394.85us  13.41ms   99.53%
    Req/Sec    24.98k     0.90k   26.78k    89.60%
  Latency Distribution
     50%  212.00us
     75%  226.00us
     90%  240.00us
     99%  305.00us
  502003 requests in 10.10s, 71.81MB read
Requests/sec:  49706.13
Transfer/sec:      7.11MB
```
