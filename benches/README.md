## CPU

```
Architecture:     x86_64 (架构)
CPU op-mode(s):   32-bit, 64-bit
Byte Order:       Little Endian
CPU(s):           16       (总逻辑核心数/线程数)
On-line CPU(s) list: 0-15
Thread(s) per core: 2        (每个物理核心的线程数，2代表开启了超线程)
Model name:       Intel(R) Core(TM) i5-13400 @ 4.60GHz (CPU型号)
L3 cache:         20 MiB   (L3缓存大小，对性能影响显著)
```


## Adjust linux setting

```bash
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
```

## Pingap

```bash
pingap -d -c ~/tmp/pingap.toml --log=~/tmp/pingap.log
```

### Pingap direct response
```bash

wrk --latency http://127.0.0.1:8090/api/test
Running 10s test @ http://127.0.0.1:8090/api/test
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    64.95us   19.83us 497.00us   86.45%
    Req/Sec    76.75k     1.39k   78.71k    81.68%
  Latency Distribution
     50%   70.00us
     75%   73.00us
     90%   77.00us
     99%   84.00us
  1542915 requests in 10.10s, 410.53MB read
Requests/sec: 152775.01
Transfer/sec:     40.65MB
```

## Pingap proxy to nginx

```bash
wrk --latency http://127.0.0.1:8090/api/json
Running 10s test @ http://127.0.0.1:8090/api/json
  2 threads and 10 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   166.06us   90.85us   4.85ms   97.73%
    Req/Sec    30.57k     1.16k   32.51k    53.96%
  Latency Distribution
     50%  178.00us
     75%  188.00us
     90%  195.00us
     99%  204.00us
  614080 requests in 10.10s, 195.60MB read
Requests/sec:  60802.82
Transfer/sec:     19.37MB
```