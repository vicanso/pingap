# web socket

WebSocket服务：`wss://ws.postman-echo.com/raw`，使用postman测试


```bash
pingap -c ~/github/pingap/examples/web-socket --admin=127.0.0.1:3018 --autoreload
```


## 配置简述

- `wssUpstream`: WebSocket服务，使用`dns`发现，`ipv4_only`为`true`，`sni`为`ws.postman-echo.com`（wss需要设置sni），`update_frequency`为`30s`，整体的配置与普通的https上游服务一致
- `wssLocation`: 单一提供给websocket，因此location中只配置对应的upstream即可，其它配置可按需增加

完成配置之后，在`postman`中测试`ws://127.0.0.1:6118/raw`地址即可。