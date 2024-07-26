# Changelog

## [0.6.2](https://github.com/vicanso/pingap/compare/v0.6.1..0.6.2) - 2024-07-26

### ⛰️  Features

- Support delay processing for plugin auth fail - ([a272b1c](https://github.com/vicanso/pingap/commit/a272b1c252d6fdc45db10d7b0251f35856db3fc9))
- Add cache reading and writing for prometheus metrics - ([171d3f2](https://github.com/vicanso/pingap/commit/171d3f2181e7c9236c2e9047f9f693a695368099))
- Support get processing count of file cache - ([e9392a1](https://github.com/vicanso/pingap/commit/e9392a1b759fa2a8c1d41a72dbc08ee477cd6235))
- Set upstream processing count to prometheus metrics - ([38503fb](https://github.com/vicanso/pingap/commit/38503fbcf0c04b924253fb7e9912bb023d1b9a54))
- Set upstream connected count to prometheus metrics - ([8fe5d37](https://github.com/vicanso/pingap/commit/8fe5d376abcdbb9f2c0cb1016e47ec4784914fbd))

### 🐛 Bug Fixes

- Fix wrong chain certificate - ([8448010](https://github.com/vicanso/pingap/commit/8448010a578a88395a63a82639e086922213935b))

### 🚜 Refactor

- Adjust dns resolve timeout - ([7aae593](https://github.com/vicanso/pingap/commit/7aae5934052b8f022d9103cf98cc66bcbd50508b))
- Adjust configuration hot reload - ([2b79357](https://github.com/vicanso/pingap/commit/2b793570dbf78803ae1c923c42e7df040d7337b2))
- Add error type for error template - ([4f18011](https://github.com/vicanso/pingap/commit/4f18011e7a81e723aba17e7e9720cbbb3745e021))
- Add more message for diff config - ([c4ea78b](https://github.com/vicanso/pingap/commit/c4ea78b739573063bc24163be7cc6c79663f8e5a))

### 📚 Documentation

- Update document - ([80a82e3](https://github.com/vicanso/pingap/commit/80a82e3e5e6a5848face114dfc741c9899a172df))
- Update changelog - ([8ebdb8f](https://github.com/vicanso/pingap/commit/8ebdb8f6ea1880b96870515f21fdbfa38001b35f))

### 🧪 Testing

- Add test for prometheus - ([59336d9](https://github.com/vicanso/pingap/commit/59336d959151ce591acc5b2bc6be1569a81861ed))

### ⚙️ Miscellaneous Tasks

- Version 0.6.2 - ([e3d0e20](https://github.com/vicanso/pingap/commit/e3d0e2063293ecbc82ca7db5c566dcb0e0d35073))

## [0.6.1](https://github.com/vicanso/pingap/compare/v0.6.0..0.6.1) - 2024-07-20

### ⛰️  Features

- Support buffer file logger - ([9bb88e8](https://github.com/vicanso/pingap/commit/9bb88e85dcbf8d19c8b5fd0c855a0bf6ffa394e7))
- Support prometheus push - ([774a350](https://github.com/vicanso/pingap/commit/774a350b4b8e3ffcd957f90369252b899d010be5))
- Add `upstream_tls_handshake_time` to prometheus metrics - ([490221a](https://github.com/vicanso/pingap/commit/490221a339abd17357a4c0847efa31e9b2d60fb6))
- Support prometheus metrics - ([2b059ea](https://github.com/vicanso/pingap/commit/2b059ea5c42d8645fe6d15f7dc76a9fac1fa8b1f))

### 🐛 Bug Fixes

- Fix diff result of hot reload - ([0e97a17](https://github.com/vicanso/pingap/commit/0e97a1751e5f05fa1fe06f473f2804bbb795ee28))

### 🚜 Refactor

- Adjust http cache Vec<u8> to Bytes - ([d0f91c2](https://github.com/vicanso/pingap/commit/d0f91c2c429a70d86d2da3c060c2fe542685805e))
- Add log for service task - ([d5266b1](https://github.com/vicanso/pingap/commit/d5266b1d3dc049b6d51001f128a49b98a172ac1e))
- Adjust weight of cache - ([ab38612](https://github.com/vicanso/pingap/commit/ab386124d10ab299a85370bc94f47c297ef6b72d))

### 📚 Documentation

- Adjust documents - ([7f5868a](https://github.com/vicanso/pingap/commit/7f5868aa3f667be36591b80e554f4e7ebb2ccb5d))

### ⚙️ Miscellaneous Tasks

- Version 0.6.1 - ([55287d9](https://github.com/vicanso/pingap/commit/55287d9e5fbe68053fc8100ebaf29c855925b8d1))
- Adjust meta size - ([d0c8e10](https://github.com/vicanso/pingap/commit/d0c8e10fc34da363252de4d01fc7a80aaea4b4d0))

