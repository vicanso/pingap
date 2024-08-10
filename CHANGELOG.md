# Changelog

## [0.7.0](https://github.com/vicanso/pingap/compare/v0.6.2..0.7.0) - 2024-08-10

### ⛰️  Features

- Support get arguments from env - ([33ed2a8](https://github.com/vicanso/pingap/commit/33ed2a88091d4ac3e0ae3faa1d443e9c3c992b58))
- Support opentelemetry ([#20](https://github.com/orhun/git-cliff/issues/20)) - ([d50596c](https://github.com/vicanso/pingap/commit/d50596c5882ad91744dd19eba69232fc142bb438))
- Add docker-compose template config, #19 - ([534c0b5](https://github.com/vicanso/pingap/commit/534c0b53b93e81eaa8aaeff471b633113076df9c))
- Support backend health observe handler - ([5f5892b](https://github.com/vicanso/pingap/commit/5f5892baa862bb02476f9f8d302372ec885871e0))
- Support different backends webhook event - ([bccc695](https://github.com/vicanso/pingap/commit/bccc6958232b7d211a0d17c3aeb7e035622c3bf4))
- Add rustc version to basic info - ([ad21162](https://github.com/vicanso/pingap/commit/ad21162b3825b1ba298bd4cba8aff68e4634ece3))
- Support delay for mock response plugin - ([1f368c3](https://github.com/vicanso/pingap/commit/1f368c3f3f63595013a8bbd3b0451136c5ad2e50))

### 🐛 Bug Fixes

- Fixed dns discovery not update backend health status - ([f6f8b0a](https://github.com/vicanso/pingap/commit/f6f8b0a998ae99e4fedbfd2a665fe0951ee8bf0c))

### 🚜 Refactor

- Update pingora version - ([aa8c96e](https://github.com/vicanso/pingap/commit/aa8c96e322be3f782f556bf300a82ad9e4a0bec7))
- Support more params for opentelemetry - ([66694b0](https://github.com/vicanso/pingap/commit/66694b01374d19b1428bf0d34aa29dce574b769c))
- Adjust auto reload and restart handler - ([b8f8799](https://github.com/vicanso/pingap/commit/b8f87997d96fc0ad4f6a70709e4e054d59302832))
- Adjust conf parameter get from env - ([778d944](https://github.com/vicanso/pingap/commit/778d94487ee939a3a5d66b50e659f3f8ec9989b9))
- Adjust open telemetry for each server service, not global - ([e022cf3](https://github.com/vicanso/pingap/commit/e022cf3c07791d453e3b6fc3882a7545e54b9d30))
- Adjust http status code of error - ([db351fb](https://github.com/vicanso/pingap/commit/db351fb6dfe334f8bbeff2beebe640de854a6e90))
- Adjust file cache stats - ([462f46f](https://github.com/vicanso/pingap/commit/462f46f99b880556c67e15df6a7cacb727f520de))
- Set ip strategy for better performance - ([1e701c2](https://github.com/vicanso/pingap/commit/1e701c2cc00fba07090da36db03c88e9c5386324))
- Adjust dns timeout for lookup ip - ([9b9a6b8](https://github.com/vicanso/pingap/commit/9b9a6b883c765dc978938e1e4df76ca1ad825f2c))
- Adjust configuration diff handler - ([3f283f4](https://github.com/vicanso/pingap/commit/3f283f430dfeae7b9d6d3b44b6a09f70ae7b3285))
- Adjust error message - ([d7a2d3c](https://github.com/vicanso/pingap/commit/d7a2d3cba0f530a3550bef994f40d3c409b927dd))
- Adjust upstream and location update handler - ([1ea5e92](https://github.com/vicanso/pingap/commit/1ea5e92e8755ae5a433f22a80da0c411f1e6a4d2))
- Adjust acme and rcgen - ([8a8b12d](https://github.com/vicanso/pingap/commit/8a8b12da9390ea2e5eefb63ef4f5116cd6090924))
- Adjust update and health check frequency - ([25dbc7b](https://github.com/vicanso/pingap/commit/25dbc7bb98732ee0143f968cda6ac4f42d28a211))
- Adjust http cache storage trait - ([aafde95](https://github.com/vicanso/pingap/commit/aafde955b39f20dbef099fd93f374ee810b7afd0))
- Adjust webhook notification - ([8ec4fcc](https://github.com/vicanso/pingap/commit/8ec4fccbf34b4cba874b99f5a0e07d8f421ab17a))
- Adjust prometheus timing - ([de46260](https://github.com/vicanso/pingap/commit/de46260e1cadfd714005e2e6b8f55228af1133f0))

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

