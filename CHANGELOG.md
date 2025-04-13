# Changelog

## [0.10.6](https://github.com/vicanso/pingap/compare/v0.10.5..0.10.6) - 2025-04-13

### ⛰️  Features

- Add upstream status notification - ([fdd4354](https://github.com/vicanso/pingap/commit/fdd43546b363433d4a3c875188c0e0f61312914b))

### 🐛 Bug Fixes

- Fix crossbeam channel, #109 - ([45d4758](https://github.com/vicanso/pingap/commit/45d4758b83d7d0cf65205d9fe1cc88aa28929795))
- Remove unused module - ([8ba1d2a](https://github.com/vicanso/pingap/commit/8ba1d2a9cdf2852955acef693bc891454424f443))
- Fix lint - ([8c8e772](https://github.com/vicanso/pingap/commit/8c8e772472f0cd34c85d67726d99b4b9c78696d2))
- Temporarily fix sfv - ([c345985](https://github.com/vicanso/pingap/commit/c345985110b8bf53c27217b22ef72d647fe2713a))
- Fix lint of rust 1.86.0 - ([d8bb02b](https://github.com/vicanso/pingap/commit/d8bb02b6f1935744426a9b75fd4f257e5ba6f833))
- Remove syslog of windows target - ([6a58fcc](https://github.com/vicanso/pingap/commit/6a58fcc19e6433778697f4701b33a20faafdacc3))
- Fix async send notification for rust 1.81.0 - ([49e210e](https://github.com/vicanso/pingap/commit/49e210ec4a21506f6c6d356bf5ff0a58c6dad686))

### 🚜 Refactor

- Enhance dns service discovery handling when resolved fail - ([10c449b](https://github.com/vicanso/pingap/commit/10c449b0eea0713fd2f934b618a4c4ca914d09c2))
- Adjust get upstream healthy status - ([51697ba](https://github.com/vicanso/pingap/commit/51697baf69a081a9504202165345c6fe648d7024))
- Add text color for upstream status - ([614fa44](https://github.com/vicanso/pingap/commit/614fa44ff48b7f9ef921fc9ac570ac4ab2b9d872))
- Update tailwind and shadcn - ([20d8b7a](https://github.com/vicanso/pingap/commit/20d8b7a12f002833f6cafd4643cfe790f8778014))
- Adjust webhook notification sender - ([260c861](https://github.com/vicanso/pingap/commit/260c86126e99bfa3bba1b590b9e1b58702ba6dc1))
- Adjust webhook sender - ([7b634e6](https://github.com/vicanso/pingap/commit/7b634e6dd8785a50fd54ef3cdf4ee3dc44fad47f))

### ⚙️ Miscellaneous Tasks

- Update shadcn ui - ([f13f5b2](https://github.com/vicanso/pingap/commit/f13f5b284068018293b474926cd4d87acfe588c7))
- Update modules, #106 - ([6aac395](https://github.com/vicanso/pingap/commit/6aac39590dfff78e88151e555548b33bab1cb405))
- Remove unused components - ([4b02929](https://github.com/vicanso/pingap/commit/4b02929ad2578ce4d97948061662bf1df795fb57))
- Update github workflow - ([6581459](https://github.com/vicanso/pingap/commit/6581459966e6ed7c3b2b8e5ee7eefd1e0ee7b974))
- Add windows build script - ([58117fa](https://github.com/vicanso/pingap/commit/58117fa64d0358cedd7ea93549fe2f2067d5c372))
- Use baco instead of cargo watch - ([8614e25](https://github.com/vicanso/pingap/commit/8614e25b9fb9f83e13032a8e7a38fd8bc40170be))

## [0.10.5](https://github.com/vicanso/pingap/compare/v0.10.4..0.10.5) - 2025-03-23

### ⛰️  Features

- Path rewrite and upstream support variables, #104 - ([3786735](https://github.com/vicanso/pingap/commit/37867358b7569037055ec71ddc582414d2b63937))
- Add syslog writer for logger - ([113d758](https://github.com/vicanso/pingap/commit/113d758889640182e5d1d325f079d10f1fabd8d6))
- Add base64 encode and decode function - ([3d27056](https://github.com/vicanso/pingap/commit/3d27056573e1067c4aecaef614a7c58720651aa7))
- Add cache span attributes of open telemetry - ([103d6c8](https://github.com/vicanso/pingap/commit/103d6c8dcfc57c2d50a84412715d3858224f4bc0))
- Open telemetry support compression - ([36ea569](https://github.com/vicanso/pingap/commit/36ea56943e036c3c7bc5ebc31997193fbd57b0a8))
- Custom buffer days for acme renew or certificate validate - ([dde9738](https://github.com/vicanso/pingap/commit/dde9738bc8083b8e3f50097d72a6e8351f80aec0))

### 🐛 Bug Fixes

- Fix default value of upstream input - ([88fefe1](https://github.com/vicanso/pingap/commit/88fefe17b707a053564941fe337de6f24a081baa))

### 🚜 Refactor

- Adjust location weight calculation method - ([6eb396c](https://github.com/vicanso/pingap/commit/6eb396c5c0eaa1cde950fc7834c7c42af43b0209))
- Adjust sidebar navigation - ([08cc8d0](https://github.com/vicanso/pingap/commit/08cc8d045e35c28609bcaa4e3f188d2985fb986b))
- Adjust sentry core version - ([61182c4](https://github.com/vicanso/pingap/commit/61182c4cd0a437c25141aa7c2f9f6bab06edfde4))
- Remove default parameters for docker run cmd, #103 - ([654ee51](https://github.com/vicanso/pingap/commit/654ee5106c5824658a805ccae05a241ccf0a2fea))
- Update pingora version - ([b3dc30f](https://github.com/vicanso/pingap/commit/b3dc30f742d7ae409cccf1d18a1f134623c9908a))
- Use mimalloc for better performance of musl - ([45cd230](https://github.com/vicanso/pingap/commit/45cd2308a77456cfd8ca1fcb75de93235271ae42))
- Add sub title of location - ([9936ee6](https://github.com/vicanso/pingap/commit/9936ee6606c5da74bba341a265a86bbaefa5f009))
- Adjust access log format - ([85f96f9](https://github.com/vicanso/pingap/commit/85f96f99ae4d87728f180ad931d8bc20fd833895))

### 📚 Documentation

- Add web socket example - ([8a8fd7d](https://github.com/vicanso/pingap/commit/8a8fd7d59ad6197b210c9ef114b942d4c3511e61))

### 🧪 Testing

- Fix test of location weight - ([5c30952](https://github.com/vicanso/pingap/commit/5c309525cda71e73f981f24511a27f4285ee0878))

## [0.10.4](https://github.com/vicanso/pingap/compare/v0.10.3..0.10.4) - 2025-03-02

### ⛰️  Features

- Record the plugin's processing time in context and server timing header - ([17234d7](https://github.com/vicanso/pingap/commit/17234d791d343a6422db9b378ba09ed9eb49c4b8))
- Add weight for rate limit slot - ([177ad52](https://github.com/vicanso/pingap/commit/177ad523ec85663424227171c74ff2a3872f79e1))
- Support http server timing - ([be5fd74](https://github.com/vicanso/pingap/commit/be5fd7426a281b179f7b38e5a970a6f656e10d23))
- Generate server timing from context - ([163482e](https://github.com/vicanso/pingap/commit/163482eec9f6ec25aabdc9e39386b77adcb82ba9))
- Get upstream healthy status - ([3ffe796](https://github.com/vicanso/pingap/commit/3ffe7968ca539ac327f4003121a7b3abe6d72a87))

### 🐛 Bug Fixes

- Fix clippy error - ([4cb7c08](https://github.com/vicanso/pingap/commit/4cb7c0875255abe579b1bb5933071ab97c2f7e94))
- Fix test for server timing - ([b695018](https://github.com/vicanso/pingap/commit/b69501811ff814399659a5adf99c09c0867b93f2))
- Fix spelling check - ([30c0158](https://github.com/vicanso/pingap/commit/30c0158389868095a452cea209344fa187abe57d))
- Fix lint - ([c8ea679](https://github.com/vicanso/pingap/commit/c8ea679452bf8eac246338d7bdf38bfba8da8859))
- Fix sub filter loop modify response body if the data from cache - ([ce7e0ce](https://github.com/vicanso/pingap/commit/ce7e0ce852c0f0855ef0ee9d288779b9285f2b07))
- Fix regex capture - ([8c77612](https://github.com/vicanso/pingap/commit/8c77612f617571493bb600c234ace514c2998c03))
- Fix scheduled clearing of expired data - ([9acebe6](https://github.com/vicanso/pingap/commit/9acebe639d70b972c4af4793713e321277d76c9f))

### 🚜 Refactor

- Sort summary description by name - ([eac4d50](https://github.com/vicanso/pingap/commit/eac4d50580091ab52d60151508e09272da073505))
- Adjust plugin trait to add an "executed" flag that indicates whether the plugin was executed or not - ([1c1264b](https://github.com/vicanso/pingap/commit/1c1264b18635753b7f6a92d7b9eebaf1b2109046))
- Add inline to some plugin functions - ([b75e797](https://github.com/vicanso/pingap/commit/b75e797ebb4686b7b0ea04eac878c3ccce3b9565))
- Lazy formatting for timestamp - ([06386ef](https://github.com/vicanso/pingap/commit/06386ef59346020f4c025b1af00f1fddb9ad9fea))
- Improve the performance of access log format - ([295a20b](https://github.com/vicanso/pingap/commit/295a20bceef4f151cb36cbb7955b00e94f3da6c8))
- Remove not include value of server timing - ([c66c618](https://github.com/vicanso/pingap/commit/c66c618ff6263fc73c890ea8e4d0da5b24eed7c1))
- Support more path options for pid file to facilitate non-root user execution - ([6d70d48](https://github.com/vicanso/pingap/commit/6d70d4804d8a1e6a0168f33fa3425681f6829a8f))
- Adjust open telemetry service name - ([032f544](https://github.com/vicanso/pingap/commit/032f54436435c0d3fbed0566409241d3056c8999))
- Adjust dependencies of open telemetry - ([d807e11](https://github.com/vicanso/pingap/commit/d807e11ae5cc2199c39c0faf46bd5923897717ff))

### 🧪 Testing

- Fix test of generate server timing - ([b205ac0](https://github.com/vicanso/pingap/commit/b205ac0f30c735c729196d374a9cd1c5d01710a9))
- Fix test of server config - ([c1534d3](https://github.com/vicanso/pingap/commit/c1534d3705571555a30e5c5aab51d4f4f9aa17a5))

### ⚙️ Miscellaneous Tasks

- Update rust version to 1.84.0 - ([f8d789c](https://github.com/vicanso/pingap/commit/f8d789c53e2578c4599615a24df48965ac401f83))
- Update machete version for github workflow - ([9cc0495](https://github.com/vicanso/pingap/commit/9cc04957bf00d304b7b7a24fadd890feabe2f262))
- Use edition 2024 - ([609878f](https://github.com/vicanso/pingap/commit/609878ffd1a10aaff9db7bc6c5df44650af958b6))
- Update github workflow - ([862814b](https://github.com/vicanso/pingap/commit/862814b01e639e336833fcd7cc367f9c77a36abc))
- Update msrv - ([5df07a6](https://github.com/vicanso/pingap/commit/5df07a6fb6a23db40d3d11aadf47457514fa422e))
- Update github workflow for rust 1.74.0 - ([c1b9d7a](https://github.com/vicanso/pingap/commit/c1b9d7a96983f2736761517373b64a526c6e176d))
- Support aarch64 full feature release - ([89a358f](https://github.com/vicanso/pingap/commit/89a358f7d135364b759e3daa1afddf28ba580ec0))

## [0.10.1](https://github.com/vicanso/pingap/compare/v0.10.1..0.10.1) - 2025-02-22

### 🚜 Refactor

- Update pingora version - ([4e210a0](https://github.com/vicanso/pingap/commit/4e210a016255181c916d0899402604f547772507))
- Adjust log level selector - ([274f579](https://github.com/vicanso/pingap/commit/274f57905eb448a538ec5ec142d2c2128dbc4c24))
- Set x-trace-id and x-span-id response header - ([3549dd0](https://github.com/vicanso/pingap/commit/3549dd0a3f0ec54b2a8ee79c250e005dc896f27a))
- Update dependencies - ([2c0b8e7](https://github.com/vicanso/pingap/commit/2c0b8e732876e52bb25c5d0e789b87a55ea1132d))
- Use ceil for rate limit plugin - ([bc816c0](https://github.com/vicanso/pingap/commit/bc816c0e2daadaab97014ed70a924cae1fb7d872))
- Downgrade tailwindcss  to v3 - ([a2f70dc](https://github.com/vicanso/pingap/commit/a2f70dcf1e3e9c2b2f3bb9e429a1f6a48d98e98d))
- Adjust log of pingap cache - ([4f5d2cb](https://github.com/vicanso/pingap/commit/4f5d2cba0cc123758e32ec6311334166e77f673f))
- Add log of admin plugin config - ([04526b2](https://github.com/vicanso/pingap/commit/04526b264738b7379c6583bde4f981d6b2dbeb32))
- Adjust background service name - ([22d1bc9](https://github.com/vicanso/pingap/commit/22d1bc9cfe68b54ac599e4f04707fbad470c355f))

### 📚 Documentation

- Update readme - ([c362e54](https://github.com/vicanso/pingap/commit/c362e54ba0e1e73d8b0cf4ca76b1a152b400f425))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([cd129f3](https://github.com/vicanso/pingap/commit/cd129f3ee89c0667ff1946254ab5315aaf0bfa92))

## [0.10.0](https://github.com/vicanso/pingap/compare/v0.9.11..0.10.0) - 2025-02-15

### ⛰️  Features

- Support set `listener_tasks_per_fd` for server configuration - ([5a24214](https://github.com/vicanso/pingap/commit/5a24214849feb6b08c0dd320eda7a4159ae562ce))
- Support plugin factory - ([2c3c2ff](https://github.com/vicanso/pingap/commit/2c3c2ffae27ffbd672fc61b4f00f5a73cab759b4))
- Support upstream connection time for state - ([e88981d](https://github.com/vicanso/pingap/commit/e88981d1fc6405822f8a1154e2cbb42631202257))

### 🐛 Bug Fixes

- Fix hickory dns failure to verify self-signed, #91 - ([99fb7bc](https://github.com/vicanso/pingap/commit/99fb7bc21d5ae52bf1442ad034dbaad874b6f52a))
- Fix test - ([f5331b1](https://github.com/vicanso/pingap/commit/f5331b16bfc76528d8f125eb7fa6f20c256bca3f))
- Fix format - ([56d0149](https://github.com/vicanso/pingap/commit/56d0149356821aa473c0eea5309bf5df5454350f))
- Fix openssl `ssl::select_next_proto use after free`, #89 - ([938b731](https://github.com/vicanso/pingap/commit/938b731d73b12d692653b4e901ddbdc44feffa13))

### 🚜 Refactor

- Adjust cache, config, discovery, health, location and upsgream - ([c5cce43](https://github.com/vicanso/pingap/commit/c5cce43ce8288b8f22fce550b9de0b3777366a0c))
- Adjust pingap cache - ([a5fa802](https://github.com/vicanso/pingap/commit/a5fa802a35e2de6ff3535d10fc25c7499c63dd78))
- Adjust pingap certificate - ([09770e3](https://github.com/vicanso/pingap/commit/09770e3d1e59f3cc3e9009416a83eb1cf75e3398))
- Merge limit and service module into core module - ([60a7f34](https://github.com/vicanso/pingap/commit/60a7f3428bc5c736fb21b77c945996fa5c7ef6db))
- Optimize cache backend initialization - ([9b9a80f](https://github.com/vicanso/pingap/commit/9b9a80f89dd8de7b56228630dc67817cba2f8553))
- Merge the state module with the core module - ([459ba7d](https://github.com/vicanso/pingap/commit/459ba7db0e6a8ea6bbe297fa9ab9c67f25e09c39))
- Adjust pingap core - ([ce2c262](https://github.com/vicanso/pingap/commit/ce2c262baf216b4a761bd035357f0cdfc5b42488))
- Remove state's dependency on util - ([a788778](https://github.com/vicanso/pingap/commit/a788778d7e6004c612916f56659d887683464f41))
- Adjust location and upstream of ctx - ([fdaf7b0](https://github.com/vicanso/pingap/commit/fdaf7b00aeaa46e5bf37c37b1b99302e8be78bae))
- Adjust pingap workspace member - ([ebe820f](https://github.com/vicanso/pingap/commit/ebe820f70d5d2b498cce1863c9a7f9f9d8362731))
- Adjust pingap workspace member - ([beecaeb](https://github.com/vicanso/pingap/commit/beecaeb075654b323e0c7832a7bf3857332f420c))
- Adjust pingap workspace member - ([d372af3](https://github.com/vicanso/pingap/commit/d372af35e08aee01a990b48cd33341e26d66d0dc))
- Adjust pingap workspace member - ([d31293b](https://github.com/vicanso/pingap/commit/d31293bf6bb93661e61a5c7d573e8411203f3135))
- Adjust pingap workspace member - ([b7e1a56](https://github.com/vicanso/pingap/commit/b7e1a5611ad39e85a94d9a1f15d0f6b31a5ec791))
- Adjust pingap workspace member - ([cf41202](https://github.com/vicanso/pingap/commit/cf412029729e5eef35b34cd88a6b10661ffaef20))
- Adjust pingap workspace member - ([72f24ca](https://github.com/vicanso/pingap/commit/72f24ca47642ead8cbb6ba3a3d1867cb91c54e7c))
- Adjust pingap workspace member - ([6f6fb10](https://github.com/vicanso/pingap/commit/6f6fb10ccb93ee30751652d94cfcbafc0c9510a4))
- Adjust pingap workspace member - ([254432a](https://github.com/vicanso/pingap/commit/254432a55566a4a7cfa670e6834325499bc4523f))
- Adjust pingap workspace member - ([95ba42d](https://github.com/vicanso/pingap/commit/95ba42d6ccb20c331ebe872390eff106bf1400c4))
- Adjust pingap workspace member - ([670c9e1](https://github.com/vicanso/pingap/commit/670c9e1622a85ffa15738fa66945251fda2d3917))
- Adjust pingap-util as pingap workspace member - ([2553717](https://github.com/vicanso/pingap/commit/2553717f8fd1239501cf733bf7c46c7d202a9cb2))
- Adjust proxy handle function - ([226d322](https://github.com/vicanso/pingap/commit/226d32258d1b18e669242fdb9b8986e77339330c))
- Add delay for observer watch fail - ([be88a90](https://github.com/vicanso/pingap/commit/be88a906b245d212534575bc245320d28833d367))

### 📚 Documentation

- Update modules - ([f7894ea](https://github.com/vicanso/pingap/commit/f7894eae68fe71972ba9d0e374f00ad354c74125))
- Update module dependency graph - ([d6631e7](https://github.com/vicanso/pingap/commit/d6631e72a2bbe6fbeb585ecc45e7983898c97973))

### 🧪 Testing

- Remove unuse dependencies - ([7ec491a](https://github.com/vicanso/pingap/commit/7ec491aa3df56281ed3b6d10259e23218fe46a06))
- Add more test for core - ([7eba578](https://github.com/vicanso/pingap/commit/7eba5788b272dfa2b0fb9fcab7996bbd0af5a3dd))
- Add test for pingap util - ([71c316f](https://github.com/vicanso/pingap/commit/71c316fcc1dbea18dfe041af0f748f019fdeb0a4))

### ⚙️ Miscellaneous Tasks

- Set build args to github output - ([eb628f2](https://github.com/vicanso/pingap/commit/eb628f2509105586ece5eb910a2d1ae36319cc47))
- Adjust docker image tag - ([caa392d](https://github.com/vicanso/pingap/commit/caa392d2022259eb6f3429e686429bd0d5bf9a68))
- Update github action for building images with different feature - ([e9826a6](https://github.com/vicanso/pingap/commit/e9826a6867327c404c475370f61ff8a7976d7b82))
- Update dependencies - ([13a8665](https://github.com/vicanso/pingap/commit/13a8665e35b1627a0e793826999fc1e4ef2206ea))
- Support build args for dockerfile - ([22add72](https://github.com/vicanso/pingap/commit/22add72d9df1bf160ac4373d0c341a1955263653))
- Support build args for dockerfile - ([6b8b363](https://github.com/vicanso/pingap/commit/6b8b36357581c1f5303a7535d3e5b444f4ebbfb9))
- Update cargo - ([0611610](https://github.com/vicanso/pingap/commit/0611610bf37ce6e6c2e33b4b262be833b8ebfcd2))

## [0.9.10](https://github.com/vicanso/pingap/compare/v0.9.9..0.9.10) - 2025-02-02

### 🐛 Bug Fixes

- Fix loop renew certificate, #88 - ([3cbdd38](https://github.com/vicanso/pingap/commit/3cbdd38191e8f9a7c2f57c3426d1e991dbba8d54))
- Fix disable acme for pingap - ([bc5b506](https://github.com/vicanso/pingap/commit/bc5b5065ab1f1d8b04af0ce0ab4267b19730d010))
- Fix validate empty tls cert and key - ([95ef582](https://github.com/vicanso/pingap/commit/95ef58295885ab89f9acc0ecafe2a8e2abe2481d))
- Fix no native root CA certificates, #85 - ([fbef48b](https://github.com/vicanso/pingap/commit/fbef48bc5f25ce2dbc0e6b78ae9b0d84237b9e93))
- Fix empty certificate parse error - ([5ed9eca](https://github.com/vicanso/pingap/commit/5ed9eca44014e8cb7b2ebc6264342adc52797679))

### 🚜 Refactor

- Add log category for logger - ([64f5cec](https://github.com/vicanso/pingap/commit/64f5cec60a2af411724ff1436bd354fc112506ff))
- Use default port for transparent http/https, #84 - ([2543cd8](https://github.com/vicanso/pingap/commit/2543cd80258980071c4c6b452f9667f9e533f755))
- Add log category for proxy - ([ef53962](https://github.com/vicanso/pingap/commit/ef539622e75235c9ea2578d6358fc9b629026de7))
- Adjust static discovery and add test - ([140f8d2](https://github.com/vicanso/pingap/commit/140f8d20362d368e22056e9f46ccd09d56b26afd))
- Log level allow null - ([28f2cb4](https://github.com/vicanso/pingap/commit/28f2cb4598aceafcefecc920e146027d48d522fd))
- Support setting null as empty string - ([7d82026](https://github.com/vicanso/pingap/commit/7d82026e1b1a1ede2d780eeb336bc670ec63a503))
- Adjust let's encrypt service - ([759a4dc](https://github.com/vicanso/pingap/commit/759a4dc3d33325ba60bae6922c5815965643015d))
- Add log category for cache - ([51048d3](https://github.com/vicanso/pingap/commit/51048d32c11461633b40d30f56baf742c54dd13c))
- Adjust tiny ufo estimated size - ([0c153e9](https://github.com/vicanso/pingap/commit/0c153e9b0ed255146489a9ca3e3eea689bf3b070))
- Adjust let's encrypt - ([f59b204](https://github.com/vicanso/pingap/commit/f59b204a467e8521d71f24d3b89c3744c44c46ee))
- Use ubuntu 20.04 for docker - ([f785e08](https://github.com/vicanso/pingap/commit/f785e08534b119e362b88762c1cd2bc3dab8c51f))
- Some plugin use fixed step - ([64cb9e6](https://github.com/vicanso/pingap/commit/64cb9e6271b17a9aaea68d689590108da30a9855))
- Adjust certificate - ([2092c0c](https://github.com/vicanso/pingap/commit/2092c0c1635e6a21ded685f9d92c84df6967f1d5))

### 📚 Documentation

- Add comments - ([ee93523](https://github.com/vicanso/pingap/commit/ee935231e483070f1a76407529d8583c0793e515))
- Update copyright - ([df8bb50](https://github.com/vicanso/pingap/commit/df8bb50c1f1eaca8b8c2e8c07f8735a6003c2452))
- Update documents - ([82d2b07](https://github.com/vicanso/pingap/commit/82d2b077e96dab0e3fbffdffa745d98c9f48529f))
- Update toml config - ([aab3965](https://github.com/vicanso/pingap/commit/aab3965de6ad134aec788282a2fe28e92fbee2d9))
- Update documents - ([45733d4](https://github.com/vicanso/pingap/commit/45733d4480c4e5292dd8195c6a347bf4f41b2c56))
- Update proxy upstream config, #83 - ([df4f6d1](https://github.com/vicanso/pingap/commit/df4f6d1ed519df7163519a14793b5bc94535819e))

### 🎨 Styling

- Add comments for webhook - ([ac22399](https://github.com/vicanso/pingap/commit/ac22399a84eadf36a7e1406675eb52e22ec18b6a))
- Add comments for state - ([b024e55](https://github.com/vicanso/pingap/commit/b024e556acfc9b18d277078661acf04ac15f3c79))
- Add comments for service - ([53ee207](https://github.com/vicanso/pingap/commit/53ee207e98fd8fb9b60ca53b5a88393680b940fe))
- Add comments for otel - ([4e2e41a](https://github.com/vicanso/pingap/commit/4e2e41af1a3f6555fa47fa8278c37fb9ee21bb6e))

### 🧪 Testing

- Add test for crypto - ([1d614c4](https://github.com/vicanso/pingap/commit/1d614c42478350d4d329062b9a042bfdaabdc42c))
- Add test for certificate - ([8aa1d2b](https://github.com/vicanso/pingap/commit/8aa1d2b8241ffb60c487e64c3782b68e4af15edd))

### ⚙️ Miscellaneous Tasks

- Use sentry core instead of sentry - ([fa1620a](https://github.com/vicanso/pingap/commit/fa1620ad922060e6c13f03292405a83108dd3622))
- Use rust 1.83.0 - ([1e10601](https://github.com/vicanso/pingap/commit/1e10601b5ea76fa5b92d274c22ceb0405435b195))
- Update dependencies - ([e64bb71](https://github.com/vicanso/pingap/commit/e64bb71f2c32009d500df986ceed2b4fe87f8b02))
- Remove modify swap step - ([736123a](https://github.com/vicanso/pingap/commit/736123acfdd88c9ddafcd3a7d65eb854c36e5458))
- Use self hosted runner - ([8a0e602](https://github.com/vicanso/pingap/commit/8a0e60200b81c12af3298d839ad12a6a9a49de56))
- Use ubuntu latest for docker build - ([e606384](https://github.com/vicanso/pingap/commit/e60638447567c4d4cbc73b2e2cea625690e55a54))
- Set docker only build for arm64 - ([d6ed2b5](https://github.com/vicanso/pingap/commit/d6ed2b55ec8280e170f9346c6f007c16bf91c570))
- Update pingora - ([cc10122](https://github.com/vicanso/pingap/commit/cc10122f6f79c55dec3a57c05c8ecf75d53a263f))
- Remove arm64 platform - ([76596eb](https://github.com/vicanso/pingap/commit/76596ebe0bcabf54155f609abe2166725ac75d65))
- Adjust swap size - ([c6da4dd](https://github.com/vicanso/pingap/commit/c6da4dda46081a3ca50e9695f8c6d8499eaa8ca6))
- Add free disk spacke step - ([f15f3ce](https://github.com/vicanso/pingap/commit/f15f3ce05f6f803b17c6b376d4467b2422bcfb94))
- Adjust swap size - ([11e6483](https://github.com/vicanso/pingap/commit/11e6483305d7932bc08bbe26d24fb10aa6862e89))
- Update github workflow - ([14a0dea](https://github.com/vicanso/pingap/commit/14a0deab0371d3b6a95f291000da1c003d27bdbd))
- Update github action - ([309ca20](https://github.com/vicanso/pingap/commit/309ca20a2f83a5f2dcf859b2abfe813333393e4f))
- Update github action for large runner - ([2457c68](https://github.com/vicanso/pingap/commit/2457c68459de47e266079dcdec0d72b21b2508da))

### Fest

- Add test for proxy - ([d02b4d9](https://github.com/vicanso/pingap/commit/d02b4d9f85fade655f776b978274abf10a47ae65))

## [0.9.9](https://github.com/vicanso/pingap/compare/v0.9.8..0.9.9) - 2025-01-18

### ⛰️  Features

- Support getting certificate from file - ([aed1d48](https://github.com/vicanso/pingap/commit/aed1d48be8170373f2f94ee3617478e1d7d7f63a))
- Support set response header if not exists - ([2ca1366](https://github.com/vicanso/pingap/commit/2ca1366f8ef416823e04aae9385f1be4319da905))
- Add sub filter plugin, #80 - ([5ae2a9c](https://github.com/vicanso/pingap/commit/5ae2a9c54bd2e3e38fe2ae7c4eb689c30ce6321d))
- Support cache file max weight for tinyufo of file cache - ([2da5b77](https://github.com/vicanso/pingap/commit/2da5b7766601e7e3d637a05391ccfe264af51b32))

### 🐛 Bug Fixes

- Fix test - ([b137266](https://github.com/vicanso/pingap/commit/b1372664578823bb9ec2548a6d657a39f21acaf6))
- Fix empty access log format - ([ed77687](https://github.com/vicanso/pingap/commit/ed77687f891507ac2d66dbadc0b236d906fd6fe6))

### 🚜 Refactor

- Log chain certificate parse error - ([500dd41](https://github.com/vicanso/pingap/commit/500dd410d7b3b807370500df87e3b3f50404aed6))
- Update shadcn ui - ([30ffc48](https://github.com/vicanso/pingap/commit/30ffc485936735752d020ec44f39f582d4a291ff))
- Set default step for each plugin - ([47326bf](https://github.com/vicanso/pingap/commit/47326bfd0fafd04d4834554ed2018fcc61c0a82c))
- Adjust http header - ([c54db8f](https://github.com/vicanso/pingap/commit/c54db8f1ffded64feb86ccfd690133dda9c3e8ed))
- Adjust performance metrics - ([5be5359](https://github.com/vicanso/pingap/commit/5be5359914aaa61f624867ac4f791112ecb26b7e))
- Remove dhat feature - ([8bcfe7d](https://github.com/vicanso/pingap/commit/8bcfe7d572c2d70c289726e9ea63e89cc6f8e7ff))
- Adjust performance metrics - ([6c8a7e5](https://github.com/vicanso/pingap/commit/6c8a7e5ba8a52a1a4d568dbb712b3607094c6df0))
- Adjust cache storage trait - ([b08a5c0](https://github.com/vicanso/pingap/commit/b08a5c00c713d800d1aadaa9f012f1fe5824a6f3))
- Adjust performance metrics - ([bbd1faf](https://github.com/vicanso/pingap/commit/bbd1faf645e0ced36486e147f06f08b14efff2b4))
- Adjust trait of http cache storage - ([83632a5](https://github.com/vicanso/pingap/commit/83632a5ab6e410309b297e936e1af088f3d77255))
- Adjust tinyufo cache for file cache - ([5b98684](https://github.com/vicanso/pingap/commit/5b98684aa41ed978afda363f2aca976893e3821e))

### 📚 Documentation

- Update comments - ([f31b591](https://github.com/vicanso/pingap/commit/f31b59113d0d438351bf4edb84240cf2cd41e1f3))
- Update documents - ([759159e](https://github.com/vicanso/pingap/commit/759159e2b351af2d0ab8e1427fe488cabaf36a79))
- Add comments - ([b6e4219](https://github.com/vicanso/pingap/commit/b6e42191160480fcf3fb73880fd61c5a70e94b7c))
- Add comments - ([616e75f](https://github.com/vicanso/pingap/commit/616e75f4c2605ecb6419654c597a79e8acb221df))
- Add comments to service - ([2c2440d](https://github.com/vicanso/pingap/commit/2c2440de49138a48cbd4961139e3708bbf3aa5d6))
- Add comments to plugin - ([15bb6be](https://github.com/vicanso/pingap/commit/15bb6be5429093dcf56f26ae14e146703ff86229))
- Update proxy upstream example - ([ab07a99](https://github.com/vicanso/pingap/commit/ab07a99bacf378cc7ff40003cf2f8f78ff351b43))

## [0.9.8](https://github.com/vicanso/pingap/compare/v0.9.7..0.9.8) - 2025-01-04

### ⛰️  Features

- Support set default reverse proxy header, #77 - ([2a4d198](https://github.com/vicanso/pingap/commit/2a4d1984c08aedd764845d27083505cd15f4795d))

### 🐛 Bug Fixes

- Fix test - ([0489480](https://github.com/vicanso/pingap/commit/0489480027f8c4dfc04080cb757a3c58299fb508))
- Fix format - ([cf9ddb8](https://github.com/vicanso/pingap/commit/cf9ddb8cd5f06c3260f2de89c25beb7a431341c8))

### 🚜 Refactor

- Update dependencies - ([248c32f](https://github.com/vicanso/pingap/commit/248c32fda5ae8fa0073a0e6ccaaf3d5789178930))
- Update upstream health check - ([7fa172c](https://github.com/vicanso/pingap/commit/7fa172c28ab97365c0a193a4be20aa5760410daa))
- Adjust upstream discovery - ([fc3414e](https://github.com/vicanso/pingap/commit/fc3414ea2286e5c1ebfcdc84029230faa5cdf9d0))
- Add comments - ([b6454cb](https://github.com/vicanso/pingap/commit/b6454cb15d42717278d83ac99d0af4445046e582))
- Adjust label name of config - ([c724a87](https://github.com/vicanso/pingap/commit/c724a8705c107908705f4ec176bcc920cf4c6448))
- Add more comments - ([7fe8e20](https://github.com/vicanso/pingap/commit/7fe8e20049a0c588e3be9957caef66e909e5ad9a))
- Adjust the code of service - ([788e86e](https://github.com/vicanso/pingap/commit/788e86e7fcd0373eb87b552a66a90e8baaeaa813))
- Adjust acme handle function - ([fba764b](https://github.com/vicanso/pingap/commit/fba764ba540fccabc789b1e7985cb613f1b1e431))
- Use crc32 hash for secret description - ([a5ef9c1](https://github.com/vicanso/pingap/commit/a5ef9c1c0e0293d98b430887eaa56241d7f990f2))

### 📚 Documentation

- Update documents - ([776c293](https://github.com/vicanso/pingap/commit/776c29321d52288b7dfe3caf32000d155e3e66d1))
- Update reademd - ([492405b](https://github.com/vicanso/pingap/commit/492405b9ce5adeb5302a766f83db9da56746e782))

## [0.9.7](https://github.com/vicanso/pingap/compare/v0.9.5..0.9.7) - 2024-12-28

### ⛰️  Features

- Add performance metrics log task - ([7dbe176](https://github.com/vicanso/pingap/commit/7dbe176d4a1c0e1580ddd093cdc8c6f768e0856e))

### 🐛 Bug Fixes

- Fix format - ([8493bfc](https://github.com/vicanso/pingap/commit/8493bfc3881b001083d347319efd670d6bd7b4a6))
- Fix validate certificate of let's encrypt - ([bfc88af](https://github.com/vicanso/pingap/commit/bfc88af74151254409f61e1b5aefa62fc55002e6))
- Fix test of prometheus - ([4e39e26](https://github.com/vicanso/pingap/commit/4e39e2602c3cc7b56866ad8c4d6b175bfa36fd97))

### 🚜 Refactor

- Adjust ua restriction plugin exec step - ([34c47f9](https://github.com/vicanso/pingap/commit/34c47f9540bf69f911ce01f472c2895efe229f1a))
- Adjust ip and referer restriction plugin exec step - ([733de57](https://github.com/vicanso/pingap/commit/733de57aeacb56ad0931a5660b26147f287017fa))
- Adjust comibined auth plugin exec step - ([9db1bd3](https://github.com/vicanso/pingap/commit/9db1bd3865df6dedbde6995399c5ede88aa59d5d))
- Adjust jwt auth plugin exec step - ([c53a1eb](https://github.com/vicanso/pingap/commit/c53a1eb4330664b938e8be5af08f7f38ed3f76d1))
- Adjust grpc health check - ([1757aa7](https://github.com/vicanso/pingap/commit/1757aa7e337c7b4e0a725bb73c04d3678a82789e))
- Adjust redirect for admin prefix path - ([761f043](https://github.com/vicanso/pingap/commit/761f043c63f121604d9e9786c397020788c8c2f8))
- Adjust background service log - ([b908d07](https://github.com/vicanso/pingap/commit/b908d07a6f2324a78216881a4c28902a61634f85))
- Adjust log of background service task - ([918afd3](https://github.com/vicanso/pingap/commit/918afd3f3d242fe337d01aac73fa0a0fe106f787))
- Adjust async webhook notification - ([252c7c3](https://github.com/vicanso/pingap/commit/252c7c3173558ff0c518a5f2c45aea72ca3483b7))
- Adjust prometheus metrics - ([fefb2f3](https://github.com/vicanso/pingap/commit/fefb2f3d446d1a7d71d921b3bd12e5f93c9dc125))
- Merge prometheus push service to simple background service - ([3c27551](https://github.com/vicanso/pingap/commit/3c275510d67d9207ed4c554be8bb1e19cfc4306f))
- Merge let's encrypt and log compress to simple background service - ([6100d36](https://github.com/vicanso/pingap/commit/6100d364252e8466ee98954d7d38fef0050dae0d))

### 📚 Documentation

- Update documents - ([34028d0](https://github.com/vicanso/pingap/commit/34028d065b5952b61ff5c849b6ad30f760b17d2b))

### ⚙️ Miscellaneous Tasks

- Version 0.9.6 - ([3027d71](https://github.com/vicanso/pingap/commit/3027d71e7f5af6ddb5358645c79860d2e355fd69))
- Add ignore for mechete - ([de22dd0](https://github.com/vicanso/pingap/commit/de22dd06b610ca182d125b3f1686747f708c65f2))
- Add cargo machete - ([6a42f39](https://github.com/vicanso/pingap/commit/6a42f39f42ca4f8b5e37d9391584998e8f8215e8))

## [0.9.6](https://github.com/vicanso/pingap/compare/v0.9.5..0.9.6) - 2024-12-28

### ⛰️  Features

- Add performance metrics log task - ([7dbe176](https://github.com/vicanso/pingap/commit/7dbe176d4a1c0e1580ddd093cdc8c6f768e0856e))

### 🐛 Bug Fixes

- Fix test of prometheus - ([4e39e26](https://github.com/vicanso/pingap/commit/4e39e2602c3cc7b56866ad8c4d6b175bfa36fd97))

### 🚜 Refactor

- Adjust ua restriction plugin exec step - ([34c47f9](https://github.com/vicanso/pingap/commit/34c47f9540bf69f911ce01f472c2895efe229f1a))
- Adjust ip and referer restriction plugin exec step - ([733de57](https://github.com/vicanso/pingap/commit/733de57aeacb56ad0931a5660b26147f287017fa))
- Adjust comibined auth plugin exec step - ([9db1bd3](https://github.com/vicanso/pingap/commit/9db1bd3865df6dedbde6995399c5ede88aa59d5d))
- Adjust jwt auth plugin exec step - ([c53a1eb](https://github.com/vicanso/pingap/commit/c53a1eb4330664b938e8be5af08f7f38ed3f76d1))
- Adjust grpc health check - ([1757aa7](https://github.com/vicanso/pingap/commit/1757aa7e337c7b4e0a725bb73c04d3678a82789e))
- Adjust redirect for admin prefix path - ([761f043](https://github.com/vicanso/pingap/commit/761f043c63f121604d9e9786c397020788c8c2f8))
- Adjust background service log - ([b908d07](https://github.com/vicanso/pingap/commit/b908d07a6f2324a78216881a4c28902a61634f85))
- Adjust log of background service task - ([918afd3](https://github.com/vicanso/pingap/commit/918afd3f3d242fe337d01aac73fa0a0fe106f787))
- Adjust async webhook notification - ([252c7c3](https://github.com/vicanso/pingap/commit/252c7c3173558ff0c518a5f2c45aea72ca3483b7))
- Adjust prometheus metrics - ([fefb2f3](https://github.com/vicanso/pingap/commit/fefb2f3d446d1a7d71d921b3bd12e5f93c9dc125))
- Merge prometheus push service to simple background service - ([3c27551](https://github.com/vicanso/pingap/commit/3c275510d67d9207ed4c554be8bb1e19cfc4306f))
- Merge let's encrypt and log compress to simple background service - ([6100d36](https://github.com/vicanso/pingap/commit/6100d364252e8466ee98954d7d38fef0050dae0d))

### 📚 Documentation

- Update documents - ([34028d0](https://github.com/vicanso/pingap/commit/34028d065b5952b61ff5c849b6ad30f760b17d2b))

### ⚙️ Miscellaneous Tasks

- Add ignore for mechete - ([de22dd0](https://github.com/vicanso/pingap/commit/de22dd06b610ca182d125b3f1686747f708c65f2))
- Add cargo machete - ([6a42f39](https://github.com/vicanso/pingap/commit/6a42f39f42ca4f8b5e37d9391584998e8f8215e8))

## [0.9.5](https://github.com/vicanso/pingap/compare/v0.9.4..0.9.5) - 2024-12-21

### ⛰️  Features

- Admin panel support set upstream keepalive pool size - ([d6ed036](https://github.com/vicanso/pingap/commit/d6ed036c36c91a79fb5f01a32835618ca7ab1593))
- Support generate certificate from self sigined ca, #66 - ([f1b2f6f](https://github.com/vicanso/pingap/commit/f1b2f6f8c5cd0626ab41ee6958f1bafcbcf1068e))
- Support print default config template - ([c3ea1d6](https://github.com/vicanso/pingap/commit/c3ea1d6df91e5cf773c5f013c0ba5b9489f1e5c2))

### 🐛 Bug Fixes

- Fix spelling - ([a97f232](https://github.com/vicanso/pingap/commit/a97f232bd4ae8909b54537432db4f54d35ac2740))

### 🚜 Refactor

- Use namespace of cache plugin as sub directory - ([e2ef50c](https://github.com/vicanso/pingap/commit/e2ef50c7cd87f38e816b919c6b7a42393db82edd))
- Adjust certificate of acme and self signed - ([69e7f37](https://github.com/vicanso/pingap/commit/69e7f379fa2ed5a61574e4d0aa31828f9bbd7b78))
- Adjust chain and self signed certificate - ([32efe09](https://github.com/vicanso/pingap/commit/32efe09c50c96bcc57898711bd81048949aa87ee))
- Make background service more simplified - ([be8652d](https://github.com/vicanso/pingap/commit/be8652dbe834858bf946480cd64695420ee55d34))
- Remove stale self signed certificate interval - ([a75af2a](https://github.com/vicanso/pingap/commit/a75af2ae8069dbcbe106a1d196fc67e064468d78))
- Adjust validate error of config - ([9ddccb1](https://github.com/vicanso/pingap/commit/9ddccb166c950dad9ec9b5f6053c49953824a700))
- Adjust log for discovery - ([5ffd70a](https://github.com/vicanso/pingap/commit/5ffd70a3f56b7a20ebc050e8dff817caacdd8427))
- Enhance file and tinyufo cache - ([c602154](https://github.com/vicanso/pingap/commit/c6021540201f033208d281c95546fecc3c5474a0))
- Add error log for self signed certificate fail - ([eb97a4d](https://github.com/vicanso/pingap/commit/eb97a4d6491a38186bbfd4cdf5cbd5f2cd46e1ee))

### ⚙️ Miscellaneous Tasks

- Sync pingora latest commit - ([818ee7a](https://github.com/vicanso/pingap/commit/818ee7aafb140aecab4089519371b6ce231807be))

## [0.9.4](https://github.com/vicanso/pingap/compare/v0.9.3..0.9.4) - 2024-12-14

### ⛰️  Features

- File cache support limit tinyufo cache size - ([9aa1219](https://github.com/vicanso/pingap/commit/9aa12195562ec970cb0b0923bb34a93e67125435))

### 🐛 Bug Fixes

- Fix open telemetry init - ([a6784a0](https://github.com/vicanso/pingap/commit/a6784a0f7a6ea42d93db0bee4f8a94c595b4e7c5))
- Fix 80 port for admin plugin, #58 - ([1d41c05](https://github.com/vicanso/pingap/commit/1d41c057f6df561b9549b9c08a4bb015fef6d7e1))

### 🚜 Refactor

- Update package - ([e744805](https://github.com/vicanso/pingap/commit/e74480551eb0eacd258bcc16890114accb385278))
- Adjust acme token directory - ([55413ad](https://github.com/vicanso/pingap/commit/55413ad78b691465a7814ea3c6b05fb17fbd2ef3))
- Save acme token as file - ([00cb15b](https://github.com/vicanso/pingap/commit/00cb15baa01548990925619b8f0ed0da860d996c))
- Save let's encrypt cert and key to config storage - ([6e7b5b7](https://github.com/vicanso/pingap/commit/6e7b5b7991f4dc8afc618117de8cbc8d7e340823))
- Adjust certificate of tls - ([757a75c](https://github.com/vicanso/pingap/commit/757a75cd272cd6cffd9fdb7ccc49a159ff55ba01))

### 📚 Documentation

- Update benchmark - ([3406310](https://github.com/vicanso/pingap/commit/3406310c9d2901b79d18a559c170559287e672e9))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([571d199](https://github.com/vicanso/pingap/commit/571d19973c9016fc34048c549b6b24dc9fc95134))
- Use rust 1.82.0 - ([f314e83](https://github.com/vicanso/pingap/commit/f314e83ae2bbbbdbb408614c156de542f6378a4e))

## [0.9.3](https://github.com/vicanso/pingap/compare/v0.9.2..0.9.3) - 2024-12-08

### ⛰️  Features

- Support importing config to storage, #58 - ([767df00](https://github.com/vicanso/pingap/commit/767df009fc2c895ac2c59d4640565e1a86b9e8e3))
- Support transparent proxy gateway, #66 - ([14cc735](https://github.com/vicanso/pingap/commit/14cc735964e7a52e4b4aa1c2a53d0e5c55a4002b))

### 🐛 Bug Fixes

- Remove validate from admin get config function, #67 - ([762e1a1](https://github.com/vicanso/pingap/commit/762e1a1030bdac57a070f1ae2004012b0711c7ad))

### 🚜 Refactor

- Adjust location of server - ([43fb471](https://github.com/vicanso/pingap/commit/43fb4714f5e876146b330c11bb13bffd20f281d2))
- Adjust derive debug for location and upstream - ([073c6c2](https://github.com/vicanso/pingap/commit/073c6c2a7086a4c745606998eb06bedc37a207db))
- Add original and compress size - ([8b82709](https://github.com/vicanso/pingap/commit/8b82709d379a0489db7a4fdd534c494ee1fa2a0e))
- Support reading and writing max count for file cache storage - ([aacfb31](https://github.com/vicanso/pingap/commit/aacfb31d8b244c453fed5d38ba87524f44691fc3))
- Adjust let's encrypt renew - ([f596461](https://github.com/vicanso/pingap/commit/f5964611ed435bcd405b4b949fa54956dae06a0e))
- Guess discovery for name addrs, #67 - ([227dd3a](https://github.com/vicanso/pingap/commit/227dd3a2c4d2f10b452eb6c68fdba090e178e7c4))
- Validity checker ignore acme certificate - ([5cf182f](https://github.com/vicanso/pingap/commit/5cf182f56fbd777a213bc56975fefc255ecd0799))

### 📚 Documentation

- Add transparent proxy demo - ([27503f2](https://github.com/vicanso/pingap/commit/27503f2062fb32077f86eef069fdbdc05a408b3c))

### 🧪 Testing

- Fix request entity too large error - ([bb56bc0](https://github.com/vicanso/pingap/commit/bb56bc0bab9d5a7540a5fcb50144fb846366d222))

### ⚙️ Miscellaneous Tasks

- Update pingap service - ([3809608](https://github.com/vicanso/pingap/commit/38096087c417849871a5a20e60a6e79dfcac71b2))

## [0.9.2](https://github.com/vicanso/pingap/compare/v0.9.1..0.9.2) - 2024-11-30

### ⛰️  Features

- Cache plugin support skip handle - ([111ccb6](https://github.com/vicanso/pingap/commit/111ccb623d82e4527195f1cee047f32db08b0c5e))
- Support add admin plugin to server, #58 - ([d9cd254](https://github.com/vicanso/pingap/commit/d9cd254bf4a231605c94f02ec9d05cef44802133))
- Response header plugin support rename header, #61 ([#62](https://github.com/orhun/git-cliff/issues/62)) - ([66b4824](https://github.com/vicanso/pingap/commit/66b48241fad52624c93ec9ae3e5a8ed3a671d40f))

### 🐛 Bug Fixes

- Fix base64 encode of admin auth, #63 - ([a435cbf](https://github.com/vicanso/pingap/commit/a435cbf0606648dae34d2c16bdb0dd1f5c71d264))

### 🚜 Refactor

- Adjust admin login page - ([6e458f2](https://github.com/vicanso/pingap/commit/6e458f22a2714758757b6d8e88af40663fc87481))
- Adjust admin login page - ([9f3825c](https://github.com/vicanso/pingap/commit/9f3825cccb30f5d28061e76de0c76af95352afd1))
- Update open telemetry module ([#59](https://github.com/orhun/git-cliff/issues/59)) - ([2feb080](https://github.com/vicanso/pingap/commit/2feb0805ebd201e3265d095307eecee68c5693b9))
- Adjust get query from etcd connection uri - ([5103c26](https://github.com/vicanso/pingap/commit/5103c26d0cf01d3e5596c49bb10d5c0275ec6e76))

### 🧪 Testing

- Fix clippy result large err - ([fbe27fe](https://github.com/vicanso/pingap/commit/fbe27fe0d2ba95f73479ca5b6243f4502718311d))

### ⚙️ Miscellaneous Tasks

- Update deppendencies - ([626b829](https://github.com/vicanso/pingap/commit/626b829b8d7b5dfe5910b6ede4d0b1ad0853fdde))
- Update modules - ([b4bb67e](https://github.com/vicanso/pingap/commit/b4bb67eae34d243a966b0a484c8572a594243c38))
- Add pingap service config - ([e008557](https://github.com/vicanso/pingap/commit/e00855760d22c465c7b4f510f6087b0c594813c6))

## [0.9.1](https://github.com/vicanso/pingap/compare/v0.9.0..0.9.1) - 2024-11-23

### ⛰️  Features

- Split and save the config as single toml in separation mode - ([562085b](https://github.com/vicanso/pingap/commit/562085b0d2cda2724739b83cbc93cabe7363cbb5))
- Supports days_ago and time_point_hour parameters for log compression - ([ee76bd7](https://github.com/vicanso/pingap/commit/ee76bd7313d2d6deee1b426f24c55e4398bd0759))
- Admin argument supports path - ([d676aeb](https://github.com/vicanso/pingap/commit/d676aeb06438ef4e1d5433dce6a542f0a2eb481b))
- Supports log compression ([#57](https://github.com/orhun/git-cliff/issues/57)) - ([b6be388](https://github.com/vicanso/pingap/commit/b6be388f7e1910d04a7a4002fdbb5fab678366dc))
- Health check supports grpc protocol ([#56](https://github.com/orhun/git-cliff/issues/56)) - ([165fa8a](https://github.com/vicanso/pingap/commit/165fa8aca23011517c21929c13d01c7421232a57))
- Support pingap accept encoding adjustment plugin - ([22ab2fc](https://github.com/vicanso/pingap/commit/22ab2fc68500530cfb06423ece504fe146dee62e))
- Show validity date of certificate - ([9d40a98](https://github.com/vicanso/pingap/commit/9d40a98acba45dc5fc82675b1e6064ad5f0fc30f))
- Path rewrite support variable substitution - ([4c62dc2](https://github.com/vicanso/pingap/commit/4c62dc25a2b160f1d4588b4389cab2c928450338))
- Server and location support grpc web module - ([e353aa6](https://github.com/vicanso/pingap/commit/e353aa67090a231c9dac2aa91bc6934c8911c646))
- Location host match supports regex - ([8498168](https://github.com/vicanso/pingap/commit/84981687261eddcd3e9006ffae6d1ef5163634ef))
- Tinyufo cache supports remove function - ([23833bf](https://github.com/vicanso/pingap/commit/23833bf13e17d011bf55bf35c6adf470ff225000))

### 🐛 Bug Fixes

- Fix non-latin name of config, #55 - ([b7b5129](https://github.com/vicanso/pingap/commit/b7b5129f0ac36d5c6c2f14d7a8158169f7addf15))
- Fix lint error - ([7cea336](https://github.com/vicanso/pingap/commit/7cea33643c7a4a208f8e45a1a80d773021751e2c))

### 🚜 Refactor

- Create toml config if if not exists - ([46b17e7](https://github.com/vicanso/pingap/commit/46b17e7b0aef054fb1a42ab5e7f34a0effa3b358))
- Add debug for proxy http trait - ([025031e](https://github.com/vicanso/pingap/commit/025031e626e585d9b59e2b616c6c5b579b9dadab))
- Add static serve example - ([2384ffe](https://github.com/vicanso/pingap/commit/2384ffe5c9b886733b4050a678cb3a3a049c8cf9))
- Adjust certificate editor - ([20acd3e](https://github.com/vicanso/pingap/commit/20acd3edf96bdee0f4ab6259da8a5f3a69b18b1b))
- Ctx supports add variable function - ([cd66f0d](https://github.com/vicanso/pingap/commit/cd66f0db80d9b75741a3f0776b494e1e0f0dfa21))
- Adjust regex capture for variables - ([9ade424](https://github.com/vicanso/pingap/commit/9ade4247fd953715bf460a6a2a49a6d734a6f4e4))
- Update logo of pingap - ([01ffb87](https://github.com/vicanso/pingap/commit/01ffb876b8fd71ccb4d2b38d3d42c5fb1ac8f478))
- Update opentelemetry - ([9a04df1](https://github.com/vicanso/pingap/commit/9a04df1857059711a161eaf85b60e1097f505f94))

### 📚 Documentation

- Add grpc web example - ([10001c3](https://github.com/vicanso/pingap/commit/10001c3fdbf230f406d744dc5aae372c99b76d53))
- Add proxy upstream example - ([e7fbacd](https://github.com/vicanso/pingap/commit/e7fbacd4ad721cac79f5f85810f02d7eb56e8493))

### 🧪 Testing

- Add purge test for cache plugin - ([1411704](https://github.com/vicanso/pingap/commit/1411704819802016e157946ec66443efc9b20962))
- Add test for basic auth plugin - ([04d1ec0](https://github.com/vicanso/pingap/commit/04d1ec0aee48ba1324b6bf22d297f4355be897ab))
- Add test for config - ([9c13cbb](https://github.com/vicanso/pingap/commit/9c13cbb8569c8aff47a746b6173eb72e4e696a6f))

### ⚙️ Miscellaneous Tasks

- Update pingora version - ([5bc53d3](https://github.com/vicanso/pingap/commit/5bc53d35ae158689d72ee388ea63ab7ade56a9eb))
- Using ubuntu 18.04 as the build system - ([8a592e4](https://github.com/vicanso/pingap/commit/8a592e4638cf34d33c3a6782e8cf68be1ab21db0))
- Benchmark test - ([0e519eb](https://github.com/vicanso/pingap/commit/0e519eb0f4156919477770db478130390b44bd05))
- Use latest commit pingora - ([7199e3c](https://github.com/vicanso/pingap/commit/7199e3ce72887001f584b02e87f435b4d6211053))

## [0.9.0](https://github.com/vicanso/pingap/compare/v0.8.12..0.9.0) - 2024-11-02

### ⛰️  Features

- Support user agent restriction plugin - ([c97adcd](https://github.com/vicanso/pingap/commit/c97adcd5ff8eb317ac1161e77139b8ddec713005))
- Support get storage value for pingap - ([e51a076](https://github.com/vicanso/pingap/commit/e51a076529c73bf7c07cca145d570f484051fc95))
- Support aes encrypt and decrypt - ([b38843f](https://github.com/vicanso/pingap/commit/b38843f83eca7221467648c3eaca1565e179fbf8))

### 🚜 Refactor

- Adjust aes encrypt and decrypt - ([f700ff7](https://github.com/vicanso/pingap/commit/f700ff789329ff5e2ac8eefd2c72ce8dc0a7447f))
- Adjust prometheus - ([2c86d21](https://github.com/vicanso/pingap/commit/2c86d217108a0b093239c3b76e2c29d24d5442d3))
- Adjust omit includes value - ([d2b2306](https://github.com/vicanso/pingap/commit/d2b23063157e5ac154bb005d67ab63ddcea09201))

### ⚙️ Miscellaneous Tasks

- Update pingora version - ([b9533d6](https://github.com/vicanso/pingap/commit/b9533d67c437d1dbb5b8dd11b48e91ac59934ed0))

## [0.8.12](https://github.com/vicanso/pingap/compare/v0.8.11..0.8.12) - 2024-10-27

### ⛰️  Features

- Support file storage clear background service - ([4e4afcd](https://github.com/vicanso/pingap/commit/4e4afcdda32670589b4bf58f933b04c46d72e70d))
- Support server addr and port for response header - ([7ae4ed1](https://github.com/vicanso/pingap/commit/7ae4ed1575ec8457dd86f263011a8a109a84a6dc))
- Support check cache control for cache plugin - ([ba48ed5](https://github.com/vicanso/pingap/commit/ba48ed5a4016b66fcff709ec85751619be07ef8f))
- Support pingap config preview - ([42b3ff8](https://github.com/vicanso/pingap/commit/42b3ff858775dd7325bebc214ecb50d99aa77576))
- Support get connection id from context - ([139c04c](https://github.com/vicanso/pingap/commit/139c04c071c7bda8f0afd43e7cc26c1450b359b7))

### 🐛 Bug Fixes

- Fix fd and connection count - ([9def503](https://github.com/vicanso/pingap/commit/9def50380444dd33524dfabf79a7e3c481e7487e))
- Fix process id - ([ae4f946](https://github.com/vicanso/pingap/commit/ae4f946b1cc5cb5d8a725edd7407e2454e90579a))
- Fix default threads of service - ([e2a2a68](https://github.com/vicanso/pingap/commit/e2a2a68b48a1cc5212a6437b22b99904a9c140d8))
- Fix prefix of redirect plugin - ([97fc5e0](https://github.com/vicanso/pingap/commit/97fc5e06815d8403baa5a92954024a83cdce2212))
- Fix connection id for windows - ([1d21562](https://github.com/vicanso/pingap/commit/1d21562e03080d3b7b50740c4cdce2c468154cb9))

### 🚜 Refactor

- Add fd and tcp default for home page - ([9b824f8](https://github.com/vicanso/pingap/commit/9b824f8395f6995fb3c1e598be2bcee806e66b62))
- Adjust stats of pingap - ([99f0183](https://github.com/vicanso/pingap/commit/99f0183357c573c15349a819942f16263a80f602))
- Adjust common service task - ([718ab0e](https://github.com/vicanso/pingap/commit/718ab0e687931e39b5f43f5a4fe73c52c8cd87b5))
- Set default certificate for none server name - ([d5fb595](https://github.com/vicanso/pingap/commit/d5fb59540fcdc9566957450d292e0151d428f802))
- Adjust web admin for open telemetry and pyroscope - ([3a79342](https://github.com/vicanso/pingap/commit/3a7934283d78364fb6b7d8c2320fad1341f82c87))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([296fd10](https://github.com/vicanso/pingap/commit/296fd1034fc365016a63eb6aa0149a61ea5eb328))

## [0.8.11](https://github.com/vicanso/pingap/compare/v0.8.10..0.8.11) - 2024-10-19

### ⛰️  Features

- Support daily rolling log - ([34c99e1](https://github.com/vicanso/pingap/commit/34c99e1aa8f8f67340cb6044f46b2ef45c7033bb))

### 🐛 Bug Fixes

- Fix lint error - ([fc40efe](https://github.com/vicanso/pingap/commit/fc40efe8eec386f36add0937f87a87dcf312e8bb))

### 🚜 Refactor

- Support windows ([#47](https://github.com/orhun/git-cliff/issues/47)) - ([ede1024](https://github.com/vicanso/pingap/commit/ede1024e88d75ab7167781c22864bf59b31c748a))
- Adjust tracking feature for prometheus and open telemetry ([#46](https://github.com/orhun/git-cliff/issues/46)) - ([f46edc8](https://github.com/vicanso/pingap/commit/f46edc879290e8dc9050bee949e868295e24b0ae))
- Adjust main header - ([0e38e1f](https://github.com/vicanso/pingap/commit/0e38e1feb8032ad5a43faa05eaeb5fbb29c88ab6))
- Support more header for http - ([24267bd](https://github.com/vicanso/pingap/commit/24267bd2055844e5118a9d0e13abf582986feb74))
- Support more rolling type - ([538ba7a](https://github.com/vicanso/pingap/commit/538ba7a95bb5fb850c613c1495ad0391657f3811))
- Adjust label of pingap config web page - ([2b917cf](https://github.com/vicanso/pingap/commit/2b917cf60dfd6eeba2ba3fc2f1574aeed6b51fbf))
- Add tracking and kernel for basic info - ([d7ed17d](https://github.com/vicanso/pingap/commit/d7ed17dffeeaba065f641cc3e0faa6c2412b18dc))
- Adjust sentry optional - ([d778449](https://github.com/vicanso/pingap/commit/d778449e13008b17d0d53ea05e459e0341b569a1))

### ⚙️ Miscellaneous Tasks

- Update workflow - ([adc53e8](https://github.com/vicanso/pingap/commit/adc53e8fc77f780b6685be17fb3a3bfe8ae6c94a))
- Update workflow - ([681620d](https://github.com/vicanso/pingap/commit/681620d8d3943432b8984e2c2eef91a6567ce248))

## [0.8.10](https://github.com/vicanso/pingap/compare/v0.8.8..0.8.10) - 2024-10-13

### ⛰️  Features

- Support more infomations for stats - ([ec74050](https://github.com/vicanso/pingap/commit/ec74050f5ee59016a3ea2c9fab99598aa5751ce6))

### 🧪 Testing

- Fix test - ([acda41e](https://github.com/vicanso/pingap/commit/acda41e40772859f9acc00eb85f1d7b5578d6ac0))

### ⚙️ Miscellaneous Tasks

- Use ubuntu 20.04 for workflow - ([af70c91](https://github.com/vicanso/pingap/commit/af70c913bbc974a09e8a2a5215b8045b8ffe5fba))
- Version 0.8.9 - ([9241030](https://github.com/vicanso/pingap/commit/9241030ea2ffa29987549a6b9e89fec93d2c9a15))
- Version 0.8.8 - ([bcb5ef4](https://github.com/vicanso/pingap/commit/bcb5ef46f1f1be374b6e5e932451bc0ad11684fe))
- Update components - ([746294e](https://github.com/vicanso/pingap/commit/746294e32be82b149071e51bc4465f4bb3de9daa))

## [0.8.9](https://github.com/vicanso/pingap/compare/v0.8.8..0.8.9) - 2024-10-13

### ⛰️  Features

- Support more infomations for stats - ([ec74050](https://github.com/vicanso/pingap/commit/ec74050f5ee59016a3ea2c9fab99598aa5751ce6))

### 🧪 Testing

- Fix test - ([acda41e](https://github.com/vicanso/pingap/commit/acda41e40772859f9acc00eb85f1d7b5578d6ac0))

### ⚙️ Miscellaneous Tasks

- Version 0.8.8 - ([bcb5ef4](https://github.com/vicanso/pingap/commit/bcb5ef46f1f1be374b6e5e932451bc0ad11684fe))
- Update components - ([746294e](https://github.com/vicanso/pingap/commit/746294e32be82b149071e51bc4465f4bb3de9daa))

## [0.8.8](https://github.com/vicanso/pingap/compare/v0.8.8..0.8.8) - 2024-10-13

### ⛰️  Features

- Support more infomations for stats - ([ec74050](https://github.com/vicanso/pingap/commit/ec74050f5ee59016a3ea2c9fab99598aa5751ce6))

### 🧪 Testing

- Fix test - ([acda41e](https://github.com/vicanso/pingap/commit/acda41e40772859f9acc00eb85f1d7b5578d6ac0))

### ⚙️ Miscellaneous Tasks

- Update components - ([746294e](https://github.com/vicanso/pingap/commit/746294e32be82b149071e51bc4465f4bb3de9daa))

## [0.8.7](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.7) - 2024-09-29

### ⛰️  Features

- Support gzip for admin - ([308d226](https://github.com/vicanso/pingap/commit/308d2266487a8b4a8d6e13eb1c17240df0772ae8))
- Web admin supports combined auth plugin config - ([8ec0960](https://github.com/vicanso/pingap/commit/8ec09600d280aace01390ce89a64ca95f7ea50cb))
- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Fix get location of empty host - ([30b48ea](https://github.com/vicanso/pingap/commit/30b48ea88c0bb2a92c3045a0d3a6c1ac2d66290f))
- Fix certificate summary list - ([c176296](https://github.com/vicanso/pingap/commit/c17629668d8d4de4703cb11a917b93a3d3642847))
- Fix get weight of location - ([1b8d094](https://github.com/vicanso/pingap/commit/1b8d09413030a56501f431e91c1846f2a2b7dc98))
- Fix select category of plugin - ([1ad25aa](https://github.com/vicanso/pingap/commit/1ad25aa15179cb324008346b598d5f97fde6e9de))
- Adjust base path for static serve - ([64cdf29](https://github.com/vicanso/pingap/commit/64cdf29c5f91aa5437ce3cb8247f4ba6837b76f4))
- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### 🚜 Refactor

- Adjust remove popup over - ([cff3354](https://github.com/vicanso/pingap/commit/cff3354d9f90eea6e053bff05734232a07144814))
- Adjust home page - ([53e006b](https://github.com/vicanso/pingap/commit/53e006bb31a111a41d5a5483b345e0a1cb24bf6a))
- Adjust home page - ([e322dc4](https://github.com/vicanso/pingap/commit/e322dc4ed86ee9bdbafe04c580832126ace707e8))
- Adjust config tabs - ([48989db](https://github.com/vicanso/pingap/commit/48989dba1971eca181acf12d97e1eecc9ec55007))
- Adjust config editor - ([cb0ea53](https://github.com/vicanso/pingap/commit/cb0ea53e7e7085e78ca53e68c6df1b658a2e1626))
- Adjust i18n - ([4c4b8b6](https://github.com/vicanso/pingap/commit/4c4b8b6c48a24e88712536397896a18fc451a1a1))

### 📚 Documentation

- Update CHANGELOG - ([b8498b8](https://github.com/vicanso/pingap/commit/b8498b8ca44e9c6b6fc20023f9251148122b26ce))

### ⚙️ Miscellaneous Tasks

- Version 0.8.6 - ([5bf9602](https://github.com/vicanso/pingap/commit/5bf9602b599305ff40aaacf0f7237ed4280a8394))
- Fix spelling - ([0ffb5e1](https://github.com/vicanso/pingap/commit/0ffb5e17c284ed9ae039897764036754718a86bc))
- Version 0.8.5 - ([80c0253](https://github.com/vicanso/pingap/commit/80c0253ba829d64b9cf9b428b80a7128e45e6218))
- Update cargo msrv - ([0f73b82](https://github.com/vicanso/pingap/commit/0f73b824257ca47395fb0f9519be2c1bb6940428))
- Version 0.8.4 - ([a870107](https://github.com/vicanso/pingap/commit/a87010770dd5ad10d5a4de8d6c59a23bf3c3de9d))
- Version 0.8.3 - ([9c139b8](https://github.com/vicanso/pingap/commit/9c139b8d4ff5af5ab4cee3a7408f8a532687407b))
- Version 0.8.2 - ([daf9a19](https://github.com/vicanso/pingap/commit/daf9a19516d63162a6f4bcd415f7a0cdef71f40b))
- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.6](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.6) - 2024-09-29

### ⛰️  Features

- Support gzip for admin - ([308d226](https://github.com/vicanso/pingap/commit/308d2266487a8b4a8d6e13eb1c17240df0772ae8))
- Web admin supports combined auth plugin config - ([8ec0960](https://github.com/vicanso/pingap/commit/8ec09600d280aace01390ce89a64ca95f7ea50cb))
- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Fix certificate summary list - ([c176296](https://github.com/vicanso/pingap/commit/c17629668d8d4de4703cb11a917b93a3d3642847))
- Fix get weight of location - ([1b8d094](https://github.com/vicanso/pingap/commit/1b8d09413030a56501f431e91c1846f2a2b7dc98))
- Fix select category of plugin - ([1ad25aa](https://github.com/vicanso/pingap/commit/1ad25aa15179cb324008346b598d5f97fde6e9de))
- Adjust base path for static serve - ([64cdf29](https://github.com/vicanso/pingap/commit/64cdf29c5f91aa5437ce3cb8247f4ba6837b76f4))
- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### 🚜 Refactor

- Adjust remove popup over - ([cff3354](https://github.com/vicanso/pingap/commit/cff3354d9f90eea6e053bff05734232a07144814))
- Adjust home page - ([53e006b](https://github.com/vicanso/pingap/commit/53e006bb31a111a41d5a5483b345e0a1cb24bf6a))
- Adjust home page - ([e322dc4](https://github.com/vicanso/pingap/commit/e322dc4ed86ee9bdbafe04c580832126ace707e8))
- Adjust config tabs - ([48989db](https://github.com/vicanso/pingap/commit/48989dba1971eca181acf12d97e1eecc9ec55007))
- Adjust config editor - ([cb0ea53](https://github.com/vicanso/pingap/commit/cb0ea53e7e7085e78ca53e68c6df1b658a2e1626))
- Adjust i18n - ([4c4b8b6](https://github.com/vicanso/pingap/commit/4c4b8b6c48a24e88712536397896a18fc451a1a1))

### 📚 Documentation

- Update CHANGELOG - ([b8498b8](https://github.com/vicanso/pingap/commit/b8498b8ca44e9c6b6fc20023f9251148122b26ce))

### ⚙️ Miscellaneous Tasks

- Fix spelling - ([0ffb5e1](https://github.com/vicanso/pingap/commit/0ffb5e17c284ed9ae039897764036754718a86bc))
- Version 0.8.5 - ([80c0253](https://github.com/vicanso/pingap/commit/80c0253ba829d64b9cf9b428b80a7128e45e6218))
- Update cargo msrv - ([0f73b82](https://github.com/vicanso/pingap/commit/0f73b824257ca47395fb0f9519be2c1bb6940428))
- Version 0.8.4 - ([a870107](https://github.com/vicanso/pingap/commit/a87010770dd5ad10d5a4de8d6c59a23bf3c3de9d))
- Version 0.8.3 - ([9c139b8](https://github.com/vicanso/pingap/commit/9c139b8d4ff5af5ab4cee3a7408f8a532687407b))
- Version 0.8.2 - ([daf9a19](https://github.com/vicanso/pingap/commit/daf9a19516d63162a6f4bcd415f7a0cdef71f40b))
- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.5](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.5) - 2024-09-28

### ⛰️  Features

- Support gzip for admin - ([308d226](https://github.com/vicanso/pingap/commit/308d2266487a8b4a8d6e13eb1c17240df0772ae8))
- Web admin supports combined auth plugin config - ([8ec0960](https://github.com/vicanso/pingap/commit/8ec09600d280aace01390ce89a64ca95f7ea50cb))
- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Fix select category of plugin - ([1ad25aa](https://github.com/vicanso/pingap/commit/1ad25aa15179cb324008346b598d5f97fde6e9de))
- Adjust base path for static serve - ([64cdf29](https://github.com/vicanso/pingap/commit/64cdf29c5f91aa5437ce3cb8247f4ba6837b76f4))
- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### 🚜 Refactor

- Adjust remove popup over - ([cff3354](https://github.com/vicanso/pingap/commit/cff3354d9f90eea6e053bff05734232a07144814))
- Adjust home page - ([53e006b](https://github.com/vicanso/pingap/commit/53e006bb31a111a41d5a5483b345e0a1cb24bf6a))
- Adjust home page - ([e322dc4](https://github.com/vicanso/pingap/commit/e322dc4ed86ee9bdbafe04c580832126ace707e8))
- Adjust config tabs - ([48989db](https://github.com/vicanso/pingap/commit/48989dba1971eca181acf12d97e1eecc9ec55007))
- Adjust config editor - ([cb0ea53](https://github.com/vicanso/pingap/commit/cb0ea53e7e7085e78ca53e68c6df1b658a2e1626))
- Adjust i18n - ([4c4b8b6](https://github.com/vicanso/pingap/commit/4c4b8b6c48a24e88712536397896a18fc451a1a1))

### 📚 Documentation

- Update CHANGELOG - ([b8498b8](https://github.com/vicanso/pingap/commit/b8498b8ca44e9c6b6fc20023f9251148122b26ce))

### ⚙️ Miscellaneous Tasks

- Update cargo msrv - ([0f73b82](https://github.com/vicanso/pingap/commit/0f73b824257ca47395fb0f9519be2c1bb6940428))
- Version 0.8.4 - ([a870107](https://github.com/vicanso/pingap/commit/a87010770dd5ad10d5a4de8d6c59a23bf3c3de9d))
- Version 0.8.3 - ([9c139b8](https://github.com/vicanso/pingap/commit/9c139b8d4ff5af5ab4cee3a7408f8a532687407b))
- Version 0.8.2 - ([daf9a19](https://github.com/vicanso/pingap/commit/daf9a19516d63162a6f4bcd415f7a0cdef71f40b))
- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.3](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.3) - 2024-09-25

### ⛰️  Features

- Web admin supports combined auth plugin config - ([8ec0960](https://github.com/vicanso/pingap/commit/8ec09600d280aace01390ce89a64ca95f7ea50cb))
- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Adjust base path for static serve - ([64cdf29](https://github.com/vicanso/pingap/commit/64cdf29c5f91aa5437ce3cb8247f4ba6837b76f4))
- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### 🚜 Refactor

- Adjust home page - ([e322dc4](https://github.com/vicanso/pingap/commit/e322dc4ed86ee9bdbafe04c580832126ace707e8))
- Adjust config tabs - ([48989db](https://github.com/vicanso/pingap/commit/48989dba1971eca181acf12d97e1eecc9ec55007))
- Adjust config editor - ([cb0ea53](https://github.com/vicanso/pingap/commit/cb0ea53e7e7085e78ca53e68c6df1b658a2e1626))
- Adjust i18n - ([4c4b8b6](https://github.com/vicanso/pingap/commit/4c4b8b6c48a24e88712536397896a18fc451a1a1))

### 📚 Documentation

- Update CHANGELOG - ([b8498b8](https://github.com/vicanso/pingap/commit/b8498b8ca44e9c6b6fc20023f9251148122b26ce))

### ⚙️ Miscellaneous Tasks

- Version 0.8.3 - ([9c139b8](https://github.com/vicanso/pingap/commit/9c139b8d4ff5af5ab4cee3a7408f8a532687407b))
- Version 0.8.2 - ([daf9a19](https://github.com/vicanso/pingap/commit/daf9a19516d63162a6f4bcd415f7a0cdef71f40b))
- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.3](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.3) - 2024-09-25

### ⛰️  Features

- Web admin supports combined auth plugin config - ([8ec0960](https://github.com/vicanso/pingap/commit/8ec09600d280aace01390ce89a64ca95f7ea50cb))
- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Adjust base path for static serve - ([64cdf29](https://github.com/vicanso/pingap/commit/64cdf29c5f91aa5437ce3cb8247f4ba6837b76f4))
- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### 🚜 Refactor

- Adjust home page - ([e322dc4](https://github.com/vicanso/pingap/commit/e322dc4ed86ee9bdbafe04c580832126ace707e8))
- Adjust config tabs - ([48989db](https://github.com/vicanso/pingap/commit/48989dba1971eca181acf12d97e1eecc9ec55007))
- Adjust config editor - ([cb0ea53](https://github.com/vicanso/pingap/commit/cb0ea53e7e7085e78ca53e68c6df1b658a2e1626))
- Adjust i18n - ([4c4b8b6](https://github.com/vicanso/pingap/commit/4c4b8b6c48a24e88712536397896a18fc451a1a1))

### ⚙️ Miscellaneous Tasks

- Version 0.8.3 - ([9c139b8](https://github.com/vicanso/pingap/commit/9c139b8d4ff5af5ab4cee3a7408f8a532687407b))
- Version 0.8.2 - ([daf9a19](https://github.com/vicanso/pingap/commit/daf9a19516d63162a6f4bcd415f7a0cdef71f40b))
- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.2](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.2) - 2024-09-21

### ⛰️  Features

- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.1](https://github.com/vicanso/pingap/compare/v0.8.0..0.8.1) - 2024-09-07

### ⛰️  Features

- Support hot reload certificates - ([202c5d7](https://github.com/vicanso/pingap/commit/202c5d799fa566dd60165a49a39148e8342bde40))
- Support sync config to other storage - ([e66740d](https://github.com/vicanso/pingap/commit/e66740d389ef5a792131a6e0b9d0c1908ab866d2))

### 🚜 Refactor

- Adjust certificate reload - ([e6b5e04](https://github.com/vicanso/pingap/commit/e6b5e0496cab829b1021e74f7ff51965587fcfa7))
- Adjust certificate of config - ([a5e484a](https://github.com/vicanso/pingap/commit/a5e484af9634d8cab8e29436656f6e891ea0c8a3))
- Adjust stats and compression plugin - ([2334f5a](https://github.com/vicanso/pingap/commit/2334f5a395c5cde8e1650b2fc27c3626193a9239))
- Set max limit for tcp probe count - ([8da5d08](https://github.com/vicanso/pingap/commit/8da5d08cc059d5ae58912a1d4a546b2c0b4f8d72))

### ⚙️ Miscellaneous Tasks

- Version 0.8.1 - ([8083922](https://github.com/vicanso/pingap/commit/80839223e8f1aae688cf7314cdf849d07064966e))
- Update dependencies - ([a612d45](https://github.com/vicanso/pingap/commit/a612d45b88ac4ab2f86b4f5a4124681c9d23a4b4))

## [0.8.0](https://github.com/vicanso/pingap/compare/v0.7.0..0.8.0) - 2024-08-31

### ⛰️  Features

- Support observe config update for etcd storage - ([622ef94](https://github.com/vicanso/pingap/commit/622ef94cc2a5648f00f27503435691b571d2cf30))
- Support docker service discovery - ([3bed37b](https://github.com/vicanso/pingap/commit/3bed37b19e24cf5f6cf137c117bd185c84430232))
- Support upstream and location updated notification - ([ee73fac](https://github.com/vicanso/pingap/commit/ee73fac1774612c2da34c5665114e6bf651976ef))

### 🐛 Bug Fixes

- Fix docker discovery find by name - ([8aaec59](https://github.com/vicanso/pingap/commit/8aaec59dfc5accfab6c88de58e418a401d55d230))
- Fix get version of rustc - ([c03b4ac](https://github.com/vicanso/pingap/commit/c03b4ac253d98bf888f58cdca80e66ff15aa56ff))

### 🚜 Refactor

- Adjust http cache plugin - ([0401080](https://github.com/vicanso/pingap/commit/0401080c14d7cc29768e28f2c786f307041e4076))
- Adjust docker service discover for label filter - ([925a105](https://github.com/vicanso/pingap/commit/925a1057ba857b7e9af3a211a17220a02ce4becf))
- Adjust config reload handle - ([fc4d6e7](https://github.com/vicanso/pingap/commit/fc4d6e7a8434ac891ad3d1a522ec804e3f9fc5a0))
- Adjust proxy server - ([15e6143](https://github.com/vicanso/pingap/commit/15e61436320cb906774e189bb4c297954edecd50))
- Adjust discovery and otel - ([7a61860](https://github.com/vicanso/pingap/commit/7a61860a00e55901fea0836edc5ef93f3a514637))
- Adjust cache modules - ([ef7ce98](https://github.com/vicanso/pingap/commit/ef7ce9831875e37aaf08b3ae3134930db6e915aa))
- Adjust acme handler - ([c6ea96c](https://github.com/vicanso/pingap/commit/c6ea96cb344cbacfc1a441f7831e67534877beb1))
- Remove unused features - ([a39b1ce](https://github.com/vicanso/pingap/commit/a39b1ce752b663d2dde3d0db3b8d953061d5f191))
- Adjust dns service discovery - ([ec2f190](https://github.com/vicanso/pingap/commit/ec2f190db3a7d7f48dab7399fabf33ebb9ce9464))
- Adjust tls validity handle - ([87f8a74](https://github.com/vicanso/pingap/commit/87f8a744b5d31f0b19cad4074bc98e04943537aa))
- Add realod fail notification for web hook - ([85be103](https://github.com/vicanso/pingap/commit/85be1035f40dbe2ba9a73a6814395632511d589a))
- Adjust plugin reload function - ([cf5e8f5](https://github.com/vicanso/pingap/commit/cf5e8f5f66fb7621f87c899e797f97e8931c01a4))
- Adjust sentry client options - ([46f85e6](https://github.com/vicanso/pingap/commit/46f85e610a58233dd086cb080ece4c9b8929f5ec))
- Support auto reload plugin handler - ([f8ea609](https://github.com/vicanso/pingap/commit/f8ea6090f785ef33558cbab241d903917db14644))
- Adjust scopeguard for reading writing count - ([44234e0](https://github.com/vicanso/pingap/commit/44234e00e3870070184060a3c4f285b8517ce35f))
- Adjust backend observe notification - ([6065894](https://github.com/vicanso/pingap/commit/6065894448cfb538ee98454574042377d92c306d))
- Adjust base64 encode and decode - ([69a84af](https://github.com/vicanso/pingap/commit/69a84af7fdaefaef15fbcfda0b44eb20a68ff98d))
- Adjust error handler - ([121f428](https://github.com/vicanso/pingap/commit/121f428c71c2e3d1c7c6566cfdc6e4b6a4a5ae8a))

### 📚 Documentation

- Update documents, #21 - ([8d39a6b](https://github.com/vicanso/pingap/commit/8d39a6bd3ded554323041cc0d0c11560e377b449))

### ⚙️ Miscellaneous Tasks

- Version 0.8.0 - ([27cdc8e](https://github.com/vicanso/pingap/commit/27cdc8edefda33e79148be1ab8ee9ce7b4da9a67))
- Update dependencies - ([3d54394](https://github.com/vicanso/pingap/commit/3d543941308c9fe27a476a614b3563c509a9dd54))
- Add security audit - ([fc281c9](https://github.com/vicanso/pingap/commit/fc281c9e76b694860fc70c13fb925778177d9c28))

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

