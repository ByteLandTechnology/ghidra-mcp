# Changelog

## [2.1.0](https://github.com/ByteLandTechnology/ghidra-mcp/compare/v2.0.0...v2.1.0) (2026-11-24)


### Features

* publish compact tool schemas and enriched domain help ([#42](https://github.com/ByteLandTechnology/ghidra-mcp/issues/42)) ([7178453](https://github.com/ByteLandTechnology/ghidra-mcp/commit/717845323924c5f2f67681b82c4be00a66774b3c))


### Bug Fixes

* reject external origins on the mcp http endpoint ([#43](https://github.com/ByteLandTechnology/ghidra-mcp/issues/43)) ([7784b0c](https://github.com/ByteLandTechnology/ghidra-mcp/commit/7784b0c7e6d2c506fcc1ebb8f8f9a18421a2a2e8))
* **tools:** coerce JSON string params and list valid parameters ([#40](https://github.com/ByteLandTechnology/ghidra-mcp/issues/40)) ([95aa390](https://github.com/ByteLandTechnology/ghidra-mcp/commit/95aa3906befda2f30ce7ec03f6b5bc9256ff3a10))

## [2.0.0](https://github.com/ByteLandTechnology/ghidra-mcp/compare/v1.2.0...v2.0.0) (2026-11-16)


### ⚠ BREAKING CHANGES

* **cli:** use "ghidra-mcp daemon run" instead of "ghidra-mcp --daemon".

### Features

* **cli:** add management commands and replace --daemon ([baece2b](https://github.com/ByteLandTechnology/ghidra-mcp/commit/baece2be470615c025d542eee9ed4f26a4a0e2f9))
* **tools:** add daemon status, daemon shutdown and job list ([79e57ba](https://github.com/ByteLandTechnology/ghidra-mcp/commit/79e57baf60c2613a1e1885dc587027ddf80e045a))

## [1.2.0](https://github.com/ByteLandTechnology/ghidra-mcp/compare/v1.1.0...v1.2.0) (2026-11-15)


### Features

* **xtask:** add npm package generation ([35bef82](https://github.com/ByteLandTechnology/ghidra-mcp/commit/35bef82ecf12ef9beb15dbcd5760bf7a8d537c50))


### Bug Fixes

* **build:** bump rmcp from 3.8.0 to 3.10.0 ([4016295](https://github.com/ByteLandTechnology/ghidra-mcp/commit/40162955d9ce170efe2eb687aa492e5943823ca7))
* **build:** bump rustix from 1.1.5 to 1.1.6 ([cc205e6](https://github.com/ByteLandTechnology/ghidra-mcp/commit/cc205e69fba59ad4edc7e88d3575af77ad3a3192))
* **build:** let release-please update npm optional dependencies ([9443d6f](https://github.com/ByteLandTechnology/ghidra-mcp/commit/9443d6f6fa1c4c18d902f6a9d2a60b925619f12e))

## [1.1.0](https://github.com/ByteLandTechnology/ghidra-mcp/compare/v1.0.3...v1.1.0) (2026-11-02)


### Features

* add decompilation documents and C++ names ([8377347](https://github.com/ByteLandTechnology/ghidra-mcp/commit/8377347c8d5b64aa292764034ba2558eaf8390ad))
* add function creation and deletion ([ca737e2](https://github.com/ByteLandTechnology/ghidra-mcp/commit/ca737e232ec6ac794f35e3fe4f2a75d690f5a3a5))


### Bug Fixes

* generate and parse the asyncapi yaml contract ([83f8855](https://github.com/ByteLandTechnology/ghidra-mcp/commit/83f88554f7daef5e93ce61d2e8b856cef8f32985))
* guide clients to check operation parameters ([379bf5d](https://github.com/ByteLandTechnology/ghidra-mcp/commit/379bf5db950ebb27df0024742650cc0eafc6c800))
* replace the deprecated md5 compute method ([cf432b8](https://github.com/ByteLandTechnology/ghidra-mcp/commit/cf432b805f935c05b8c35d466f3d12189fae3394))

## [1.0.3](https://github.com/ByteLandTechnology/ghidra-mcp/compare/v1.0.2...v1.0.3) (2026-10-29)


### Bug Fixes

* return structured tool results as text ([25dbee9](https://github.com/ByteLandTechnology/ghidra-mcp/commit/25dbee9ef82437fa59d0e69ef41a8714c11932a1))

## [1.0.2](https://github.com/ByteLandTechnology/ghidra-mcp/compare/v1.0.1...v1.0.2) (2026-10-21)


### Bug Fixes

* **mcp:** update upload URLs in text results ([079f6a3](https://github.com/ByteLandTechnology/ghidra-mcp/commit/079f6a3004fc203941249495c420d3f7ca9e482d))

## [1.0.1](https://github.com/ByteLandTechnology/ghidra-mcp/compare/v1.0.0...v1.0.1) (2026-10-19)


### Bug Fixes

* fail daemon startup when Ghidra is unavailable ([ea12cb9](https://github.com/ByteLandTechnology/ghidra-mcp/commit/ea12cb9d7684825a97b951f2ae9d4ccb387c1a89))
* return absolute upload URLs for HTTP tool calls ([0fdd3ed](https://github.com/ByteLandTechnology/ghidra-mcp/commit/0fdd3ed1bd33730ca1e1e8dbd2c51f318dd24622))

## [1.0.0](https://github.com/ByteLandTechnology/ghidra-mcp/compare/v0.4.0...v1.0.0) (2026-10-16)


### ⚠ BREAKING CHANGES

* The ghidra tool and its command argument are removed. Clients call the ghidra_<domain> tools with operation, md5 and params.

### Features

* replace the ghidra tool with domain tools ([9f56629](https://github.com/ByteLandTechnology/ghidra-mcp/commit/9f56629b6f59ee8b6a7ceaefab7ab56a4a7e943d))

## [0.4.0](https://github.com/ByteLandTechnology/ghidra-mcp/compare/v0.3.0...v0.4.0) (2026-10-16)


### Features

* add shared Ghidra analysis through MCP ([e7d6c8e](https://github.com/ByteLandTechnology/ghidra-mcp/commit/e7d6c8e7cc083725eb1067adc03eef4980589488))
