# Changelog

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
