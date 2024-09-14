# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added _ctx_ parameter to signing and verifying functions. Existing functions are are unchanged and
  provide an empty string for _ctx_ per the FIPS 205 standard.

### Changed

- Comments and documentation which referenced the draft are updated to match the released standard.
  This is mostly figure/table/algorithm/page/line numbers.

## 0.1.2 (2024-03-15)

- Internal improvements, removed dependency on generic-array, MSRV at 1.70
- Supporting examples for benchmarking, CT measurements, WASM development, 
  C FFI, and Python bindings
- Additional testcases

## 0.1.1 (2024-02-14)

- Initial release
