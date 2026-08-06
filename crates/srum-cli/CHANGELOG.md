# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2](https://github.com/SecurityRonin/srum-forensic/compare/srum-cli-v0.3.1...srum-cli-v0.3.2) - 2026-08-06

### Fixed

- *(lints)* allow unwrap in srum-cli tests, unblocking Test on all three OS

### Other

- adopt canonical workspace lints; remove the JSON as_object_mut unwraps

## [0.3.1](https://github.com/SecurityRonin/srum-forensic/compare/srum-cli-v0.3.0...srum-cli-v0.3.1) - 2026-08-04

### Fixed

- *(output)* guard CSV cells against formula injection via jsonguard
