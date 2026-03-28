

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
*   Initial release of the Secure Boot + OTA Update.
*   Mock implementation of SHA-256 hashing and digital signing.
*   A/B partition simulation logic.
*   Rollback protection mechanism.
*   Makefile and CMakeLists.txt build configurations.

## [1.0.0] - 2026-03-23

### Added
*   **Core Architecture:** Implemented `config.h`, `crypto_utils`, `secure_boot`, and `ota_manager` modules.
*   **Secure Boot Phase:** Added verification logic for bootloader and kernel with event logging.
*   **OTA Manager:** Implemented update checking, mock download, manifest verification, and installation flow.
*   **Safety Features:** Added rollback capability if firmware verification fails.
*   **Documentation:** Created `README.md`, `CONTRIBUTING.md`, and this `CHANGELOG.md`.

### Changed
*   Updated mock crypto functions to use simple XOR loops for educational clarity (not for production).

### Fixed
*   N/A (Initial Release)

### Security Note
*   **Warning:** This version uses mock cryptographic primitives. It is **not secure** for real-world deployment.
