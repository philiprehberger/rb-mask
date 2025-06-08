# Changelog

All notable changes to this gem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-04-11

### Added
- Add `mode:` parameter to `scrub_hash` for partial and format-preserving masking on nested structures
- Add `scrub_hash_with_audit` for audit trails on structured data with path tracking
- Add `add_sensitive_key` to configuration DSL for persistent custom sensitive key registration

## [0.2.2] - 2026-03-31

### Added
- Add GitHub issue templates, dependabot config, and PR template

## [0.2.1] - 2026-03-31

### Changed
- Standardize README badges, support section, and license format

## [0.2.0] - 2026-03-28

### Added
- New PII detectors: US passport numbers, IBAN, driver's license, medical record numbers (MRN)
- Context-preserving masking mode via `scrub(str, mode: :partial)` showing partial info (last 4 digits, first initial)
- Format-preserving masking mode via `scrub(str, mode: :format_preserving)` replacing chars while keeping separators
- Tokenization support via `Mask.tokenize(str)` and `Mask.detokenize(masked, tokens:)` for reversible masking
- Masking audit trail via `Mask.scrub_with_audit(str)` returning detailed detection metadata
- Custom detector registration DSL via `configure { |c| c.detect(:name, /pattern/) { |match| replacement } }`

## [0.1.10] - 2026-03-26

### Changed
- Add Sponsor badge to README
- Fix License section format


## [0.1.9] - 2026-03-24

### Changed
- Expand test coverage to 50+ examples covering edge cases and error paths

## [0.1.8] - 2026-03-24

### Fixed
- Shorten README one-liner and gemspec summary to stay under 120 characters

## [0.1.7] - 2026-03-24

### Fixed
- Remove inline comments from Development section to match template

## [0.1.6] - 2026-03-23

### Fixed
- Standardize README to match template guide

## [0.1.5] - 2026-03-22

### Changed
- Expand test coverage

## [0.1.4] - 2026-03-18

### Changed
- Revert gemspec to single-quoted strings per RuboCop default configuration

## [0.1.3] - 2026-03-18

### Fixed
- Fix RuboCop Style/StringLiterals violations in gemspec

## [0.1.2] - 2026-03-16

### Changed
- Add License badge to README
- Add bug_tracker_uri to gemspec

## [0.1.1] - 2026-03-15

## [0.1.0] - 2026-03-15

### Added
- Initial release
- Built-in detectors for email credit card SSN phone IP and JWT
- String and deep hash/array scrubbing
- Key-name heuristic detection for sensitive fields
- Configurable custom pattern registration
