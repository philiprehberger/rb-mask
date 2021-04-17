# philiprehberger-mask

[![Tests](https://github.com/philiprehberger/rb-mask/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-mask/actions/workflows/ci.yml) [![Gem Version](https://img.shields.io/gem/v/philiprehberger-mask)](https://rubygems.org/gems/philiprehberger-mask) [![GitHub release](https://img.shields.io/github/v/release/philiprehberger/rb-mask)](https://github.com/philiprehberger/rb-mask/releases) [![GitHub last commit](https://img.shields.io/github/last-commit/philiprehberger/rb-mask)](https://github.com/philiprehberger/rb-mask/commits/main) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Bug Reports](https://img.shields.io/badge/bug-reports-red.svg)](https://github.com/philiprehberger/rb-mask/issues) [![Feature Requests](https://img.shields.io/badge/feature-requests-blue.svg)](https://github.com/philiprehberger/rb-mask/issues) [![GitHub Sponsors](https://img.shields.io/badge/sponsor-philiprehberger-ea4aaa.svg?logo=github)](https://github.com/sponsors/philiprehberger)

Data masking library with auto-detect PII redaction for strings and nested structures

## Requirements

- Ruby >= 3.1

## Installation

Add to your Gemfile:

```ruby
gem "philiprehberger-mask"
```

Or install directly:

```bash
gem install philiprehberger-mask
```

## Usage

```ruby
require "philiprehberger/mask"

Philiprehberger::Mask.scrub("Contact us at user@example.com")
# => "Contact us at u***@e******.com"
```

### Hash Scrubbing

```ruby
Philiprehberger::Mask.scrub_hash({
  name: "Alice",
  email: "alice@example.com",
  password: "secret123",
  nested: { ssn: "123-45-6789" }
})
# => { name: "Alice", email: "a***@e******.com", password: "[FILTERED]", nested: { ssn: "***-**-6789" } }
```

### Partial Masking

Show partial information like last 4 digits or first initial:

```ruby
Philiprehberger::Mask.scrub("Card: 4111-1111-1111-1111", mode: :partial)
# => "Card: ****1111"

Philiprehberger::Mask.scrub("Email: user@example.com", mode: :partial)
# => "Email: u***@example.com"
```

### Format-Preserving Masking

Replace characters while keeping separators and format intact:

```ruby
Philiprehberger::Mask.scrub("SSN: 123-45-6789", mode: :format_preserving)
# => "SSN: 000-00-0000"

Philiprehberger::Mask.scrub("Email: user@example.com", mode: :format_preserving)
# => "Email: XXXX@XXXXXXX.XXX"
```

### Tokenization

Replace PII with reversible tokens:

```ruby
result = Philiprehberger::Mask.tokenize("Contact user@example.com")
# => { masked: "Contact <TOKEN_EMAIL_1>", tokens: { "<TOKEN_EMAIL_1>" => "user@example.com" } }

Philiprehberger::Mask.detokenize(result[:masked], tokens: result[:tokens])
# => "Contact user@example.com"
```

### Audit Trail

Track what was masked and where:

```ruby
result = Philiprehberger::Mask.scrub_with_audit("SSN: 123-45-6789")
# => { result: "SSN: ***-**-6789", audit: [{ detector: :ssn, original: "123-45-6789", masked: "***-**-6789", position: 5 }] }
```

### Custom Patterns

```ruby
Philiprehberger::Mask.configure do |c|
  c.add_pattern(:order_id, /ORD-\d{10}/, replacement: "ORD-XXXXXXXXXX")
end
```

### Custom Detector DSL

Register detectors with block-based replacers:

```ruby
Philiprehberger::Mask.configure do |c|
  c.detect(:employee_id, /EMP\d{6}/) { |match| "[EMPLOYEE_ID]" }
end
```

### Built-in Detectors

| Detector | Pattern | Masking |
|----------|---------|---------|
| Email | `user@example.com` | `u***@e******.com` |
| Credit Card | `4111-1111-1111-1111` | `****-****-****-1111` |
| SSN | `123-45-6789` | `***-**-6789` |
| Phone | `555-123-4567` | `***-***-4567` |
| IP Address | `192.168.1.1` | `***.***.***.***` |
| JWT | `eyJ...` | `[REDACTED_JWT]` |
| Passport | `C12345678` | `[REDACTED_PASSPORT]` |
| IBAN | `GB29NWBK60161331926819` | `[REDACTED_IBAN]` |
| Driver's License | `D1234567` | `[REDACTED_DL]` |
| MRN | `MRN12345678` | `[REDACTED_MRN]` |

## API

| Method | Description |
|--------|-------------|
| `Mask.scrub(string, mode: :full)` | Detect and redact PII in a string |
| `Mask.scrub_hash(hash, keys: nil)` | Deep-walk and redact hash values |
| `Mask.scrub_with_audit(string)` | Scrub and return audit trail of detections |
| `Mask.tokenize(string)` | Replace PII with reversible tokens |
| `Mask.detokenize(string, tokens:)` | Restore original values from tokens |
| `Mask.configure { \|c\| ... }` | Register custom patterns or detectors |
| `Mask.reset_configuration!` | Reset to default patterns |

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## Support

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Philip%20Rehberger-blue?logo=linkedin)](https://linkedin.com/in/philiprehberger) [![More Packages](https://img.shields.io/badge/more-packages-blue.svg)](https://github.com/philiprehberger?tab=repositories)

## License

[MIT](LICENSE)
