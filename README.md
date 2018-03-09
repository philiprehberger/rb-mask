# philiprehberger-mask

[![Tests](https://github.com/philiprehberger/rb-mask/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-mask/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-mask.svg)](https://rubygems.org/gems/philiprehberger-mask)
[![License](https://img.shields.io/github/license/philiprehberger/rb-mask)](LICENSE)

Data masking library — auto-detect and redact PII (emails, credit cards, SSNs, tokens) in strings and nested structures

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

### Custom Patterns

```ruby
Philiprehberger::Mask.configure do |c|
  c.add_pattern(:order_id, /ORD-\d{10}/, replacement: "ORD-XXXXXXXXXX")
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

## API

| Method | Description |
|--------|-------------|
| `Mask.scrub(string)` | Detect and redact PII in a string |
| `Mask.scrub_hash(hash, keys: nil)` | Deep-walk and redact hash values |
| `Mask.configure { \|c\| ... }` | Register custom patterns |
| `Mask.reset_configuration!` | Reset to default patterns |

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## License

MIT
