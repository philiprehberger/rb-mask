# philiprehberger-mask

[![Tests](https://github.com/philiprehberger/rb-mask/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-mask/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-mask.svg)](https://rubygems.org/gems/philiprehberger-mask)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/rb-mask)](https://github.com/philiprehberger/rb-mask/commits/main)

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

### Hash Scrubbing with Modes

Apply partial or format-preserving masking to nested structures:

```ruby
Philiprehberger::Mask.scrub_hash({ card: '4111-1111-1111-1111' }, mode: :partial)
# => { card: "****1111" }

Philiprehberger::Mask.scrub_hash({ ssn: '123-45-6789' }, mode: :format_preserving)
# => { ssn: "000-00-0000" }
```

### Hash Audit Trail

Track what was masked in structured data with path information:

```ruby
result = Philiprehberger::Mask.scrub_hash_with_audit({ user: { email: 'alice@example.com', password: 'secret' } })
# => { result: { user: { email: "a***@e******.com", password: "[FILTERED]" } },
#      audit: [{ detector: :email, path: [:user, :email], ... }, { detector: :sensitive_key, key: "password", path: [:user, :password], ... }] }
```

### Batch Processing

Process multiple strings efficiently with shared compiled patterns:

```ruby
results = Philiprehberger::Mask.batch_scrub([
  "Contact user@example.com",
  "SSN: 123-45-6789",
  "Call 555-123-4567"
])
# => ["Contact u***@e******.com", "SSN: ***-**-6789", "Call ***-***-4567"]
```

### Detector Priority

Control which detector wins when patterns overlap:

```ruby
Philiprehberger::Mask.configure_priority(%i[ssn phone email credit_card ip_address jwt passport iban drivers_license mrn])
# SSN detector now evaluates first
```

### Locale Patterns

Register locale-specific detection patterns:

```ruby
Philiprehberger::Mask.add_locale(:de, { phone: /\b0\d{3}[- ]?\d{7,8}\b/ })

# Use locale patterns with scrub_io or batch_scrub
Philiprehberger::Mask.batch_scrub(["Call 0301-1234567"], locale: :de)
```

### IO Streaming

Scrub IO sources line by line:

```ruby
io = StringIO.new("user@example.com\nSSN: 123-45-6789\n")
results = Philiprehberger::Mask.scrub_io(io)
# => ["u***@e******.com\n", "SSN: ***-**-6789\n"]

File.open("sensitive.log") do |f|
  scrubbed_lines = Philiprehberger::Mask.scrub_io(f, mode: :partial)
end
```

### Log File Scrubbing

Scrub a log file in-place (atomic temp-file swap) or write to a separate output path:

```ruby
# In-place overwrite
summary = Philiprehberger::Mask.scrub_log('production.log')
# => { lines_processed: 1200, lines_modified: 43, detections: 51 }

# Write to a separate file
Philiprehberger::Mask.scrub_log('production.log', output: 'production.scrubbed.log')

# With masking mode and locale
Philiprehberger::Mask.scrub_log('app.log', mode: :partial, locale: :de)
```

### Custom Patterns

```ruby
Philiprehberger::Mask.configure do |c|
  c.add_pattern(:order_id, /ORD-\d{10}/, replacement: "ORD-XXXXXXXXXX")
end
```

### Custom Sensitive Keys

Register additional key names to redact in hash scrubbing:

```ruby
Philiprehberger::Mask.configure do |c|
  c.add_sensitive_key(:ssn_field)
  c.add_sensitive_key(:credit_card_number)
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
| `Mask.scrub_hash(hash, keys: nil, mode: :full)` | Deep-walk and redact hash values |
| `Mask.scrub_hash_with_audit(hash, keys: nil)` | Deep-walk, redact, and return audit trail with paths |
| `Mask.scrub_with_audit(string)` | Scrub and return audit trail of detections |
| `Mask.batch_scrub(strings, **opts)` | Process array of strings with shared compiled patterns |
| `Mask.scrub_io(io, **opts)` | Read IO line by line and scrub each line |
| `Mask.scrub_log(path, output: nil, mode: :full, locale: nil)` | Scrub a log file in-place or to an output path; returns `{ lines_processed:, lines_modified:, detections: }` |
| `Mask.tokenize(string)` | Replace PII with reversible tokens |
| `Mask.detokenize(string, tokens:)` | Restore original values from tokens |
| `Mask.configure_priority(detector_order)` | Set detector evaluation order |
| `Mask.add_locale(locale, patterns)` | Register locale-specific detection patterns |
| `Mask.configure { \|c\| ... }` | Register custom patterns, detectors, or sensitive keys |
| `Mask.reset_configuration!` | Reset to default patterns and sensitive keys |

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/rb-mask)

🐛 [Report issues](https://github.com/philiprehberger/rb-mask/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/rb-mask/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
