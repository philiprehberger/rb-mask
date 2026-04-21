# frozen_string_literal: true

require 'spec_helper'
require 'stringio'
require 'tempfile'

RSpec.describe Philiprehberger::Mask do
  before { described_class.reset_configuration! }

  it 'has a version number' do
    expect(described_class::VERSION).not_to be_nil
  end

  describe '.scrub' do
    it 'masks email addresses' do
      result = described_class.scrub('Contact user@example.com')
      expect(result).to include('u***@e')
      expect(result).not_to include('user@example.com')
    end

    it 'masks credit card numbers with dashes' do
      result = described_class.scrub('Card: 4111-1111-1111-1111')
      expect(result).to include('****-****-****-1111')
    end

    it 'masks credit card numbers with spaces' do
      result = described_class.scrub('Card: 4111 1111 1111 1111')
      expect(result).to include('**** **** **** 1111')
    end

    it 'masks SSNs' do
      result = described_class.scrub('SSN: 123-45-6789')
      expect(result).to include('***-**-6789')
    end

    it 'masks phone numbers' do
      result = described_class.scrub('Call 555-123-4567')
      expect(result).to include('***-***-4567')
    end

    it 'masks IP addresses' do
      result = described_class.scrub('IP: 192.168.1.1')
      expect(result).to include('***.***.***.***')
    end

    it 'masks JWTs' do
      jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456'
      result = described_class.scrub("Token: #{jwt}")
      expect(result).to include('[REDACTED_JWT]')
    end

    it 'leaves non-sensitive strings unchanged' do
      expect(described_class.scrub('Hello World')).to eq('Hello World')
    end

    it 'masks multiple emails in one string' do
      result = described_class.scrub('From alice@test.com to bob@test.com')
      expect(result).not_to include('alice@test.com')
      expect(result).not_to include('bob@test.com')
    end

    it 'masks multiple PII types in one string' do
      input = 'Email: user@example.com SSN: 123-45-6789 IP: 10.0.0.1'
      result = described_class.scrub(input)
      expect(result).not_to include('user@example.com')
      expect(result).to include('***-**-6789')
      expect(result).to include('***.***.***.***')
    end

    it 'returns a new string without modifying the original' do
      original = 'user@example.com'
      result = described_class.scrub(original)
      expect(original).to eq('user@example.com')
      expect(result).not_to eq(original)
    end

    it 'handles empty string' do
      expect(described_class.scrub('')).to eq('')
    end

    it 'preserves SSN last four digits' do
      result = described_class.scrub('SSN: 999-88-1234')
      expect(result).to include('1234')
      expect(result).to include('***-**-')
    end

    it 'masks phone with parentheses format' do
      result = described_class.scrub('Call (555) 123-4567')
      expect(result).to include('4567')
      expect(result).not_to include('(555)')
    end

    it 'masks credit card numbers without separators' do
      result = described_class.scrub('Card: 4111111111111111')
      expect(result).to include('1111')
      expect(result).not_to include('4111111111111111')
    end

    it 'masks phone numbers with +1 prefix' do
      result = described_class.scrub('Call +1-800-555-1234')
      expect(result).to include('1234')
      expect(result).not_to include('800')
    end

    it 'masks phone numbers with dot separators' do
      result = described_class.scrub('Phone: 555.123.4567')
      expect(result).to include('4567')
      expect(result).not_to include('555.123')
    end

    it 'masks email and preserves the domain TLD' do
      result = described_class.scrub('user@example.com')
      expect(result).to include('.com')
    end

    it 'does not mask a partial JWT-like string' do
      result = described_class.scrub('eyJhbGci is not a full JWT')
      expect(result).not_to include('[REDACTED_JWT]')
    end

    it 'masks IP addresses embedded in longer text' do
      result = described_class.scrub('Server at 10.0.0.1 responded with 200')
      expect(result).to include('***.***.***.***')
      expect(result).to include('responded with 200')
    end

    it 'returns the original value when input is not a string' do
      expect(described_class.scrub(nil)).to be_nil
      expect(described_class.scrub(42)).to eq(42)
    end

    it 'masks multiple SSNs in a single string' do
      result = described_class.scrub('SSN1: 111-22-3333 SSN2: 444-55-6666')
      expect(result).to include('***-**-3333')
      expect(result).to include('***-**-6666')
    end

    it 'handles a string with only whitespace' do
      expect(described_class.scrub('   ')).to eq('   ')
    end

    it 'masks email with single-character local part' do
      result = described_class.scrub('a@example.com')
      expect(result).not_to include('a@example.com')
      expect(result).to include('.com')
    end

    it 'masks email with subdomain' do
      result = described_class.scrub('user@mail.example.co.uk')
      expect(result).not_to include('user@mail.example.co.uk')
      expect(result).to include('.uk')
    end

    it 'masks credit card preserving last four digits with no separators' do
      result = described_class.scrub('Card: 5500000000005559')
      expect(result).to include('5559')
      expect(result).not_to include('5500000000005559')
    end

    it 'masks multiple IP addresses in one string' do
      result = described_class.scrub('From 10.0.0.1 to 192.168.1.100')
      expect(result).not_to include('10.0.0.1')
      expect(result).not_to include('192.168.1.100')
      expect(result.scan('***.***.***.***').length).to eq(2)
    end

    it 'masks multiple JWTs in one string' do
      jwt1 = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig1'
      jwt2 = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyIn0.sig2'
      result = described_class.scrub("#{jwt1} and #{jwt2}")
      expect(result.scan('[REDACTED_JWT]').length).to eq(2)
    end

    it 'handles string with all PII types combined' do
      input = 'email: a@b.com card: 4111-1111-1111-1111 ssn: 123-45-6789 phone: 555-123-4567 ip: 1.2.3.4'
      result = described_class.scrub(input)
      expect(result).not_to include('a@b.com')
      expect(result).to include('****-****-****-1111')
      expect(result).to include('***-**-6789')
      expect(result).to include('***.***.***.***')
    end

    it 'masks phone number with +1 dot format' do
      result = described_class.scrub('Call +1.800.555.1234')
      expect(result).to include('1234')
      expect(result).not_to include('800.555')
    end

    it 'preserves surrounding text after scrubbing' do
      result = described_class.scrub('Hello user@example.com, welcome!')
      expect(result).to start_with('Hello ')
      expect(result).to end_with(', welcome!')
    end

    # --- New PII detectors ---

    it 'masks US passport numbers' do
      result = described_class.scrub('Passport: C12345678')
      expect(result).to include('[REDACTED_PASSPORT]')
      expect(result).not_to include('C12345678')
    end

    it 'masks multiple passport numbers' do
      result = described_class.scrub('Passports: A12345678 and B98765432')
      expect(result.scan('[REDACTED_PASSPORT]').length).to be >= 2
    end

    it 'masks IBAN numbers' do
      result = described_class.scrub('IBAN: GB29NWBK60161331926819')
      expect(result).to include('[REDACTED_IBAN]')
      expect(result).not_to include('GB29NWBK60161331926819')
    end

    it 'masks driver license numbers' do
      result = described_class.scrub('DL: D1234567')
      expect(result).not_to include('D1234567')
    end

    it 'masks driver license with 8 digits' do
      result = described_class.scrub('License: S12345678')
      expect(result).not_to include('S12345678')
    end

    it 'masks medical record numbers' do
      result = described_class.scrub('Record: MRN12345678')
      expect(result).to include('[REDACTED_MRN]')
      expect(result).not_to include('MRN12345678')
    end

    it 'masks MRN with varying digit lengths' do
      result = described_class.scrub('MRN1234 and MRN999999999')
      expect(result.scan('[REDACTED_MRN]').length).to eq(2)
    end

    it 'does not mask MRN with too few digits' do
      result = described_class.scrub('MRN123')
      expect(result).to eq('MRN123')
    end
  end

  describe '.scrub with mode: :partial' do
    it 'partially masks credit cards showing last 4' do
      result = described_class.scrub('Card: 4111-1111-1111-1111', mode: :partial)
      expect(result).to include('****1111')
    end

    it 'partially masks SSNs showing last 4' do
      result = described_class.scrub('SSN: 123-45-6789', mode: :partial)
      expect(result).to include('***-**-6789')
    end

    it 'partially masks phone numbers showing last 4' do
      result = described_class.scrub('Phone: 555-123-4567', mode: :partial)
      expect(result).to include('***-***-4567')
    end

    it 'partially masks emails showing first initial' do
      result = described_class.scrub('Email: user@example.com', mode: :partial)
      expect(result).to include('u***@example.com')
    end

    it 'partially masks IP addresses showing last octet' do
      result = described_class.scrub('IP: 192.168.1.42', mode: :partial)
      expect(result).to include('***.***.***.42')
    end

    it 'partially masks unknown patterns with first char visible' do
      described_class.configure do |c|
        c.add_pattern(:custom_id, /CUST-\d{8}/, replacement: 'CUST-XXXXXXXX')
      end
      result = described_class.scrub('ID: CUST-12345678', mode: :partial)
      expect(result).to include('C')
    end

    it 'leaves non-sensitive text unchanged in partial mode' do
      expect(described_class.scrub('Hello World', mode: :partial)).to eq('Hello World')
    end
  end

  describe '.scrub with mode: :format_preserving' do
    it 'replaces letters with X and digits with 0' do
      result = described_class.scrub('Email: user@example.com', mode: :format_preserving)
      expect(result).to include('XXXX@XXXXXXX.XXX')
    end

    it 'preserves separators in credit cards' do
      result = described_class.scrub('Card: 4111-1111-1111-1111', mode: :format_preserving)
      expect(result).to include('0000-0000-0000-0000')
    end

    it 'preserves SSN format' do
      result = described_class.scrub('SSN: 123-45-6789', mode: :format_preserving)
      expect(result).to include('000-00-0000')
    end

    it 'preserves IP address format with dots' do
      result = described_class.scrub('IP: 192.168.1.1', mode: :format_preserving)
      expect(result).to include('000.000.0.0')
    end

    it 'leaves non-sensitive text unchanged' do
      expect(described_class.scrub('Hello World', mode: :format_preserving)).to eq('Hello World')
    end

    it 'handles multiple PII types preserving their formats' do
      result = described_class.scrub('SSN: 123-45-6789 IP: 10.0.0.1', mode: :format_preserving)
      expect(result).to include('000-00-0000')
      expect(result).to include('00.0.0.0')
    end
  end

  describe '.tokenize' do
    it 'replaces PII with tokens' do
      result = described_class.tokenize('Email: user@example.com')
      expect(result[:masked]).to include('<TOKEN_EMAIL_1>')
      expect(result[:masked]).not_to include('user@example.com')
      expect(result[:tokens]).to have_key('<TOKEN_EMAIL_1>')
      expect(result[:tokens]['<TOKEN_EMAIL_1>']).to eq('user@example.com')
    end

    it 'generates unique tokens for each match' do
      result = described_class.tokenize('alice@test.com and bob@test.com')
      expect(result[:tokens].keys.length).to eq(2)
    end

    it 'tokenizes multiple PII types' do
      result = described_class.tokenize('Email: user@example.com SSN: 123-45-6789')
      expect(result[:tokens].keys.length).to eq(2)
      expect(result[:tokens].values).to include('user@example.com', '123-45-6789')
    end

    it 'returns empty tokens for non-sensitive text' do
      result = described_class.tokenize('Hello World')
      expect(result[:masked]).to eq('Hello World')
      expect(result[:tokens]).to be_empty
    end

    it 'handles nil input' do
      result = described_class.tokenize(nil)
      expect(result[:masked]).to be_nil
      expect(result[:tokens]).to be_empty
    end
  end

  describe '.detokenize' do
    it 'reverses tokenization' do
      original = 'Contact user@example.com for help'
      tokenized = described_class.tokenize(original)
      restored = described_class.detokenize(tokenized[:masked], tokens: tokenized[:tokens])
      expect(restored).to eq(original)
    end

    it 'reverses tokenization with multiple PII types' do
      original = 'Email: alice@test.com SSN: 111-22-3333'
      tokenized = described_class.tokenize(original)
      restored = described_class.detokenize(tokenized[:masked], tokens: tokenized[:tokens])
      expect(restored).to eq(original)
    end

    it 'returns the string unchanged with empty tokens' do
      result = described_class.detokenize('Hello World', tokens: {})
      expect(result).to eq('Hello World')
    end

    it 'does not modify the original string' do
      original = 'Contact user@example.com'
      tokenized = described_class.tokenize(original)
      masked_copy = tokenized[:masked].dup
      described_class.detokenize(tokenized[:masked], tokens: tokenized[:tokens])
      expect(tokenized[:masked]).to eq(masked_copy)
    end
  end

  describe '.scrub_with_audit' do
    it 'returns the scrubbed result' do
      result = described_class.scrub_with_audit('Email: user@example.com')
      expect(result[:result]).not_to include('user@example.com')
    end

    it 'includes audit entries with detector name' do
      result = described_class.scrub_with_audit('Email: user@example.com')
      expect(result[:audit].length).to eq(1)
      expect(result[:audit][0][:detector]).to eq(:email)
    end

    it 'includes original and masked values in audit' do
      result = described_class.scrub_with_audit('SSN: 123-45-6789')
      entry = result[:audit].find { |a| a[:detector] == :ssn }
      expect(entry[:original]).to eq('123-45-6789')
      expect(entry[:masked]).to eq('***-**-6789')
    end

    it 'includes position in audit entries' do
      result = described_class.scrub_with_audit('SSN: 123-45-6789')
      entry = result[:audit].find { |a| a[:detector] == :ssn }
      expect(entry[:position]).to eq(5)
    end

    it 'tracks multiple detections' do
      result = described_class.scrub_with_audit('Email: a@b.com SSN: 123-45-6789')
      expect(result[:audit].length).to eq(2)
      detectors = result[:audit].map { |a| a[:detector] }
      expect(detectors).to include(:email, :ssn)
    end

    it 'returns empty audit for clean strings' do
      result = described_class.scrub_with_audit('Hello World')
      expect(result[:result]).to eq('Hello World')
      expect(result[:audit]).to be_empty
    end

    it 'handles nil input' do
      result = described_class.scrub_with_audit(nil)
      expect(result[:result]).to be_nil
      expect(result[:audit]).to be_empty
    end

    it 'audits new PII types like passport' do
      result = described_class.scrub_with_audit('Passport: C12345678')
      entry = result[:audit].find { |a| a[:detector] == :passport }
      expect(entry).not_to be_nil
      expect(entry[:original]).to eq('C12345678')
    end

    it 'audits MRN detections' do
      result = described_class.scrub_with_audit('Record: MRN12345678')
      entry = result[:audit].find { |a| a[:detector] == :mrn }
      expect(entry).not_to be_nil
      expect(entry[:masked]).to eq('[REDACTED_MRN]')
    end
  end

  describe '.scrub_hash' do
    it 'scrubs string values in hashes' do
      result = described_class.scrub_hash({ email: 'user@example.com' })
      expect(result[:email]).not_to eq('user@example.com')
    end

    it 'scrubs nested hashes' do
      data = { user: { contact: { email: 'user@example.com' } } }
      result = described_class.scrub_hash(data)
      expect(result[:user][:contact][:email]).not_to eq('user@example.com')
    end

    it 'redacts sensitive key names' do
      data = { password: 'secret123', name: 'Alice' }
      result = described_class.scrub_hash(data)
      expect(result[:password]).to eq('[FILTERED]')
      expect(result[:name]).to eq('Alice')
    end

    it 'redacts token keys' do
      data = { api_key: 'sk-1234567890' }
      result = described_class.scrub_hash(data)
      expect(result[:api_key]).to eq('[FILTERED]')
    end

    it 'handles arrays in hashes' do
      data = { emails: ['user@example.com', 'admin@test.org'] }
      result = described_class.scrub_hash(data)
      result[:emails].each { |e| expect(e).not_to include('@example.com') }
    end

    it 'handles nil values' do
      data = { name: nil, email: 'user@example.com' }
      result = described_class.scrub_hash(data)
      expect(result[:name]).to be_nil
    end

    it 'handles numeric values' do
      data = { age: 30 }
      result = described_class.scrub_hash(data)
      expect(result[:age]).to eq(30)
    end

    it 'redacts all default sensitive key names' do
      data = {
        password: 'pw',
        secret: 's',
        token: 't',
        authorization: 'a',
        api_key: 'k',
        apikey: 'k2',
        access_token: 'at',
        refresh_token: 'rt',
        private_key: 'pk',
        secret_key: 'sk'
      }
      result = described_class.scrub_hash(data)
      data.each_key do |key|
        expect(result[key]).to eq('[FILTERED]')
      end
    end

    it 'handles deeply nested structures' do
      data = { level1: { level2: { level3: { email: 'deep@example.com' } } } }
      result = described_class.scrub_hash(data)
      expect(result[:level1][:level2][:level3][:email]).not_to include('deep@example.com')
    end

    it 'handles array of hashes' do
      data = { users: [{ password: 'pw1' }, { password: 'pw2' }] }
      result = described_class.scrub_hash(data)
      expect(result[:users][0][:password]).to eq('[FILTERED]')
      expect(result[:users][1][:password]).to eq('[FILTERED]')
    end

    it 'handles empty hash' do
      expect(described_class.scrub_hash({})).to eq({})
    end

    it 'handles empty array' do
      expect(described_class.scrub_hash([])).to eq([])
    end

    it 'handles boolean values without modification' do
      data = { active: true, deleted: false }
      result = described_class.scrub_hash(data)
      expect(result[:active]).to be(true)
      expect(result[:deleted]).to be(false)
    end

    it 'handles string keys for sensitive detection' do
      data = { 'password' => 'secret' }
      result = described_class.scrub_hash(data)
      expect(result['password']).to eq('[FILTERED]')
    end

    it 'is case-insensitive for sensitive key detection' do
      data = { 'Password' => 'secret', 'API_KEY' => 'key' }
      result = described_class.scrub_hash(data)
      expect(result['Password']).to eq('[FILTERED]')
      expect(result['API_KEY']).to eq('[FILTERED]')
    end

    it 'scrubs with custom sensitive keys' do
      data = { custom_field: 'sensitive_data', name: 'Alice' }
      result = described_class.scrub_hash(data, keys: [:custom_field])
      expect(result[:custom_field]).to eq('[FILTERED]')
      expect(result[:name]).to eq('Alice')
    end

    it 'scrubs PII in non-sensitive string values' do
      data = { notes: 'Contact user@example.com for details' }
      result = described_class.scrub_hash(data)
      expect(result[:notes]).not_to include('user@example.com')
    end

    it 'scrubs a top-level array of strings' do
      data = ['user@example.com', 'Hello']
      result = described_class.scrub_hash(data)
      expect(result[0]).not_to include('user@example.com')
      expect(result[1]).to eq('Hello')
    end

    it 'scrubs a top-level array of hashes' do
      data = [{ password: 'secret' }, { name: 'Bob' }]
      result = described_class.scrub_hash(data)
      expect(result[0][:password]).to eq('[FILTERED]')
      expect(result[1][:name]).to eq('Bob')
    end

    it 'handles float values without modification' do
      data = { score: 99.5 }
      result = described_class.scrub_hash(data)
      expect(result[:score]).to eq(99.5)
    end

    it 'handles symbol values without modification' do
      data = { status: :active }
      result = described_class.scrub_hash(data)
      expect(result[:status]).to eq(:active)
    end

    it 'does not modify the original hash' do
      data = { email: 'user@example.com' }
      original_email = data[:email]
      described_class.scrub_hash(data)
      expect(data[:email]).to eq(original_email)
    end

    it 'handles mixed arrays with non-string items' do
      data = { items: [42, nil, true, 'user@example.com'] }
      result = described_class.scrub_hash(data)
      expect(result[:items][0]).to eq(42)
      expect(result[:items][1]).to be_nil
      expect(result[:items][2]).to be(true)
      expect(result[:items][3]).not_to include('user@example.com')
    end

    it 'handles nested arrays within arrays' do
      data = { matrix: [['user@example.com', 'safe'], ['other@test.com']] }
      result = described_class.scrub_hash(data)
      expect(result[:matrix][0][0]).not_to include('user@example.com')
      expect(result[:matrix][0][1]).to eq('safe')
      expect(result[:matrix][1][0]).not_to include('other@test.com')
    end

    it 'custom keys parameter completely overrides default sensitive keys' do
      data = { password: 'secret', custom: 'hidden' }
      result = described_class.scrub_hash(data, keys: [:custom])
      expect(result[:password]).to eq('secret')
      expect(result[:custom]).to eq('[FILTERED]')
    end

    it 'handles hash with all nil values' do
      data = { a: nil, b: nil, c: nil }
      result = described_class.scrub_hash(data)
      expect(result).to eq({ a: nil, b: nil, c: nil })
    end

    it 'handles deeply nested sensitive keys' do
      data = { level1: { level2: { level3: { token: 'abc123' } } } }
      result = described_class.scrub_hash(data)
      expect(result[:level1][:level2][:level3][:token]).to eq('[FILTERED]')
    end

    it 'handles hash with integer keys' do
      data = { 1 => 'user@example.com', 2 => 'safe' }
      result = described_class.scrub_hash(data)
      expect(result[1]).not_to include('user@example.com')
      expect(result[2]).to eq('safe')
    end

    it 'scrubs PII inside arrays of strings at top level' do
      data = ['SSN: 123-45-6789', 'IP: 10.0.0.1']
      result = described_class.scrub_hash(data)
      expect(result[0]).to include('***-**-6789')
      expect(result[1]).to include('***.***.***.***')
    end
  end

  describe '.scrub_hash with mode: :partial' do
    it 'partially masks email values in hashes' do
      data = { contact: 'Email: user@example.com' }
      result = described_class.scrub_hash(data, mode: :partial)
      expect(result[:contact]).to include('u***@example.com')
    end

    it 'partially masks credit cards in nested hashes' do
      data = { payment: { card: '4111-1111-1111-1111' } }
      result = described_class.scrub_hash(data, mode: :partial)
      expect(result[:payment][:card]).to include('****1111')
    end

    it 'still filters sensitive keys regardless of mode' do
      data = { password: 'secret', name: 'Alice' }
      result = described_class.scrub_hash(data, mode: :partial)
      expect(result[:password]).to eq('[FILTERED]')
      expect(result[:name]).to eq('Alice')
    end
  end

  describe '.scrub_hash with mode: :format_preserving' do
    it 'format-preserves email values in hashes' do
      data = { contact: 'user@example.com' }
      result = described_class.scrub_hash(data, mode: :format_preserving)
      expect(result[:contact]).to include('XXXX@XXXXXXX.XXX')
    end

    it 'format-preserves SSNs in nested structures' do
      data = { person: { ssn: '123-45-6789' } }
      result = described_class.scrub_hash(data, mode: :format_preserving)
      expect(result[:person][:ssn]).to include('000-00-0000')
    end

    it 'still filters sensitive keys regardless of mode' do
      data = { token: 'abc123' }
      result = described_class.scrub_hash(data, mode: :format_preserving)
      expect(result[:token]).to eq('[FILTERED]')
    end
  end

  describe '.scrub_hash_with_audit' do
    it 'returns scrubbed result and audit trail' do
      data = { email: 'user@example.com', name: 'Alice' }
      result = described_class.scrub_hash_with_audit(data)
      expect(result[:result][:email]).not_to eq('user@example.com')
      expect(result[:result][:name]).to eq('Alice')
      expect(result[:audit]).not_to be_empty
    end

    it 'tracks PII detections with path' do
      data = { contact: 'user@example.com' }
      result = described_class.scrub_hash_with_audit(data)
      entry = result[:audit].find { |a| a[:detector] == :email }
      expect(entry).not_to be_nil
      expect(entry[:path]).to eq([:contact])
    end

    it 'tracks sensitive key redactions' do
      data = { password: 'secret123' }
      result = described_class.scrub_hash_with_audit(data)
      entry = result[:audit].find { |a| a[:detector] == :sensitive_key }
      expect(entry).not_to be_nil
      expect(entry[:key]).to eq('password')
      expect(entry[:masked]).to eq('[FILTERED]')
    end

    it 'tracks nested paths' do
      data = { user: { profile: { ssn: '123-45-6789' } } }
      result = described_class.scrub_hash_with_audit(data)
      entry = result[:audit].find { |a| a[:detector] == :ssn }
      expect(entry).not_to be_nil
      expect(entry[:path]).to eq(%i[user profile ssn])
    end

    it 'handles arrays in audit path' do
      data = { emails: ['user@example.com'] }
      result = described_class.scrub_hash_with_audit(data)
      entry = result[:audit].find { |a| a[:detector] == :email }
      expect(entry[:path]).to eq([:emails, 0])
    end

    it 'returns empty audit for clean data' do
      data = { name: 'Alice', age: 30 }
      result = described_class.scrub_hash_with_audit(data)
      expect(result[:audit]).to be_empty
    end
  end

  describe '.configure' do
    it 'adds custom patterns' do
      described_class.configure do |c|
        c.add_pattern(:custom_id, /CUST-\d{8}/, replacement: 'CUST-XXXXXXXX')
      end
      result = described_class.scrub('ID: CUST-12345678')
      expect(result).to include('CUST-XXXXXXXX')
    end

    it 'preserves built-in patterns after adding custom ones' do
      described_class.configure do |c|
        c.add_pattern(:custom, /CUSTOM/, replacement: '[CUSTOM]')
      end
      result = described_class.scrub('user@example.com and CUSTOM')
      expect(result).not_to include('user@example.com')
      expect(result).to include('[CUSTOM]')
    end

    it 'supports multiple custom patterns' do
      described_class.configure do |c|
        c.add_pattern(:order_id, /ORD-\d+/, replacement: 'ORD-XXXX')
        c.add_pattern(:ticket_id, /TKT-\d+/, replacement: 'TKT-XXXX')
      end
      result = described_class.scrub('Order ORD-12345 Ticket TKT-67890')
      expect(result).to include('ORD-XXXX')
      expect(result).to include('TKT-XXXX')
    end

    it 'supports DSL-style detect with block' do
      described_class.configure do |c|
        c.detect(:employee_id, /EMP\d{6}/) { |_match| '[EMPLOYEE_ID]' }
      end
      result = described_class.scrub('Employee: EMP123456')
      expect(result).to include('[EMPLOYEE_ID]')
      expect(result).not_to include('EMP123456')
    end

    it 'DSL detect block receives the matched string' do
      described_class.configure do |c|
        c.detect(:order, /ORD-\d+/) { |match| "MASKED(#{match.length})" }
      end
      result = described_class.scrub('Order: ORD-12345')
      expect(result).to include('MASKED(9)')
    end

    it 'supports mixing add_pattern and detect' do
      described_class.configure do |c|
        c.add_pattern(:static, /STATIC-\d+/, replacement: '[STATIC]')
        c.detect(:dynamic, /DYN-\d+/) { |_match| '[DYNAMIC]' }
      end
      result = described_class.scrub('STATIC-123 and DYN-456')
      expect(result).to include('[STATIC]')
      expect(result).to include('[DYNAMIC]')
    end

    it 'DSL detectors appear in patterns list' do
      described_class.configure do |c|
        c.detect(:employee_id, /EMP\d{6}/) { |_match| '[EMP]' }
      end
      config = Philiprehberger::Mask::Configuration.instance
      names = config.patterns.map { |p| p[:name] }
      expect(names).to include(:employee_id)
    end

    it 'DSL detectors work with scrub_hash' do
      described_class.configure do |c|
        c.detect(:badge, /BADGE-\d+/) { |_match| '[BADGE]' }
      end
      data = { info: 'See BADGE-999' }
      result = described_class.scrub_hash(data)
      expect(result[:info]).to include('[BADGE]')
    end
  end

  describe 'add_sensitive_key' do
    it 'adds a custom sensitive key via configure' do
      described_class.configure do |c|
        c.add_sensitive_key(:ssn_field)
      end
      data = { ssn_field: 'some-value' }
      result = described_class.scrub_hash(data)
      expect(result[:ssn_field]).to eq('[FILTERED]')
    end

    it 'preserves default sensitive keys after adding custom ones' do
      described_class.configure do |c|
        c.add_sensitive_key(:custom_secret)
      end
      data = { password: 'pw', custom_secret: 'val' }
      result = described_class.scrub_hash(data)
      expect(result[:password]).to eq('[FILTERED]')
      expect(result[:custom_secret]).to eq('[FILTERED]')
    end

    it 'handles string and symbol keys' do
      described_class.configure do |c|
        c.add_sensitive_key('my_token')
      end
      data = { my_token: 'value' }
      result = described_class.scrub_hash(data)
      expect(result[:my_token]).to eq('[FILTERED]')
    end

    it 'does not add duplicate keys' do
      described_class.configure do |c|
        c.add_sensitive_key(:password)
        c.add_sensitive_key(:password)
      end
      config = Philiprehberger::Mask::Configuration.instance
      count = config.sensitive_keys.count { |k| k == 'password' }
      expect(count).to eq(1)
    end

    it 'is cleared on reset' do
      described_class.configure do |c|
        c.add_sensitive_key(:custom_key)
      end
      described_class.reset_configuration!
      data = { custom_key: 'value' }
      result = described_class.scrub_hash(data)
      expect(result[:custom_key]).to eq('value')
    end
  end

  describe '.reset_configuration!' do
    it 'removes custom patterns' do
      described_class.configure do |c|
        c.add_pattern(:custom, /CUSTOM-\d+/, replacement: '[REDACTED]')
      end
      described_class.reset_configuration!
      result = described_class.scrub('CUSTOM-12345')
      expect(result).to eq('CUSTOM-12345')
    end

    it 'restores default sensitive keys after reset' do
      described_class.reset_configuration!
      data = { password: 'pw', token: 'tk' }
      result = described_class.scrub_hash(data)
      expect(result[:password]).to eq('[FILTERED]')
      expect(result[:token]).to eq('[FILTERED]')
    end

    it 'removes DSL-registered detectors after reset' do
      described_class.configure do |c|
        c.detect(:emp, /EMP\d+/) { |_| '[EMP]' }
      end
      described_class.reset_configuration!
      result = described_class.scrub('EMP123456')
      expect(result).to eq('EMP123456')
    end
  end

  describe '.batch_scrub' do
    it 'scrubs multiple strings in one call' do
      results = described_class.batch_scrub(['user@example.com', 'SSN: 123-45-6789'])
      expect(results[0]).not_to include('user@example.com')
      expect(results[1]).to include('***-**-6789')
    end

    it 'returns an array of the same length' do
      input = ['hello', 'world', 'test@test.com']
      results = described_class.batch_scrub(input)
      expect(results.length).to eq(3)
    end

    it 'preserves non-sensitive strings unchanged' do
      results = described_class.batch_scrub(%w[Hello World])
      expect(results).to eq(%w[Hello World])
    end

    it 'handles empty array' do
      expect(described_class.batch_scrub([])).to eq([])
    end

    it 'supports mode option' do
      results = described_class.batch_scrub(['Card: 4111-1111-1111-1111'], mode: :partial)
      expect(results[0]).to include('****1111')
    end

    it 'shares compiled patterns across all strings' do
      strings = Array.new(100) { 'user@example.com' }
      results = described_class.batch_scrub(strings)
      results.each { |r| expect(r).not_to include('user@example.com') }
    end

    it 'supports locale option' do
      described_class.add_locale(:de, { phone: /\b0\d{3}[- ]?\d{7,8}\b/ })
      results = described_class.batch_scrub(['Call 0301-1234567'], locale: :de)
      expect(results[0]).not_to include('0301-1234567')
    end
  end

  describe '.configure_priority' do
    it 'changes detector evaluation order' do
      described_class.configure_priority(%i[ssn email credit_card phone ip_address jwt passport iban drivers_license mrn])
      config = Philiprehberger::Mask::Configuration.instance
      names = config.patterns.map { |p| p[:name] }
      expect(names.first).to eq(:ssn)
    end

    it 'puts specified detectors first' do
      described_class.configure_priority(%i[phone email])
      config = Philiprehberger::Mask::Configuration.instance
      names = config.patterns.map { |p| p[:name] }
      expect(names[0]).to eq(:phone)
      expect(names[1]).to eq(:email)
    end

    it 'preserves unspecified detectors after prioritized ones' do
      described_class.configure_priority(%i[jwt])
      config = Philiprehberger::Mask::Configuration.instance
      names = config.patterns.map { |p| p[:name] }
      expect(names.first).to eq(:jwt)
      expect(names.length).to eq(10)
    end

    it 'still scrubs correctly after reordering' do
      described_class.configure_priority(%i[ssn email])
      result = described_class.scrub('SSN: 123-45-6789 email: a@b.com')
      expect(result).to include('***-**-6789')
      expect(result).not_to include('a@b.com')
    end

    it 'is cleared on reset' do
      described_class.configure_priority(%i[jwt])
      described_class.reset_configuration!
      config = Philiprehberger::Mask::Configuration.instance
      names = config.patterns.map { |p| p[:name] }
      expect(names.first).to eq(:email)
    end
  end

  describe '.add_locale' do
    it 'registers locale-specific patterns' do
      described_class.add_locale(:de, { phone: /\b0\d{3}[- ]?\d{7,8}\b/ })
      config = Philiprehberger::Mask::Configuration.instance
      expect(config.locales[:de]).to have_key(:phone)
    end

    it 'uses locale patterns when locale option is passed' do
      described_class.add_locale(:uk, { phone: /\b0\d{10}\b/ })
      result = described_class.scrub_io(StringIO.new("Call 02012345678\n"), locale: :uk)
      expect(result[0]).not_to include('02012345678')
    end

    it 'does not affect scrub without locale option' do
      described_class.add_locale(:fr, { phone: /\b0[1-9]\d{8}\b/ })
      described_class.scrub('Call 0612345678')
      # Without locale, the default phone detector may or may not match French format
      # The key thing is it uses default patterns, not locale ones
      config = Philiprehberger::Mask::Configuration.instance
      default_patterns = config.patterns
      locale_patterns = config.patterns(locale: :fr)
      expect(default_patterns).not_to eq(locale_patterns)
    end

    it 'supports multiple locales' do
      described_class.add_locale(:de, { phone: /\b0\d{3}[- ]?\d{7,8}\b/ })
      described_class.add_locale(:uk, { phone: /\b0\d{10}\b/ })
      config = Philiprehberger::Mask::Configuration.instance
      expect(config.locales.keys).to include(:de, :uk)
    end

    it 'is cleared on reset' do
      described_class.add_locale(:de, { phone: /\b0\d{3}[- ]?\d{7,8}\b/ })
      described_class.reset_configuration!
      config = Philiprehberger::Mask::Configuration.instance
      expect(config.locales).to be_empty
    end
  end

  describe '.scrub_io' do
    it 'scrubs lines from a StringIO' do
      io = StringIO.new("user@example.com\nHello World\n")
      results = described_class.scrub_io(io)
      expect(results.length).to eq(2)
      expect(results[0]).not_to include('user@example.com')
      expect(results[1]).to include('Hello World')
    end

    it 'handles empty IO' do
      io = StringIO.new('')
      expect(described_class.scrub_io(io)).to eq([])
    end

    it 'supports mode option' do
      io = StringIO.new("Card: 4111-1111-1111-1111\n")
      results = described_class.scrub_io(io, mode: :partial)
      expect(results[0]).to include('****1111')
    end

    it 'handles single line without trailing newline' do
      io = StringIO.new('SSN: 123-45-6789')
      results = described_class.scrub_io(io)
      expect(results.length).to eq(1)
      expect(results[0]).to include('***-**-6789')
    end

    it 'preserves line endings' do
      io = StringIO.new("user@example.com\ntest\n")
      results = described_class.scrub_io(io)
      expect(results[0]).to end_with("\n")
      expect(results[1]).to end_with("\n")
    end

    it 'scrubs multiple PII types across lines' do
      io = StringIO.new("Email: alice@test.com\nSSN: 123-45-6789\nIP: 10.0.0.1\n")
      results = described_class.scrub_io(io)
      expect(results[0]).not_to include('alice@test.com')
      expect(results[1]).to include('***-**-6789')
      expect(results[2]).to include('***.***.***.***')
    end
  end

  describe '.scrub_log' do
    it 'overwrites the file in-place when output is nil' do
      Tempfile.create(['mask_log', '.log']) do |f|
        f.write("user@example.com\nHello World\n")
        f.flush
        described_class.scrub_log(f.path)
        content = File.read(f.path)
        expect(content).not_to include('user@example.com')
        expect(content).to include('Hello World')
      end
    end

    it 'writes to the output path when output is provided' do
      source = Tempfile.new(['mask_src', '.log'])
      dest = Tempfile.new(['mask_dst', '.log'])
      begin
        source.write("SSN: 123-45-6789\n")
        source.flush
        described_class.scrub_log(source.path, output: dest.path)
        content = File.read(dest.path)
        expect(content).to include('***-**-6789')
        expect(content).not_to include('123-45-6789')
      ensure
        source.close
        source.unlink
        dest.close
        dest.unlink
      end
    end

    it 'returns a summary hash with correct keys' do
      Tempfile.create(['mask_log', '.log']) do |f|
        f.write("user@example.com\nHello World\n")
        f.flush
        result = described_class.scrub_log(f.path)
        expect(result).to have_key(:lines_processed)
        expect(result).to have_key(:lines_modified)
        expect(result).to have_key(:detections)
      end
    end

    it 'counts lines_processed correctly' do
      Tempfile.create(['mask_log', '.log']) do |f|
        f.write("user@example.com\nHello World\nSSN: 123-45-6789\n")
        f.flush
        result = described_class.scrub_log(f.path)
        expect(result[:lines_processed]).to eq(3)
      end
    end

    it 'counts lines_modified correctly' do
      Tempfile.create(['mask_log', '.log']) do |f|
        f.write("user@example.com\nHello World\nSSN: 123-45-6789\n")
        f.flush
        result = described_class.scrub_log(f.path)
        expect(result[:lines_modified]).to eq(2)
      end
    end

    it 'counts detections correctly' do
      Tempfile.create(['mask_log', '.log']) do |f|
        f.write("user@example.com\nSSN: 123-45-6789\n")
        f.flush
        result = described_class.scrub_log(f.path)
        expect(result[:detections]).to eq(2)
      end
    end

    it 'handles an empty file' do
      Tempfile.create(['mask_log', '.log']) do |f|
        result = described_class.scrub_log(f.path)
        expect(result[:lines_processed]).to eq(0)
        expect(result[:lines_modified]).to eq(0)
        expect(result[:detections]).to eq(0)
      end
    end

    it 'preserves clean lines unchanged in-place' do
      Tempfile.create(['mask_log', '.log']) do |f|
        f.write("Hello World\nFoo Bar\n")
        f.flush
        described_class.scrub_log(f.path)
        content = File.read(f.path)
        expect(content).to eq("Hello World\nFoo Bar\n")
      end
    end

    it 'supports mode option' do
      Tempfile.create(['mask_log', '.log']) do |f|
        f.write("Card: 4111-1111-1111-1111\n")
        f.flush
        described_class.scrub_log(f.path, mode: :partial)
        content = File.read(f.path)
        expect(content).to include('****1111')
      end
    end

    it 'supports locale option' do
      described_class.add_locale(:de, { phone: /\b0\d{3}[- ]?\d{7,8}\b/ })
      Tempfile.create(['mask_log', '.log']) do |f|
        f.write("Call 0301-1234567\n")
        f.flush
        described_class.scrub_log(f.path, locale: :de)
        content = File.read(f.path)
        expect(content).not_to include('0301-1234567')
      end
    end

    it 'does not modify the source file when output is provided' do
      source = Tempfile.new(['mask_src', '.log'])
      dest = Tempfile.new(['mask_dst', '.log'])
      begin
        original_content = "user@example.com\n"
        source.write(original_content)
        source.flush
        described_class.scrub_log(source.path, output: dest.path)
        expect(File.read(source.path)).to eq(original_content)
      ensure
        source.close
        source.unlink
        dest.close
        dest.unlink
      end
    end
  end

  describe 'Philiprehberger::Mask::Error' do
    it 'is a subclass of StandardError' do
      expect(Philiprehberger::Mask::Error.new).to be_a(StandardError)
    end
  end

  describe 'VERSION' do
    it 'follows semantic versioning format' do
      expect(described_class::VERSION).to match(/\A\d+\.\d+\.\d+\z/)
    end
  end

  describe 'Configuration' do
    it 'returns default sensitive keys' do
      config = Philiprehberger::Mask::Configuration.instance
      expect(config.sensitive_keys).to include('password', 'token', 'api_key')
    end

    it 'includes all expected default sensitive keys' do
      expected = %w[password secret token authorization api_key apikey access_token refresh_token private_key
                    secret_key]
      config = Philiprehberger::Mask::Configuration.instance
      expect(config.sensitive_keys).to match_array(expected)
    end

    it 'returns builtin plus custom patterns from patterns method' do
      described_class.configure do |c|
        c.add_pattern(:test_pat, /TEST/, replacement: '[TEST]')
      end
      config = Philiprehberger::Mask::Configuration.instance
      names = config.patterns.map { |p| p[:name] }
      expect(names).to include(:email, :credit_card, :ssn, :phone, :ip_address, :jwt, :test_pat)
    end
  end

  describe 'Detector' do
    it 'returns exactly 10 builtin patterns' do
      patterns = Philiprehberger::Mask::Detector.builtin_patterns
      expect(patterns.length).to eq(10)
    end

    it 'each builtin pattern has name, pattern, and replacer keys' do
      Philiprehberger::Mask::Detector.builtin_patterns.each do |pat|
        expect(pat).to have_key(:name)
        expect(pat).to have_key(:pattern)
        expect(pat).to have_key(:replacer)
        expect(pat[:pattern]).to be_a(Regexp)
        expect(pat[:replacer]).to respond_to(:call)
      end
    end

    it 'includes new detector types' do
      names = Philiprehberger::Mask::Detector.builtin_patterns.map { |p| p[:name] }
      expect(names).to include(:passport, :iban, :drivers_license, :mrn)
    end
  end

  describe 'custom patterns with scrub_hash' do
    it 'applies custom patterns inside deep structures' do
      described_class.configure do |c|
        c.add_pattern(:account, /ACCT-\d+/, replacement: 'ACCT-XXXX')
      end
      data = { info: { ref: 'See ACCT-999' } }
      result = described_class.scrub_hash(data)
      expect(result[:info][:ref]).to include('ACCT-XXXX')
      expect(result[:info][:ref]).not_to include('ACCT-999')
    end
  end
end
