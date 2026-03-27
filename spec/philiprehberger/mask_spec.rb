# frozen_string_literal: true

require 'spec_helper'

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

    # --- Expanded tests ---

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

    # --- Expanded tests ---

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

  describe '.configure' do
    it 'adds custom patterns' do
      described_class.configure do |c|
        c.add_pattern(:custom_id, /CUST-\d{8}/, replacement: 'CUST-XXXXXXXX')
      end
      result = described_class.scrub('ID: CUST-12345678')
      expect(result).to include('CUST-XXXXXXXX')
    end

    # --- Expanded tests ---

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
    it 'returns exactly 6 builtin patterns' do
      patterns = Philiprehberger::Mask::Detector.builtin_patterns
      expect(patterns.length).to eq(6)
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
