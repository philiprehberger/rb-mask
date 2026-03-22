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
  end
end
