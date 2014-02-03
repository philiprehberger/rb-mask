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
  end

  describe '.configure' do
    it 'adds custom patterns' do
      described_class.configure do |c|
        c.add_pattern(:custom_id, /CUST-\d{8}/, replacement: 'CUST-XXXXXXXX')
      end
      result = described_class.scrub('ID: CUST-12345678')
      expect(result).to include('CUST-XXXXXXXX')
    end
  end
end
