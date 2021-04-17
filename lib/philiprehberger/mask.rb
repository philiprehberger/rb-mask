# frozen_string_literal: true

require_relative 'mask/version'
require_relative 'mask/configuration'
require_relative 'mask/detector'
require_relative 'mask/scrubber'
require_relative 'mask/deep_scrubber'

module Philiprehberger
  module Mask
    class Error < StandardError; end

    # Detect and redact PII patterns in a string
    #
    # @param string [String] the input string
    # @param mode [Symbol] masking mode (:full, :partial, :format_preserving)
    # @return [String] the scrubbed string
    def self.scrub(string, mode: :full)
      Scrubber.call(string, patterns: Configuration.instance.patterns, mode: mode)
    end

    # Deep-walk a hash/array and redact sensitive values
    #
    # @param data [Hash, Array] the input structure
    # @param keys [Array<Symbol, String>, nil] specific keys to scrub
    # @return [Hash, Array] the scrubbed structure
    def self.scrub_hash(data, keys: nil)
      config = Configuration.instance
      DeepScrubber.call(data, patterns: config.patterns, sensitive_keys: keys || config.sensitive_keys)
    end

    # Scrub a string and return an audit trail of what was masked
    #
    # @param string [String] the input string
    # @return [Hash] { result:, audit: [{detector:, original:, masked:, position:}] }
    def self.scrub_with_audit(string)
      Scrubber.call_with_audit(string, patterns: Configuration.instance.patterns)
    end

    # Replace PII with reversible tokens
    #
    # @param string [String] the input string
    # @return [Hash] { masked:, tokens: {} }
    def self.tokenize(string)
      Scrubber.call_with_tokens(string, patterns: Configuration.instance.patterns)
    end

    # Reverse tokenization using a token lookup table
    #
    # @param string [String] the tokenized string
    # @param tokens [Hash] token-to-original mapping
    # @return [String] the restored string
    def self.detokenize(string, tokens:)
      result = string.dup
      tokens.each { |token, original| result = result.gsub(token, original) }
      result
    end

    # Configure custom patterns
    #
    # @yield [Configuration] the configuration instance
    def self.configure(&block)
      block.call(Configuration.instance)
    end

    # Reset configuration to defaults
    def self.reset_configuration!
      Configuration.reset!
    end
  end
end
