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
    # @return [String] the scrubbed string
    def self.scrub(string)
      Scrubber.call(string, patterns: Configuration.instance.patterns)
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
