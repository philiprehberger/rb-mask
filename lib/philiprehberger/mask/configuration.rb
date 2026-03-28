# frozen_string_literal: true

module Philiprehberger
  module Mask
    # Thread-safe configuration for custom patterns
    class Configuration
      DEFAULT_SENSITIVE_KEYS = %w[
        password secret token authorization api_key apikey
        access_token refresh_token private_key secret_key
      ].freeze

      attr_reader :sensitive_keys

      def initialize
        @mutex = Mutex.new
        @custom_patterns = []
        @sensitive_keys = DEFAULT_SENSITIVE_KEYS.dup
      end

      # Add a custom pattern with a static replacement string
      #
      # @param name [Symbol] pattern name
      # @param pattern [Regexp] the regex pattern
      # @param replacement [String] the replacement string
      def add_pattern(name, pattern, replacement:)
        @mutex.synchronize do
          @custom_patterns << { name: name, pattern: pattern, replacer: ->(_) { replacement } }
        end
      end

      # Register a custom detector with a block-based replacer (DSL)
      #
      # @param name [Symbol] pattern name
      # @param pattern [Regexp] the regex pattern
      # @yield [match] the matched string
      # @yieldreturn [String] the replacement
      def detect(name, pattern, &block)
        @mutex.synchronize do
          @custom_patterns << { name: name, pattern: pattern, replacer: block }
        end
      end

      # All patterns (built-in + custom)
      #
      # @return [Array<Hash>]
      def patterns
        @mutex.synchronize { Detector.builtin_patterns + @custom_patterns }
      end

      @instance_mutex = Mutex.new

      def self.instance
        @instance_mutex.synchronize { @instance ||= new }
      end

      def self.reset!
        @instance_mutex.synchronize { @instance = new }
      end
    end
  end
end
