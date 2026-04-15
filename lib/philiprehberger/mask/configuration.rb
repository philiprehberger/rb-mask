# frozen_string_literal: true

module Philiprehberger
  module Mask
    # Thread-safe configuration for custom patterns
    class Configuration
      DEFAULT_SENSITIVE_KEYS = %w[
        password secret token authorization api_key apikey
        access_token refresh_token private_key secret_key
      ].freeze

      attr_reader :sensitive_keys, :detector_priority, :locales

      def initialize
        @mutex = Mutex.new
        @custom_patterns = []
        @sensitive_keys = DEFAULT_SENSITIVE_KEYS.dup
        @detector_priority = nil
        @locales = {}
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

      # Add a custom sensitive key name
      #
      # @param key [Symbol, String] key name to treat as sensitive
      def add_sensitive_key(key)
        @mutex.synchronize do
          normalized = key.to_s.downcase
          @sensitive_keys << normalized unless @sensitive_keys.include?(normalized)
        end
      end

      # Set detector evaluation priority
      #
      # @param order [Array<Symbol>] detector names in desired evaluation order
      def set_priority(order)
        @mutex.synchronize { @detector_priority = order.map(&:to_sym) }
      end

      # Register locale-specific patterns
      #
      # @param locale [Symbol] locale identifier
      # @param patterns_hash [Hash<Symbol, Regexp>] detector name to regex mapping
      def add_locale(locale, patterns_hash)
        @mutex.synchronize do
          @locales[locale.to_sym] = patterns_hash.each_with_object({}) do |(name, regex), hash|
            hash[name.to_sym] = regex
          end
        end
      end

      # All patterns (built-in + custom), optionally reordered by priority
      #
      # @param locale [Symbol, nil] optional locale for locale-specific patterns
      # @return [Array<Hash>]
      def patterns(locale: nil)
        @mutex.synchronize do
          base = Detector.builtin_patterns + @custom_patterns
          base = apply_locale(base, locale) if locale && @locales.key?(locale)
          @detector_priority ? reorder(base, @detector_priority) : base
        end
      end

      private

      def reorder(patterns_list, order)
        by_name = patterns_list.group_by { |p| p[:name] }
        ordered = order.flat_map { |name| by_name.delete(name) || [] }
        ordered + by_name.values.flatten(1)
      end

      def apply_locale(base, locale)
        locale_patterns = @locales[locale]
        base.map do |pat|
          if locale_patterns.key?(pat[:name])
            pat.merge(pattern: locale_patterns[pat[:name]])
          else
            pat
          end
        end
      end

      @instance_mutex = Mutex.new

      class << self
        def instance
          @instance_mutex.synchronize { @instance ||= new }
        end

        def reset!
          @instance_mutex.synchronize { @instance = new }
        end
      end
    end
  end
end
