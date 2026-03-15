# frozen_string_literal: true

module Philiprehberger
  module Mask
    # Recursively scrub sensitive data in hashes and arrays
    module DeepScrubber
      FILTERED = '[FILTERED]'

      # Deep-walk and scrub a data structure
      #
      # @param data [Hash, Array, Object] the input
      # @param patterns [Array<Hash>] pattern definitions
      # @param sensitive_keys [Array<Symbol, String>] key names to fully redact
      # @return [Object] the scrubbed data
      def self.call(data, patterns:, sensitive_keys:)
        walk(data, patterns, normalize_keys(sensitive_keys))
      end

      def self.walk(data, patterns, keys)
        case data
        when Hash then scrub_hash(data, patterns, keys)
        when Array then data.map { |item| walk(item, patterns, keys) }
        when String then Scrubber.call(data, patterns: patterns)
        else data
        end
      end
      private_class_method :walk

      def self.scrub_hash(hash, patterns, keys)
        hash.each_with_object({}) do |(key, value), result|
          result[key] = sensitive_key?(key, keys) ? FILTERED : walk(value, patterns, keys)
        end
      end
      private_class_method :scrub_hash

      def self.sensitive_key?(key, keys)
        keys.include?(key.to_s.downcase)
      end
      private_class_method :sensitive_key?

      def self.normalize_keys(keys)
        keys.map { |k| k.to_s.downcase }
      end
      private_class_method :normalize_keys
    end
  end
end
