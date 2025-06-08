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
      # @param mode [Symbol] masking mode (:full, :partial, :format_preserving)
      # @return [Object] the scrubbed data
      def self.call(data, patterns:, sensitive_keys:, mode: :full)
        walk(data, patterns, normalize_keys(sensitive_keys), mode)
      end

      # Deep-walk and scrub with audit trail
      #
      # @param data [Hash, Array, Object] the input
      # @param patterns [Array<Hash>] pattern definitions
      # @param sensitive_keys [Array<Symbol, String>] key names to fully redact
      # @return [Hash] { result:, audit: [...] }
      def self.call_with_audit(data, patterns:, sensitive_keys:)
        audit = []
        result = walk_with_audit(data, patterns, normalize_keys(sensitive_keys), audit)
        { result: result, audit: audit }
      end

      def self.walk(data, patterns, keys, mode)
        case data
        when Hash then scrub_hash(data, patterns, keys, mode)
        when Array then data.map { |item| walk(item, patterns, keys, mode) }
        when String then Scrubber.call(data, patterns: patterns, mode: mode)
        else data
        end
      end
      private_class_method :walk

      def self.walk_with_audit(data, patterns, keys, audit, path: [])
        case data
        when Hash then scrub_hash_with_audit(data, patterns, keys, audit, path)
        when Array
          data.each_with_index.map { |item, i| walk_with_audit(item, patterns, keys, audit, path: path + [i]) }
        when String
          result = Scrubber.call_with_audit(data, patterns: patterns)
          result[:audit].each { |entry| entry[:path] = path }
          audit.concat(result[:audit])
          result[:result]
        else data
        end
      end
      private_class_method :walk_with_audit

      def self.scrub_hash(hash, patterns, keys, mode)
        hash.each_with_object({}) do |(key, value), result|
          result[key] = sensitive_key?(key, keys) ? FILTERED : walk(value, patterns, keys, mode)
        end
      end
      private_class_method :scrub_hash

      def self.scrub_hash_with_audit(hash, patterns, keys, audit, path)
        hash.each_with_object({}) do |(key, value), result|
          if sensitive_key?(key, keys)
            audit << { detector: :sensitive_key, key: key.to_s, path: path + [key], masked: FILTERED }
            result[key] = FILTERED
          else
            result[key] = walk_with_audit(value, patterns, keys, audit, path: path + [key])
          end
        end
      end
      private_class_method :scrub_hash_with_audit

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
