# frozen_string_literal: true

module Philiprehberger
  module Mask
    # Recursively scrub sensitive data in hashes and arrays
    module DeepScrubber
      FILTERED = '[FILTERED]'

      # Deep-walk and scrub a data structure
      #
      # Hashes and Arrays are recursed, Strings are pattern-scrubbed, and
      # +Struct+/+Data+/+to_h+-able objects are converted to a scrubbed Hash.
      #
      # @param data [Hash, Array, Object] the input
      # @param patterns [Array<Hash>] pattern definitions
      # @param sensitive_keys [Array<Symbol, String>] key names to fully redact
      # @param mode [Symbol] masking mode (:full, :partial, :format_preserving)
      # @param reveal [Integer] trailing characters to keep in :partial mode
      # @param placeholder [String] replacement for sensitive-key values
      # @return [Object] the scrubbed data (Struct/Data become a Hash)
      def self.call(data, patterns:, sensitive_keys:, mode: :full, reveal: 4, placeholder: FILTERED)
        walk(data, patterns, normalize_keys(sensitive_keys), mode, reveal, placeholder)
      end

      # Deep-walk and scrub with audit trail
      #
      # @param data [Hash, Array, Object] the input
      # @param patterns [Array<Hash>] pattern definitions
      # @param sensitive_keys [Array<Symbol, String>] key names to fully redact
      # @param placeholder [String] replacement for sensitive-key values
      # @return [Hash] { result:, audit: [...] }
      def self.call_with_audit(data, patterns:, sensitive_keys:, placeholder: FILTERED)
        audit = []
        result = walk_with_audit(data, patterns, normalize_keys(sensitive_keys), audit, placeholder)
        { result: result, audit: audit }
      end

      def self.walk(data, patterns, keys, mode, reveal, placeholder)
        case data
        when Hash then scrub_hash(data, patterns, keys, mode, reveal, placeholder)
        when Array then data.map { |item| walk(item, patterns, keys, mode, reveal, placeholder) }
        when String then Scrubber.call(data, patterns: patterns, mode: mode, reveal: reveal)
        else
          convertible?(data) ? scrub_hash(to_hash(data), patterns, keys, mode, reveal, placeholder) : data
        end
      end
      private_class_method :walk

      def self.walk_with_audit(data, patterns, keys, audit, placeholder, path: [])
        case data
        when Hash then scrub_hash_with_audit(data, patterns, keys, audit, placeholder, path)
        when Array
          data.each_with_index.map { |item, i| walk_with_audit(item, patterns, keys, audit, placeholder, path: path + [i]) }
        when String
          result = Scrubber.call_with_audit(data, patterns: patterns)
          result[:audit].each { |entry| entry[:path] = path }
          audit.concat(result[:audit])
          result[:result]
        else
          if convertible?(data)
            scrub_hash_with_audit(to_hash(data), patterns, keys, audit, placeholder, path)
          else
            data
          end
        end
      end
      private_class_method :walk_with_audit

      def self.scrub_hash(hash, patterns, keys, mode, reveal, placeholder)
        hash.each_with_object({}) do |(key, value), result|
          result[key] = if sensitive_key?(key, keys)
                          placeholder
                        else
                          walk(value, patterns, keys, mode, reveal, placeholder)
                        end
        end
      end
      private_class_method :scrub_hash

      def self.scrub_hash_with_audit(hash, patterns, keys, audit, placeholder, path)
        hash.each_with_object({}) do |(key, value), result|
          if sensitive_key?(key, keys)
            audit << { detector: :sensitive_key, key: key.to_s, path: path + [key], masked: placeholder }
            result[key] = placeholder
          else
            result[key] = walk_with_audit(value, patterns, keys, audit, placeholder, path: path + [key])
          end
        end
      end
      private_class_method :scrub_hash_with_audit

      # A Struct, Ruby 3.2+ Data, or any +to_h+-able object (excluding +nil+)
      # is convertible to a Hash for deep scrubbing.
      def self.convertible?(data)
        return false if data.nil?
        return true if data.is_a?(Struct)
        return true if defined?(Data) && data.is_a?(Data)

        data.respond_to?(:to_h)
      end
      private_class_method :convertible?

      def self.to_hash(data)
        data.to_h
      end
      private_class_method :to_hash

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
