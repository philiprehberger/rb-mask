# frozen_string_literal: true

module Philiprehberger
  module Mask
    # Scrub sensitive patterns from strings
    module Scrubber
      # Apply all patterns to a string
      #
      # @param string [String] the input string
      # @param patterns [Array<Hash>] pattern definitions
      # @param mode [Symbol] masking mode (:full, :partial, :format_preserving)
      # @param reveal [Integer] number of trailing characters to keep in :partial mode
      # @return [String] the scrubbed string
      def self.call(string, patterns:, mode: :full, reveal: 4)
        return string unless string.is_a?(String)

        result = string.dup
        patterns.each do |pat|
          result = result.gsub(pat[:pattern]) do |match|
            guarded?(pat, match) ? match : apply_mode(match, pat, mode, reveal)
          end
        end
        result
      end

      # Scan a string for matches without modifying it
      #
      # @param string [String] the input string
      # @param patterns [Array<Hash>] pattern definitions
      # @return [Array<Hash>] [{ detector:, match:, position: }, ...] in detection order
      def self.scan(string, patterns:)
        return [] unless string.is_a?(String)

        results = []
        patterns.each do |pat|
          string.scan(pat[:pattern]) do |_|
            md = Regexp.last_match
            next if guarded?(pat, md[0])

            results << { detector: pat[:name], match: md[0], position: md.begin(0) }
          end
        end
        results
      end

      # Apply all patterns and collect audit trail
      #
      # @param string [String] the input string
      # @param patterns [Array<Hash>] pattern definitions
      # @return [Hash] { result:, audit: [...] }
      def self.call_with_audit(string, patterns:)
        return { result: string, audit: [] } unless string.is_a?(String)

        audit = []
        result = string.dup
        patterns.each do |pat|
          result = result.gsub(pat[:pattern]) do |match|
            next match if guarded?(pat, match)

            masked = pat[:replacer].call(match)
            audit << {
              detector: pat[:name],
              original: match,
              masked: masked,
              position: Regexp.last_match&.begin(0)
            }
            masked
          end
        end
        { result: result, audit: audit }
      end

      # Apply all patterns and return tokenized result
      #
      # @param string [String] the input string
      # @param patterns [Array<Hash>] pattern definitions
      # @return [Hash] { masked:, tokens: {} }
      def self.call_with_tokens(string, patterns:)
        return { masked: string, tokens: {} } unless string.is_a?(String)

        tokens = {}
        counter = 0
        result = string.dup
        patterns.each do |pat|
          result = result.gsub(pat[:pattern]) do |match|
            next match if guarded?(pat, match)

            counter += 1
            token = "<TOKEN_#{pat[:name].to_s.upcase}_#{counter}>"
            tokens[token] = match
            token
          end
        end
        { masked: result, tokens: tokens }
      end

      # A guarded pattern (e.g. Luhn-gated credit_card) that rejects the
      # candidate is left untouched and not reported.
      def self.guarded?(pat, match)
        guard = pat[:guard]
        !guard.nil? && !guard.call(match)
      end
      private_class_method :guarded?

      def self.apply_mode(match, pat, mode, reveal)
        case mode
        when :full
          pat[:replacer].call(match)
        when :partial
          partial_mask(match, pat[:name], reveal)
        when :format_preserving
          format_preserving_mask(match)
        else
          pat[:replacer].call(match)
        end
      end
      private_class_method :apply_mode

      def self.partial_mask(match, name, reveal)
        case name
        when :credit_card
          digits = match.gsub(/\D/, '')
          "****#{digits[-reveal..]}"
        when :ssn
          "***-**-#{match[-reveal..]}"
        when :phone
          "***-***-#{match[-reveal..]}"
        when :email
          local, domain = match.split('@', 2)
          "#{local[0]}***@#{domain}"
        when :ip_address
          parts = match.split('.')
          "***.***.***.#{parts.last}"
        else
          match[0..0] + ('*' * (match.length - 1))
        end
      end
      private_class_method :partial_mask

      def self.format_preserving_mask(match)
        match.gsub(/[a-zA-Z]/, 'X').gsub(/[0-9]/, '0')
      end
      private_class_method :format_preserving_mask
    end
  end
end
