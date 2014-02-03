# frozen_string_literal: true

module Philiprehberger
  module Mask
    # Scrub sensitive patterns from strings
    module Scrubber
      # Apply all patterns to a string
      #
      # @param string [String] the input string
      # @param patterns [Array<Hash>] pattern definitions
      # @return [String] the scrubbed string
      def self.call(string, patterns:)
        return string unless string.is_a?(String)

        result = string.dup
        patterns.each do |pat|
          result = result.gsub(pat[:pattern]) { |match| pat[:replacer].call(match) }
        end
        result
      end
    end
  end
end
