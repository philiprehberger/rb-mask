# frozen_string_literal: true

require 'tempfile'
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
    # @example Mask an email in a string
    #   Philiprehberger::Mask.scrub('Contact user@example.com')
    #   # => "Contact u***@e******.com"
    def self.scrub(string, mode: :full)
      Scrubber.call(string, patterns: Configuration.instance.patterns, mode: mode)
    end

    # Scan a string for PII without modifying it
    #
    # Returns the list of detector matches in detection order. Each entry has
    # +:detector+, +:match+, and +:position+. Useful for "should this be
    # redacted?" checks before the cost of substitution. The input string is
    # not mutated.
    #
    # @param string [String] the input string
    # @param locale [Symbol, nil] optional locale for locale-specific patterns
    # @return [Array<Hash>] [{ detector:, match:, position: }, ...] (empty when no PII)
    # @example Detect PII without redacting
    #   Philiprehberger::Mask.detect('Email user@example.com or call 555-123-4567')
    #   # => [{ detector: :email, match: "user@example.com", position: 6 },
    #   #     { detector: :phone, match: "555-123-4567", position: 31 }]
    def self.detect(string, locale: nil)
      Scrubber.scan(string, patterns: Configuration.instance.patterns(locale: locale))
    end

    # Deep-walk a hash/array and redact sensitive values
    #
    # @param data [Hash, Array] the input structure
    # @param keys [Array<Symbol, String>, nil] specific keys to scrub
    # @param mode [Symbol] masking mode (:full, :partial, :format_preserving)
    # @return [Hash, Array] the scrubbed structure
    # @example Redact sensitive keys and PII inside nested structures
    #   Philiprehberger::Mask.scrub_hash(user: { email: 'a@b.com', password: 'secret' })
    #   # => { user: { email: "a***@b.com", password: "[FILTERED]" } }
    def self.scrub_hash(data, keys: nil, mode: :full)
      config = Configuration.instance
      DeepScrubber.call(data, patterns: config.patterns, sensitive_keys: keys || config.sensitive_keys, mode: mode)
    end

    # Deep-walk a hash/array and redact sensitive values with audit trail
    #
    # @param data [Hash, Array] the input structure
    # @param keys [Array<Symbol, String>, nil] specific keys to scrub
    # @return [Hash] { result:, audit: [{detector:, ...}] }
    def self.scrub_hash_with_audit(data, keys: nil)
      config = Configuration.instance
      DeepScrubber.call_with_audit(data, patterns: config.patterns, sensitive_keys: keys || config.sensitive_keys)
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
    # @example Replace PII with reversible tokens
    #   result = Philiprehberger::Mask.tokenize('Contact user@example.com')
    #   # => { masked: "Contact <TOKEN_EMAIL_1>", tokens: { "<TOKEN_EMAIL_1>" => "user@example.com" } }
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

    # Process an array of strings in one call with shared compiled patterns
    #
    # Raises ArgumentError when +strings+ is not an Array. An empty Array returns +[]+.
    #
    # @param strings [Array<String>] input strings
    # @param mode [Symbol] masking mode (:full, :partial, :format_preserving)
    # @param locale [Symbol, nil] optional locale for locale-specific patterns
    # @return [Array<String>] scrubbed strings (empty Array for empty input)
    # @raise [ArgumentError] if +strings+ is not an Array
    # @example Scrub several strings at once
    #   Philiprehberger::Mask.batch_scrub(['user@example.com', 'SSN: 123-45-6789'])
    #   # => ["u***@e******.com", "SSN: ***-**-6789"]
    def self.batch_scrub(strings, mode: :full, locale: nil)
      raise ArgumentError, 'strings must be an Array' unless strings.is_a?(Array)

      patterns = Configuration.instance.patterns(locale: locale)
      compiled = patterns.map { |pat| pat.merge(pattern: Regexp.new(pat[:pattern].source, pat[:pattern].options)) }
      strings.map { |s| Scrubber.call(s, patterns: compiled, mode: mode) }
    end

    # Set detector evaluation priority
    #
    # @param detector_order [Array<Symbol>] detector names in desired order
    def self.configure_priority(detector_order)
      Configuration.instance.set_priority(detector_order)
    end

    # Register locale-specific patterns
    #
    # @param locale [Symbol] locale identifier
    # @param patterns [Hash<Symbol, Regexp>] detector name to regex mapping
    def self.add_locale(locale, patterns)
      Configuration.instance.add_locale(locale, patterns)
    end

    # Read from IO line by line, scrub each line
    #
    # Raises ArgumentError when +io+ is nil. An IO that is already at EOF (or empty)
    # returns an empty Array rather than raising.
    #
    # @param io [IO, StringIO] readable IO object
    # @param mode [Symbol] masking mode (:full, :partial, :format_preserving)
    # @param locale [Symbol, nil] optional locale for locale-specific patterns
    # @return [Array<String>] scrubbed lines (empty Array when the IO is at EOF)
    # @raise [ArgumentError] if +io+ is nil
    # @example Scrub lines from an in-memory IO
    #   Philiprehberger::Mask.scrub_io(StringIO.new("user@example.com\n"))
    #   # => ["u***@e******.com\n"]
    def self.scrub_io(io, mode: :full, locale: nil)
      raise ArgumentError, 'io is required' if io.nil?
      return [] if io.respond_to?(:eof?) && io.eof?

      patterns = Configuration.instance.patterns(locale: locale)
      io.each_line.map { |line| Scrubber.call(line, patterns: patterns, mode: mode) }
    end

    # Read a file line by line, scrub each line, and write the result
    #
    # @param path [String] path to the file to scrub
    # @param output [String, nil] destination path; overwrites in-place if nil
    # @param mode [Symbol] masking mode (:full, :partial, :format_preserving)
    # @param locale [Symbol, nil] optional locale for locale-specific patterns
    # @return [Hash] { lines_processed:, lines_modified:, detections: }
    def self.scrub_log(path, output: nil, mode: :full, locale: nil)
      patterns = Configuration.instance.patterns(locale: locale)
      lines_processed = 0
      lines_modified = 0
      detections = 0

      scrubbed_lines = File.open(path, 'r') do |f|
        f.each_line.map do |line|
          lines_processed += 1
          scrubbed = Scrubber.call(line, patterns: patterns, mode: mode)
          if scrubbed != line
            lines_modified += 1
            detections += Scrubber.call_with_audit(line, patterns: patterns)[:audit].length
          end
          scrubbed
        end
      end

      if output.nil?
        Tempfile.open([File.basename(path), '.tmp'], File.dirname(path)) do |tmp|
          tmp.write(scrubbed_lines.join)
          tmp.flush
          File.rename(tmp.path, path)
        end
      else
        File.write(output, scrubbed_lines.join)
      end

      { lines_processed: lines_processed, lines_modified: lines_modified, detections: detections }
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
