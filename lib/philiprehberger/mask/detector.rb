# frozen_string_literal: true

module Philiprehberger
  module Mask
    # Built-in pattern detectors for common PII types
    module Detector
      def self.builtin_patterns
        [
          email_pattern, credit_card_pattern, ssn_pattern, phone_pattern,
          ip_pattern, jwt_pattern, passport_pattern, iban_pattern,
          drivers_license_pattern, mrn_pattern
        ]
      end

      def self.email_pattern
        {
          name: :email,
          pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
          replacer: ->(match) { mask_email(match) }
        }
      end
      private_class_method :email_pattern

      def self.credit_card_pattern
        {
          name: :credit_card,
          pattern: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b/,
          replacer: ->(match) { mask_card(match) }
        }
      end
      private_class_method :credit_card_pattern

      def self.ssn_pattern
        {
          name: :ssn,
          pattern: /\b\d{3}-\d{2}-\d{4}\b/,
          replacer: ->(match) { "***-**-#{match[-4..]}" }
        }
      end
      private_class_method :ssn_pattern

      def self.phone_pattern
        {
          name: :phone,
          pattern: /\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/,
          replacer: ->(match) { "***-***-#{match[-4..]}" }
        }
      end
      private_class_method :phone_pattern

      def self.ip_pattern
        {
          name: :ip_address,
          pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
          replacer: ->(_match) { '***.***.***.***' }
        }
      end
      private_class_method :ip_pattern

      def self.jwt_pattern
        {
          name: :jwt,
          pattern: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
          replacer: ->(_match) { '[REDACTED_JWT]' }
        }
      end
      private_class_method :jwt_pattern

      def self.passport_pattern
        {
          name: :passport,
          pattern: /\b[A-Z]\d{8}\b/,
          replacer: ->(_match) { '[REDACTED_PASSPORT]' }
        }
      end
      private_class_method :passport_pattern

      def self.iban_pattern
        {
          name: :iban,
          pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/,
          replacer: ->(_match) { '[REDACTED_IBAN]' }
        }
      end
      private_class_method :iban_pattern

      def self.drivers_license_pattern
        {
          name: :drivers_license,
          pattern: /\b[A-Z]\d{6,8}\b/,
          replacer: ->(_match) { '[REDACTED_DL]' }
        }
      end
      private_class_method :drivers_license_pattern

      def self.mrn_pattern
        {
          name: :mrn,
          pattern: /\bMRN\d{4,}\b/,
          replacer: ->(_match) { '[REDACTED_MRN]' }
        }
      end
      private_class_method :mrn_pattern

      def self.mask_email(email)
        local, domain = email.split('@', 2)
        "#{local[0]}***@#{domain[0]}******.#{domain.split('.').last}"
      end
      private_class_method :mask_email

      def self.mask_card(card)
        digits = card.gsub(/\D/, '')
        last_four = digits[-4..]
        sep = card.include?('-') ? '-' : ' '
        ['****', '****', '****', last_four].join(sep)
      end
      private_class_method :mask_card
    end
  end
end
