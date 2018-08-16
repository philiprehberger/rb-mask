# frozen_string_literal: true

require_relative 'lib/philiprehberger/mask/version'

Gem::Specification.new do |spec|
  spec.name          = 'philiprehberger-mask'
  spec.version       = Philiprehberger::Mask::VERSION
  spec.authors       = ['Philip Rehberger']
  spec.email         = ['me@philiprehberger.com']

  spec.summary       = 'Data masking library with auto-detect PII redaction for strings and nested structures'
  spec.description   = 'Automatically detect and redact sensitive data like emails, credit cards, SSNs, ' \
                       'and tokens in strings and nested structures with configurable patterns.'
  spec.homepage      = 'https://github.com/philiprehberger/rb-mask'
  spec.license       = 'MIT'

  spec.required_ruby_version = '>= 3.1.0'

  spec.metadata['homepage_uri']    = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['changelog_uri']   = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata['bug_tracker_uri']       = "#{spec.homepage}/issues"
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir['lib/**/*.rb', 'LICENSE', 'README.md', 'CHANGELOG.md']
  spec.require_paths = ['lib']
end
