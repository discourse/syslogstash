
require 'bundler'
Bundler.setup(:default, :development)
require 'rspec/core'
require 'rspec/mocks'
require 'webmock/rspec'

RSpec.configure do |config|
  config.fail_fast = true

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

