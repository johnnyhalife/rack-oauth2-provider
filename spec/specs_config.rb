require 'rubygems'
require 'spec'
require 'mocha'
require 'rack/test'
require 'rack/mock'

Spec::Runner.configure do |config|
  config.mock_with :mocha
end

$LOAD_PATH.unshift(File.dirname __FILE__)