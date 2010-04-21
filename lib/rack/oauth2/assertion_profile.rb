$LOAD_PATH.unshift(File.expand_path(File.join(File.dirname(__FILE__), "../../")))
require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'
require 'simple_web_token_builder'
require 'vendor/information_card'

module Rack
  module OAuth2
    class AssertionProfile < Rack::Auth::AbstractHandler
      def initialize(app, opts = {})
        @app = app
        @opts = opts
      end
    
      def call(env)
        request = Request.new(env)
        
        if (request.assertion_profile? && request.format == :saml)
          InformationCard::Config.audience_scope,  InformationCard::Config.audiences = :site, [@opts[:scope]]
          token = InformationCard::SamlToken.create(request.token)
          
          unless token.valid?
            return [400, {'Content-Type' => "application/x-www-form-urlencoded"}, "error=unauthorized_client"] 
          end 
          
          # conver the received claims into SWT
          swt = token_builder.build(token.claims)
          return [200, {'Content-Type' => "application/x-www-form-urlencoded"}, "access_token=#{CGI.escape(swt)}"]
        end
        
        return @app.call(env)
      end
  
      def token_builder
        @token_builder ||= SimpleWebToken::SimpleWebTokenBuilder.new(@opts)
      end
    
      class Request < Rack::Request
        def initialize(env)
          super(env)
        end
     
        def assertion_profile?
          self.params["type"] =~ /assertion/i
        end
        
        def format
          (self.params["format"] or "saml").downcase.to_sym
        end
        
        def token
          self.params["assertion"]
        end
      end
    end
  end
end