$LOAD_PATH.unshift(File.expand_path(File.join(File.dirname(__FILE__), "../../")))
require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'
require 'simple_web_token_builder'
require 'vendor/information_card'

module Rack
  module OAuth2
    # Rack::OAuth2::AssertionProfile implements the Assertion Profile for generating 
    # authorization tokens as per draft-ieft-oauth. This is a preliminary version based on the
    # Apr 16, 2010 working standard developed by the IETF.
    #
    # Initialize with the Rack application that will work as Authorization Server,
    # and a set of parameters that enables specific checks. The only mandatory parameter
    # is **:shared_secret** which is required for HMAC-SHA256 processing.
    class AssertionProfile < Rack::Auth::AbstractHandler
      
      # Creates a new instance of Rack::OAuth2::Provider, the opts are required 
      def initialize(app, opts = {})
        @app = app
        @opts = opts
      end
      
      # Authorizes the request and generates the _access token_ on the body, 
      # signed with the shared key (passed as c'tor parameter),
      # as a successful response of the token processing.
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
      
      # Singleton instance of the SimpleWebTokenBuilder
      # 
      # see alse: SimpleWebToken::SimpleWebTokenBuilder
      def token_builder
        @token_builder ||= SimpleWebToken::SimpleWebTokenBuilder.new(@opts)
      end
      
      # Internal class used to parse the current request based on 
      # the enviroment parameters.    
      class Request < Rack::Request
        def initialize(env)
          super(env)
        end
     
        # Returns a value indicating whether the type 
        # the of authorization request is _assertion_
        def assertion_profile?
          self.params["type"] =~ /assertion/i
        end
        
        # Reads from the formvars the format of the
        # set assertion
        def format
          (self.params["format"] or "saml").downcase.to_sym
        end
        
        # Reads the assertion from the given formvars
        def token
          self.params["assertion"]
        end
      end
    end
  end
end