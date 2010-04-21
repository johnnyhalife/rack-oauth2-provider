$LOAD_PATH.unshift(File.expand_path(File.join(File.dirname(__FILE__), "../../")))
require 'specs_config.rb'
require 'lib/rack/oauth2/assertion_profile'

describe "Rack middleware behavior for oAuth 2.0 Assertion Profile" do
  before do
    @opts = {:audience => "http://localhost", 
             :issuer => "http://localhost/issue", 
             :shared_secret => "N4QeKa3c062VBjnVK6fb+rnwURkcwGXh7EoNK34n0uM="}
  end
  
  it "should do anything if it's not an authentication request for AssertionProfile'" do
    env = Rack::MockRequest.env_for("/", {})
    
    (mock_app = mock).expects(:call).with(env).once
    SimpleWebToken::SimpleWebTokenBuilder.any_instance.expects(:build).never
    InformationCard::SamlToken.expects(:create).never
    
    response_code, headers, body = Rack::OAuth2::AssertionProfile.new(mock_app, @opts).call(env)
  end
  
  it "should return 400 when the given assertion isn't well-formed nor valid" do
    env = Rack::MockRequest.env_for("/", {'rack.input' => "type=assertion&format=saml&assertion=very_invalid_assertion"})

    (mock_app = mock).expects(:call).with(env).never

    mock_request = mock do 
      expects(:assertion_profile?).returns(true)
      expects(:format).returns(:saml)
      expects(:token).returns("invalid_token")
    end
    
    (invalid_token = mock).expects(:valid?).returns(false)
    InformationCard::SamlToken.expects(:create).returns(invalid_token)
    Rack::OAuth2::AssertionProfile::Request.expects(:new).with(env).returns(mock_request)    

    response_code, headers, body = Rack::OAuth2::AssertionProfile.new(mock_app, @opts).call(env)

    response_code.should == 400
    headers['Content-Type'].should == "application/x-www-form-urlencoded"
    body.should == "error=unauthorized_client"
  end
  
  it "should return 200 when the given assertion is valid and include the access_token on the body" do
    env = Rack::MockRequest.env_for("/", {'rack.input' => "type=assertion&format=saml&assertion=very_valid_assertion"})

    (mock_app = mock).expects(:call).with(env).never

    mock_request = mock do 
      expects(:assertion_profile?).returns(true)
      expects(:format).returns(:saml)
      expects(:token).returns("very_valid_assertion")
    end
    
    valid_token = mock do
      expects(:valid?).returns(true)
      expects(:claims).returns({})
    end
    
    InformationCard::SamlToken.expects(:create).with("very_valid_assertion").returns(valid_token)
    Rack::OAuth2::AssertionProfile::Request.expects(:new).with(env).returns(mock_request)
    
    (mock_builder = mock).expects(:build).with({}).returns("token")
    SimpleWebToken::SimpleWebTokenBuilder.expects(:new).with(@opts).returns(mock_builder)
    
    response_code, headers, body = Rack::OAuth2::AssertionProfile.new(mock_app, @opts).call(env)

    response_code.should == 200
    headers['Content-Type'].should == "application/x-www-form-urlencoded"
    body.should == "access_token=token"
  end
end