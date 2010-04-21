require 'spec/specs_config'
require 'lib/simple_web_token_builder'

describe "The Simple Web Token Builder behavior" do
  before do
    @opts = {:audience => "http://localhost", 
             :issuer => "http://localhost/issue", 
             :shared_secret => "N4QeKa3c062VBjnVK6fb+rnwURkcwGXh7EoNK34n0uM="}
  end
  
  it "turn the given key into pascal case and encode both key and value" do
    builder = SimpleWebToken::SimpleWebTokenBuilder.new(@opts)
    builder.claim_pair(:given_name, "johnny halife").should == "GivenName=johnny+halife"
  end

  it "should turn values that are arrays into csv" do
    builder = SimpleWebToken::SimpleWebTokenBuilder.new(@opts)
    builder.claim_pair(:projects, ["*", "foo"]).should == "Projects=#{CGI.escape("*,foo")}"
  end

  
  it "should generate each value pair for the given dictionary" do
    builder = SimpleWebToken::SimpleWebTokenBuilder.new(@opts)
    result = builder.convert({:age => 24})
    result[0].should == "Age=24"
  end
  
  it "should return default claims" do
    (mock_time ||= mock).expects(:to_i).returns(1)
    Time.expects(:now).returns(mock_time)
    
    builder = SimpleWebToken::SimpleWebTokenBuilder.new(@opts)
    default_claims_set = builder.default_claim_set
    default_claims_set[0].should == "Issuer=#{CGI.escape("http://localhost/issue")}"
    default_claims_set[1].should == "Audience=#{CGI.escape("http://localhost")}"
    default_claims_set[2].should == "ExpiresOn=#{CGI.escape("3601")}"
  end
  
  it "should sign the token" do
    builder = SimpleWebToken::SimpleWebTokenBuilder.new(@opts)
    expected_signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(@opts[:shared_secret])).update("Foo=Bar".toutf8).digest).strip
    builder.sign("Foo=Bar").should == expected_signature
  end
  
  it "should build the token" do
    builder = SimpleWebToken::SimpleWebTokenBuilder.new(@opts)
    
    builder.expects(:convert).with({:name => "johnny"}).returns(["Name=johnny"])
    builder.expects(:default_claim_set).returns([])
    builder.expects(:sign).with("Name=johnny").returns("foo")
    
    builder.build({:name => "johnny"}).should == "Name=johnny&HMACSHA256=foo"
  end
end