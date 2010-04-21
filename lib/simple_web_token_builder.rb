require 'cgi'
require 'base64'
require 'hmac-sha2'

module SimpleWebToken
  # Creates a SimpleWebToken using the given parameters
  # plus a hash containing "claims" 
  class SimpleWebTokenBuilder
    attr_accessor :shared_secret, :issuer, :audience, :expiration
    
    # Creates a new instance of the SimpleTokenBuilder, 
    # if <b>:shared_secret</b> is not provided, an exception will be raised
    def initialize(opts = {})
      raise InvalidOption, :shared_secret unless opts[:shared_secret]
      self.shared_secret = opts[:shared_secret]
      self.issuer = opts[:issuer]
      self.audience = opts[:audience]
      self.expiration = (opts[:expiration] or 3600)
    end
    
    # Creates and signs the token based on the given claims hash 
    # plus the default claims set (issuer, audience, expires_on)
    def build(claims)
      token = (convert(claims) + default_claim_set).join("&")
      return token += "&HMACSHA256=#{CGI.escape(sign(token))}"
    end
    
    # Creates the HMAC-SHA256 signature based on the form-enconded-values
    # representation of the token
    def sign(bare_token)
      signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(self.shared_secret)).update(bare_token.toutf8).digest).strip
    end

    # Converts a hash of claims into a claim-value pair
    def convert(claims)
      claims.map{|k, v| claim_pair(k, v)}
    end

    # Returns the default claim set (issuer, audience, expires_on)
    def default_claim_set
      default_claims = []
      default_claims << claim_pair(:issuer, self.issuer) if(self.issuer)
      default_claims << claim_pair(:audience, self.audience) if(self.audience)
      default_claims << claim_pair(:expires_on, Time.now.to_i + self.expiration) 
      return default_claims
    end
    
    # Creates a claim-value pair 
    #
    # The given key is converted to PascalCase and merged (_ are removed, 
    # words between _ are considered discrete terms hence are uppercased)
    #
    # Values and Keys are encoded using CGI urlEscaping
    #
    # NOTE: If the claim value is an array, the given claim value is built
    # as csv (comma-separted-values) 
    def claim_pair(key, value)
      new_key = key.to_s.downcase.split("_").map{|l| l.capitalize.strip}.join("")
      value = [value].flatten.uniq.join(",")
      [new_key, value.to_s].map{|s| CGI.escape(s)}.join("=")
    end
  end
end