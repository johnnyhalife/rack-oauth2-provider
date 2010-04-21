require 'cgi'
require 'base64'
require 'hmac-sha2'

module SimpleWebToken
  class SimpleWebTokenBuilder
    attr_accessor :shared_secret, :issuer, :audience, :expiration
    
    def initialize(opts = {})
      raise InvalidOption, :shared_secret unless opts[:shared_secret]
      self.shared_secret = opts[:shared_secret]
      self.issuer = opts[:issuer]
      self.audience = opts[:audience]
      self.expiration = (opts[:expiration] or 3600)
    end
    
    def build(claims)
      token = (convert(claims) + default_claim_set).join("&")
      return token += "&HMACSHA256=#{CGI.escape(sign(token))}"
    end

    def sign(bare_token)
      signature = Base64.encode64(HMAC::SHA256.new(Base64.decode64(self.shared_secret)).update(bare_token.toutf8).digest).strip
    end

    def convert(claims)
      claims.map{|k, v| claim_pair(k, v)}
    end

    def default_claim_set
      default_claims = []
      default_claims << claim_pair(:issuer, self.issuer) if(self.issuer)
      default_claims << claim_pair(:audience, self.audience) if(self.audience)
      default_claims << claim_pair(:expires_on, Time.now.to_i + self.expiration) 
      return default_claims
    end
    
    def claim_pair(key, value)
      new_key = key.to_s.downcase.split("_").map{|l| l.capitalize.strip}.join("")
      value = [value].flatten.uniq.join(",")
      [new_key, value.to_s].map{|s| CGI.escape(s)}.join("=")
    end
  end
end