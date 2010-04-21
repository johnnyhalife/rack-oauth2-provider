# monkeypatching the SamlToken class to verify token signatures with X509 Certificates
require 'time'

module InformationCard
  include REXML

  # added first the tree claim types
  class ClaimTypes
      @@claims = {
        :name => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        :email => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        :upn => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
        :group => "http://schemas.xmlsoap.org/claims/Group",
        :given_name => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        :surname => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        :street_address => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress",
        :locality => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality",
        :state_province => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince",
        :postal_code => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode",
        :country => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country",
        :home_phone => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone",
        :other_phone => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/otherphone",
        :mobile_phone => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone",
        :date_of_birth => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth",
        :gender => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender",
        :ppid => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier",
        :webpage => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/webpage",
        :project => "http://schemas.southworksinc.com/project", 
        :organization => "http://schemas.microsoft.com/ws/2008/06/identity/claims/organization"
      }
  end

  class SamlToken < IdentityToken
    def errors
      return @errors
    end
    
    def verify_digest     
      working_doc = REXML::Document.new(@doc.to_s)
      
      assertion_node = XPath.first(working_doc, "saml:Assertion", {"saml" => Namespaces::SAML_ASSERTION}) 
      signature_node =  XPath.first(assertion_node, "ds:Signature", {"ds" => Namespaces::DS}) 
      signed_info_node = XPath.first(signature_node, "ds:SignedInfo", {"ds" => Namespaces::DS})    
      digest_value_node = XPath.first(signed_info_node, "ds:Reference/ds:DigestValue", {"ds" => Namespaces::DS})
      
      digest_value = digest_value_node.text

      signature_node.remove
      digest_errors = []
      canonicalizer = InformationCard::XmlCanonicalizer.new
      
      reference_nodes = XPath.match(signed_info_node, "ds:Reference", {"ds" => Namespaces::DS})
      # TODO: Check specification to see if digest is required.
      @errors[:digest] = "No reference nodes to check digest" and return if reference_nodes.nil? or reference_nodes.empty?
      
      reference_nodes.each do |node|
        uri = node.attributes['URI']
        nodes_to_verify = XPath.match(working_doc, "saml:Assertion[@AssertionID='#{uri[1..uri.size]}']", {"saml" => Namespaces::SAML_ASSERTION})
  
        nodes_to_verify.each do |node|
          canonicalized_signed_info = canonicalizer.canonicalize(node)
          signed_node_hash_sha1 = Base64.encode64(Digest::SHA1.digest(canonicalized_signed_info)).chomp                    
          signed_node_hash_sha256 = Base64.encode64(Digest::SHA256.digest(canonicalized_signed_info)).chomp                              
          unless signed_node_hash_sha1 == digest_value
            unless signed_node_hash_sha256 == digest_value
              digest_errors << "Invalid Digest for #{uri}. Expected #{signed_node_hash} but was #{digest_value}"
            end
          end
        end
                       
        @errors[:digest] = digest_errors unless digest_errors.empty?
      end  
    end
    
    def verify_signature    
      working_doc = REXML::Document.new(@doc.to_s)

      assertion_node = XPath.first(working_doc, "saml:Assertion", {"saml" => Namespaces::SAML_ASSERTION})
      signature_node =  XPath.first(assertion_node, "ds:Signature", {"ds" => Namespaces::DS})            
      certificate_value_node = XPath.first(signature_node, "KeyInfo/X509Data/X509Certificate")
      certificate = get_X509Certificate(certificate_value_node.text)

      # TODO: here you should validate that the presented certificate is valid

      public_key_string = certificate.public_key      
      signed_info_node = XPath.first(signature_node, "ds:SignedInfo", {"ds" => Namespaces::DS})
      signature_value_node = XPath.first(signature_node, "ds:SignatureValue", {"ds" => Namespaces::DS})
      canonicalized_signed_info = InformationCard::XmlCanonicalizer.new.canonicalize(signed_info_node)
      signature = Base64.decode64(signature_value_node.text)
      
      unless public_key_string.verify(OpenSSL::Digest::SHA1.new, signature, canonicalized_signed_info) 
        unless public_key_string.verify(OpenSSL::Digest::SHA256.new, signature, canonicalized_signed_info) 
          @errors[:signature] = "Invalid Signature" 
        end
      end
    end
  
    def validate_conditions
      conditions = XPath.first(@doc, "//saml:Conditions", "saml" => Namespaces::SAML_ASSERTION)
      
      condition_errors = {}
      not_before_time = Time.parse(conditions.attributes['NotBefore'])
      condition_errors[:not_before] = "Time is before #{not_before_time}" if Time.now.utc < not_before_time 
  
      not_on_or_after_time = Time.parse(conditions.attributes['NotOnOrAfter'])
      condition_errors[:not_on_or_after] = "Time is on or after #{not_on_or_after_time}" if Time.now.utc >= not_on_or_after_time

      @errors[:conditions] = condition_errors unless condition_errors.empty?    
    end
    
    def process_claims            
      attribute_nodes = XPath.match(@doc, "//saml:AttributeStatement/saml:Attribute", {"saml" => Namespaces::SAML_ASSERTION})
      attribute_nodes.each do |node|
        key = ClaimTypes.lookup(node.attributes['AttributeNamespace'], node.attributes['AttributeName'])      
        value_nodes = XPath.match(node, "saml:AttributeValue", "saml" => Namespaces::SAML_ASSERTION)
        
        if (value_nodes.length < 2 or value_nodes.empty?)
            @claims[key] = value_nodes[0].text
        else
          claim_values = []
          value_nodes.each{ |value_node|
              claim_values << value_node.text
          }
          @claims[key] = claim_values
        end
      end
    end
  
    def get_X509Certificate(certificate)
      encoding = "-----BEGIN CERTIFICATE-----\n"
      offset = 0;
      # strip out the newlines
      certificate.delete!("=\n") 
      while (segment = certificate[offset, 64])
         encoding = encoding + segment + "\n"
         offset += 64
      end
      encoding = encoding + "-----END CERTIFICATE-----\n"        
      OpenSSL::X509::Certificate.new(encoding)
    end
  end
end