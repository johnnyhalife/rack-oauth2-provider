# Portions of this class were inspired by the XML::Util::XmlCanonicalizer class written by Roland Schmitt

module InformationCard
  include REXML
  
  class XmlCanonicalizer
    def initialize
      @canonicalized_xml = ''
    end
        
    def canonicalize(element)
      document = REXML::Document.new(element.to_s)
      
      #TODO: Do we need this check?
      if element.instance_of?(REXML::Element)
        namespace = element.namespace(element.prefix)
        if not namespace.empty?
          if not element.prefix.empty?
            document.root.add_namespace(element.prefix, namespace)            
          else
            document.root.add_namespace(namespace)            
          end 
        end
      end
      
      document.each_child{ |node| write_node(node, nil) } 
               
      @canonicalized_xml.strip
    end

    private  
      
    def write_node(node, scoped_prefixes)
      case node.node_type
        when :text
          write_text(node)
        when :element
          write_element(node, scoped_prefixes)
      end
    end
    
    def write_text(node)
      if node.value.strip.empty?
        @canonicalized_xml << node.value
      else
        @canonicalized_xml << normalize_whitespace(node.value) 
      end
    end
    
    def write_element(node, scoped_prefixes)
      scoped_prefixes ||= []
      @canonicalized_xml << "<#{node.expanded_name}"
      write_namespaces(node, scoped_prefixes)
      write_attributes(node)
      @canonicalized_xml << ">"
      node.each_child{ |child|
                            prefixes = Array.new(scoped_prefixes)
                            write_node(child, prefixes) }
      @canonicalized_xml << "</#{node.expanded_name}>"
    end
    
    def write_namespaces(node,  scoped_prefixes)
      scoped_prefixes ||= []

      prefixes = ["xmlns"] + node.prefixes.uniq

      prefixes.sort!.each do |prefix|
        namespace = node.namespace(prefix)
        
        unless prefix.empty? or (prefix == 'xmlns' and namespace.empty?) or scoped_prefixes.include?(prefix)
    		  scoped_prefixes << prefix
        
          @canonicalized_xml << " "
          @canonicalized_xml << "xmlns:" if not prefix == 'xmlns'
          @canonicalized_xml << normalize_whitespace("#{prefix}=\"#{namespace}\"")
        end
      end    
    end
    
    def write_attributes(node)
      attributes = []
      
      node.attributes.sort.each do |key, attribute|
        attributes << attribute if not attribute.prefix =~ /^xmlns/
      end
      
      attributes.each do |attribute|
        unless attribute.nil? or attribute.name == "xmlns"
          prefix = (attribute.prefix == "saml" || attribute.prefix == "ds") ? nil : attribute.prefix + ":"
          @canonicalized_xml << " #{prefix}#{attribute.name}=\"#{normalize_whitespace(attribute.to_s)}\"" 
        end
      end
    end

    def normalize_whitespace(input)      
      input.gsub(/\s+/, ' ').strip
    end
  end
end