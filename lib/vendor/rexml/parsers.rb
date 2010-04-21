# monkeypatching the whole pull method, only to comment out the lines 205 to 210
# because an error when trying to load a XML by calling REXML::Document.new(element)
# and this element has in the root node a namespace

module REXML
  module Parsers
    class BaseParser
      def pull
        if @closed
          x, @closed = @closed, nil
          return [ :end_element, x ]
        end
        return [ :end_document ] if empty?
        return @stack.shift if @stack.size > 0
        #STDERR.puts @source.encoding
        @source.read if @source.buffer.size<2
        #STDERR.puts "BUFFER = #{@source.buffer.inspect}"
        if @document_status == nil
          #@source.consume( /^\s*/um )
          word = @source.match( /^((?:\s+)|(?:<[^>]*>))/um )
          word = word[1] unless word.nil?
          #STDERR.puts "WORD = #{word.inspect}"
          case word
          when COMMENT_START
            return [ :comment, @source.match( COMMENT_PATTERN, true )[1] ]
          when XMLDECL_START
            #STDERR.puts "XMLDECL"
            results = @source.match( XMLDECL_PATTERN, true )[1]
            version = VERSION.match( results )
            version = version[1] unless version.nil?
            encoding = ENCODING.match(results)
            encoding = encoding[1] unless encoding.nil?
            @source.encoding = encoding
            standalone = STANDALONE.match(results)
            standalone = standalone[1] unless standalone.nil?
            return [ :xmldecl, version, encoding, standalone ]
          when INSTRUCTION_START
            return [ :processing_instruction, *@source.match(INSTRUCTION_PATTERN, true)[1,2] ]
          when DOCTYPE_START
            md = @source.match( DOCTYPE_PATTERN, true )
            @nsstack.unshift(curr_ns=Set.new)
            identity = md[1]
            close = md[2]
            identity =~ IDENTITY
            name = $1
            raise REXML::ParseException.new("DOCTYPE is missing a name") if name.nil?
            pub_sys = $2.nil? ? nil : $2.strip
            long_name = $4.nil? ? nil : $4.strip
            uri = $6.nil? ? nil : $6.strip
            args = [ :start_doctype, name, pub_sys, long_name, uri ]
            if close == ">"
              @document_status = :after_doctype
              @source.read if @source.buffer.size<2
              md = @source.match(/^\s*/um, true)
              @stack << [ :end_doctype ]
            else
              @document_status = :in_doctype
            end
            return args
          when /^\s+/
          else
            @document_status = :after_doctype
            @source.read if @source.buffer.size<2
            md = @source.match(/\s*/um, true)
          end
        end
        if @document_status == :in_doctype
          md = @source.match(/\s*(.*?>)/um)
          case md[1]
          when SYSTEMENTITY 
            match = @source.match( SYSTEMENTITY, true )[1]
            return [ :externalentity, match ]

          when ELEMENTDECL_START
            return [ :elementdecl, @source.match( ELEMENTDECL_PATTERN, true )[1] ]

          when ENTITY_START
            match = @source.match( ENTITYDECL, true ).to_a.compact
            match[0] = :entitydecl
            ref = false
            if match[1] == '%'
              ref = true
              match.delete_at 1
            end
            # Now we have to sort out what kind of entity reference this is
            if match[2] == 'SYSTEM'
              # External reference
              match[3] = match[3][1..-2] # PUBID
              match.delete_at(4) if match.size > 4 # Chop out NDATA decl
              # match is [ :entity, name, SYSTEM, pubid(, ndata)? ]
            elsif match[2] == 'PUBLIC'
              # External reference
              match[3] = match[3][1..-2] # PUBID
              match[4] = match[4][1..-2] # HREF
              # match is [ :entity, name, PUBLIC, pubid, href ]
            else
              match[2] = match[2][1..-2]
              match.pop if match.size == 4
              # match is [ :entity, name, value ]
            end
            match << '%' if ref
            return match
          when ATTLISTDECL_START
            md = @source.match( ATTLISTDECL_PATTERN, true )
            raise REXML::ParseException.new( "Bad ATTLIST declaration!", @source ) if md.nil?
            element = md[1]
            contents = md[0]

            pairs = {}
            values = md[0].scan( ATTDEF_RE )
            values.each do |attdef|
              unless attdef[3] == "#IMPLIED"
                attdef.compact!
                val = attdef[3]
                val = attdef[4] if val == "#FIXED "
                pairs[attdef[0]] = val
                if attdef[0] =~ /^xmlns:(.*)/
                  @nsstack[0] << $1
                end
              end
            end
            return [ :attlistdecl, element, pairs, contents ]
          when NOTATIONDECL_START
            md = nil
            if @source.match( PUBLIC )
              md = @source.match( PUBLIC, true )
              vals = [md[1],md[2],md[4],md[6]]
            elsif @source.match( SYSTEM )
              md = @source.match( SYSTEM, true )
              vals = [md[1],md[2],nil,md[4]]
            else
              raise REXML::ParseException.new( "error parsing notation: no matching pattern", @source )
            end
            return [ :notationdecl, *vals ]
          when CDATA_END
            @document_status = :after_doctype
            @source.match( CDATA_END, true )
            return [ :end_doctype ]
          end
        end
        begin
          if @source.buffer[0] == ?<
            if @source.buffer[1] == ?/
              @nsstack.shift
              last_tag = @tags.pop
              #md = @source.match_to_consume( '>', CLOSE_MATCH)
              md = @source.match( CLOSE_MATCH, true )
              raise REXML::ParseException.new( "Missing end tag for "+
                "'#{last_tag}' (got \"#{md[1]}\")", 
                @source) unless last_tag == md[1]
              return [ :end_element, last_tag ]
            elsif @source.buffer[1] == ?!
              md = @source.match(/\A(\s*[^>]*>)/um)
              #STDERR.puts "SOURCE BUFFER = #{source.buffer}, #{source.buffer.size}"
              raise REXML::ParseException.new("Malformed node", @source) unless md
              if md[0][2] == ?-
                md = @source.match( COMMENT_PATTERN, true )
                return [ :comment, md[1] ] if md
              else
                md = @source.match( CDATA_PATTERN, true )
                return [ :cdata, md[1] ] if md
              end
              raise REXML::ParseException.new( "Declarations can only occur "+
                "in the doctype declaration.", @source)
            elsif @source.buffer[1] == ??
              md = @source.match( INSTRUCTION_PATTERN, true )
              return [ :processing_instruction, md[1], md[2] ] if md
              raise REXML::ParseException.new( "Bad instruction declaration",
                @source)
            else
              # Get the next tag
              md = @source.match(TAG_MATCH, true)
              unless md
                # Check for missing attribute quotes
                raise REXML::ParseException.new("missing attribute quote", @source) if @source.match(MISSING_ATTRIBUTE_QUOTES )
                raise REXML::ParseException.new("malformed XML: missing tag start", @source) 
              end
              attributes = {}
              prefixes = Set.new
              prefixes << md[2] if md[2]
              @nsstack.unshift(curr_ns=Set.new)
              if md[4].size > 0
                attrs = md[4].scan( ATTRIBUTE_PATTERN )
                raise REXML::ParseException.new( "error parsing attributes: [#{attrs.join ', '}], excess = \"#$'\"", @source) if $' and $'.strip.size > 0
                attrs.each { |a,b,c,d,e| 
                  if b == "xmlns"
                    if c == "xml"
                      if d != "http://www.w3.org/XML/1998/namespace"
                        msg = "The 'xml' prefix must not be bound to any other namespace "+
                        "(http://www.w3.org/TR/REC-xml-names/#ns-decl)"
                        raise REXML::ParseException.new( msg, @source, self )
                      end
                    elsif c == "xmlns"
                      msg = "The 'xmlns' prefix must not be declared "+
                      "(http://www.w3.org/TR/REC-xml-names/#ns-decl)"
                      raise REXML::ParseException.new( msg, @source, self)
                    end
                    curr_ns << c
                  elsif b
                    prefixes << b unless b == "xml"
                  end
                  attributes[a] = e 
                }
              end

              # Verify that all of the prefixes have been defined
              #for prefix in prefixes
              #  unless @nsstack.find{|k| k.member?(prefix)}
              #    raise UndefinedNamespaceException.new(prefix,@source,self)
              #  end
              #end

              if md[6]
                @closed = md[1]
                @nsstack.shift
              else
                @tags.push( md[1] )
              end
              return [ :start_element, md[1], attributes ]
            end
          else
            md = @source.match( TEXT_PATTERN, true )
            if md[0].length == 0
              @source.match( /(\s+)/, true )
            end
            #STDERR.puts "GOT #{md[1].inspect}" unless md[0].length == 0
            #return [ :text, "" ] if md[0].length == 0
            # unnormalized = Text::unnormalize( md[1], self )
            # return PullEvent.new( :text, md[1], unnormalized )
            return [ :text, md[1] ]
          end
        rescue REXML::UndefinedNamespaceException
          raise
        rescue REXML::ParseException
          raise
        rescue Exception, NameError => error
          raise REXML::ParseException.new( "Exception parsing",
            @source, self, (error ? error : $!) )
        end
        return [ :dummy ]
      end
    end
  end
end
