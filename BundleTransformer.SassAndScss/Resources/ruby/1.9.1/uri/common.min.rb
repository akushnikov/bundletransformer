# = uri/common.rb
#
# Author:: Akira Yamada <akira@ruby-lang.org>
# Revision:: $Id: common.rb 27285 2010-04-10 22:05:02Z naruse $
# License::
#   You can redistribute it and/or modify it under the same term as Ruby.
#
module URI
  module REGEXP
    module PATTERN
      ALPHA = "a-zA-Z"
      ALNUM = "#{ALPHA}\\d"
      HEX     = "a-fA-F\\d"
      ESCAPED = "%[#{HEX}]{2}"
      UNRESERVED = "-_.!~*'()#{ALNUM}"
      RESERVED = ";/?:@&=+$,\\[\\]"
      DOMLABEL = "(?:[#{ALNUM}](?:[-#{ALNUM}]*[#{ALNUM}])?)"
      TOPLABEL = "(?:[#{ALPHA}](?:[-#{ALNUM}]*[#{ALNUM}])?)"
      HOSTNAME = "(?:#{DOMLABEL}\\.)*#{TOPLABEL}\\.?"
    end # PATTERN
  end # REGEXP
  class Parser
    include REGEXP
    def initialize(opts = {})
      @pattern = initialize_pattern(opts)
      @pattern.each_value {|v| v.freeze}
      @pattern.freeze
      @regexp = initialize_regexp(@pattern)
      @regexp.each_value {|v| v.freeze}
      @regexp.freeze
    end
    attr_reader :pattern, :regexp
    def split(uri)
      case uri
      when ''
      when @regexp[:ABS_URI]
	scheme, opaque, userinfo, host, port,
	  registry, path, query, fragment = $~[1..-1]
	if !scheme
	  raise InvalidURIError,
	    "bad URI(absolute but no scheme): #{uri}"
	end
	if !opaque && (!path && (!host && !registry))
	  raise InvalidURIError,
	    "bad URI(absolute but no path): #{uri}"
	end
      when @regexp[:REL_URI]
	scheme = nil
	opaque = nil
	userinfo, host, port, registry,
	  rel_segment, abs_path, query, fragment = $~[1..-1]
	if rel_segment && abs_path
	  path = rel_segment + abs_path
	elsif rel_segment
	  path = rel_segment
	elsif abs_path
	  path = abs_path
	end
      else
	raise InvalidURIError, "bad URI(is not URI?): #{uri}"
      end
      path = '' if !path && !opaque # (see RFC2396 Section 5.2)
      ret = [
	scheme,
	userinfo, host, port,         # X
	registry,                     # X
	path,                         # Y
	opaque,                       # Y
	query,
	fragment
      ]
      return ret
    end
    def parse(uri)
      scheme, userinfo, host, port,
       	registry, path, opaque, query, fragment = self.split(uri)
      if scheme && URI.scheme_list.include?(scheme.upcase)
	URI.scheme_list[scheme.upcase].new(scheme, userinfo, host, port,
                                           registry, path, opaque, query,
                                           fragment, self)
      else
	Generic.new(scheme, userinfo, host, port,
	   	    registry, path, opaque, query,
	    	    fragment, self)
      end
    end
    def join(*str)
      u = self.parse(str[0])
      str[1 .. -1].each do |x|
	u = u.merge(x)
      end
      u
    end
    def extract(str, schemes = nil, &block)
      if block_given?
       	str.scan(make_regexp(schemes)) { yield $& }
	nil
      else
	result = []
	str.scan(make_regexp(schemes)) { result.push $& }
	result
      end
    end
    def make_regexp(schemes = nil)
      unless schemes
       	@regexp[:ABS_URI_REF]
      else
	/(?=#{Regexp.union(*schemes)}:)#{@pattern[:X_ABS_URI]}/x
      end
    end
    def escape(str, unsafe = @regexp[:UNSAFE])
      unless unsafe.kind_of?(Regexp)
        unsafe = Regexp.new("[#{Regexp.quote(unsafe)}]", false)
      end
      str.gsub(unsafe) do
        us = $&
        tmp = ''
        us.each_byte do |uc|
          tmp << sprintf('%%%02X', uc)
        end
        tmp
      end.force_encoding(Encoding::US_ASCII)
    end
    def unescape(str, escaped = @regexp[:ESCAPED])
      str.gsub(escaped) { [$&[1, 2].hex].pack('C') }.force_encoding(str.encoding)
    end
    @@to_s = Kernel.instance_method(:to_s)
    def inspect
      @@to_s.bind(self).call
    end
    private
    def initialize_pattern(opts = {})
      ret = {}
      ret[:ESCAPED] = escaped = (opts.delete(:ESCAPED) || PATTERN::ESCAPED)
      ret[:UNRESERVED] = unreserved = opts.delete(:UNRESERVED) || PATTERN::UNRESERVED
      ret[:RESERVED] = reserved = opts.delete(:RESERVED) || PATTERN::RESERVED
      ret[:DOMLABEL] = domlabel = opts.delete(:DOMLABEL) || PATTERN::DOMLABEL
      ret[:TOPLABEL] = toplabel = opts.delete(:TOPLABEL) || PATTERN::TOPLABEL
      ret[:HOSTNAME] = hostname = opts.delete(:HOSTNAME)
      ret[:URIC] = uric = "(?:[#{unreserved}#{reserved}]|#{escaped})"
      ret[:URIC_NO_SLASH] = uric_no_slash = "(?:[#{unreserved};?:@&=+$,]|#{escaped})"
      ret[:QUERY] = query = "#{uric}*"
      ret[:FRAGMENT] = fragment = "#{uric}*"
      unless hostname
	ret[:HOSTNAME] = hostname = "(?:#{domlabel}\\.)*#{toplabel}\\.?"
      end
      ret[:IPV4ADDR] = ipv4addr = "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
      hex4 = "[#{PATTERN::HEX}]{1,4}"
      lastpart = "(?:#{hex4}|#{ipv4addr})"
      hexseq1 = "(?:#{hex4}:)*#{hex4}"
      hexseq2 = "(?:#{hex4}:)*#{lastpart}"
      ret[:IPV6ADDR] = ipv6addr = "(?:#{hexseq2}|(?:#{hexseq1})?::(?:#{hexseq2})?)"
      ret[:IPV6REF] = ipv6ref = "\\[#{ipv6addr}\\]"
      ret[:HOST] = host = "(?:#{hostname}|#{ipv4addr}|#{ipv6ref})"
      port = '\d*'
      ret[:HOSTPORT] = hostport = "#{host}(?::#{port})?"
      ret[:USERINFO] = userinfo = "(?:[#{unreserved};:&=+$,]|#{escaped})*"
      pchar = "(?:[#{unreserved}:@&=+$,]|#{escaped})"
      param = "#{pchar}*"
      segment = "#{pchar}*(?:;#{param})*"
      ret[:PATH_SEGMENTS] = path_segments = "#{segment}(?:/#{segment})*"
      server = "(?:#{userinfo}@)?#{hostport}"
      ret[:REG_NAME] = reg_name = "(?:[#{unreserved}$,;:@&=+]|#{escaped})+"
      authority = "(?:#{server}|#{reg_name})"
      ret[:REL_SEGMENT] = rel_segment = "(?:[#{unreserved};@&=+$,]|#{escaped})+"
      ret[:SCHEME] = scheme = "[#{PATTERN::ALPHA}][-+.#{PATTERN::ALPHA}\\d]*"
      ret[:ABS_PATH] = abs_path = "/#{path_segments}"
      ret[:REL_PATH] = rel_path = "#{rel_segment}(?:#{abs_path})?"
      ret[:NET_PATH] = net_path = "//#{authority}(?:#{abs_path})?"
      ret[:HIER_PART] = hier_part = "(?:#{net_path}|#{abs_path})(?:\\?(?:#{query}))?"
      ret[:OPAQUE_PART] = opaque_part = "#{uric_no_slash}#{uric}*"
      ret[:ABS_URI] = abs_uri = "#{scheme}:(?:#{hier_part}|#{opaque_part})"
      ret[:REL_URI] = rel_uri = "(?:#{net_path}|#{abs_path}|#{rel_path})(?:\\?#{query})?"
      ret[:URI_REF] = uri_ref = "(?:#{abs_uri}|#{rel_uri})?(?:##{fragment})?"
      ret[:X_ABS_URI] = "
        (#{scheme}):                           (?# 1: scheme)
        (?:
           (#{opaque_part})                    (?# 2: opaque)
        |
           (?:(?:
             //(?:
                 (?:(?:(#{userinfo})@)?        (?# 3: userinfo)
                   (?:(#{host})(?::(\\d*))?))? (?# 4: host, 5: port)
               |
                 (#{reg_name})                 (?# 6: registry)
               )
             |
             (?!//))                           (?# XXX: '//' is the mark for hostport)
             (#{abs_path})?                    (?# 7: path)
           )(?:\\?(#{query}))?                 (?# 8: query)
        )
        (?:\\#(#{fragment}))?                  (?# 9: fragment)
      "
      ret[:X_REL_URI] = "
        (?:
          (?:
            //
            (?:
              (?:(#{userinfo})@)?       (?# 1: userinfo)
                (#{host})?(?::(\\d*))?  (?# 2: host, 3: port)
            |
              (#{reg_name})             (?# 4: registry)
            )
          )
        |
          (#{rel_segment})              (?# 5: rel_segment)
        )?
        (#{abs_path})?                  (?# 6: abs_path)
        (?:\\?(#{query}))?              (?# 7: query)
        (?:\\#(#{fragment}))?           (?# 8: fragment)
      "
      ret
    end
    def initialize_regexp(pattern)
      ret = {}
      ret[:ABS_URI] = Regexp.new('\A\s*' + pattern[:X_ABS_URI] + '\s*\z', Regexp::EXTENDED)
      ret[:REL_URI] = Regexp.new('\A\s*' + pattern[:X_REL_URI] + '\s*\z', Regexp::EXTENDED)
      ret[:URI_REF]     = Regexp.new(pattern[:URI_REF])
      ret[:ABS_URI_REF] = Regexp.new(pattern[:X_ABS_URI], Regexp::EXTENDED)
      ret[:REL_URI_REF] = Regexp.new(pattern[:X_REL_URI], Regexp::EXTENDED)
      ret[:ESCAPED] = Regexp.new(pattern[:ESCAPED])
      ret[:UNSAFE]  = Regexp.new("[^#{pattern[:UNRESERVED]}#{pattern[:RESERVED]}]")
      ret[:SCHEME]   = Regexp.new("^#{pattern[:SCHEME]}$")
      ret[:USERINFO] = Regexp.new("^#{pattern[:USERINFO]}$")
      ret[:HOST]     = Regexp.new("^#{pattern[:HOST]}$")
      ret[:PORT]     = Regexp.new("^#{pattern[:PORT]}$")
      ret[:OPAQUE]   = Regexp.new("^#{pattern[:OPAQUE_PART]}$")
      ret[:REGISTRY] = Regexp.new("^#{pattern[:REG_NAME]}$")
      ret[:ABS_PATH] = Regexp.new("^#{pattern[:ABS_PATH]}$")
      ret[:REL_PATH] = Regexp.new("^#{pattern[:REL_PATH]}$")
      ret[:QUERY]    = Regexp.new("^#{pattern[:QUERY]}$")
      ret[:FRAGMENT] = Regexp.new("^#{pattern[:FRAGMENT]}$")
      ret
    end
  end # class Parser
  DEFAULT_PARSER = Parser.new
  DEFAULT_PARSER.pattern.each_pair do |sym, str|
    unless REGEXP::PATTERN.const_defined?(sym)
      REGEXP::PATTERN.const_set(sym, str)
    end
  end
  DEFAULT_PARSER.regexp.each_pair do |sym, str|
    const_set(sym, str)
  end
  module Util # :nodoc:
    def make_components_hash(klass, array_hash)
      tmp = {}
      if array_hash.kind_of?(Array) &&
          array_hash.size == klass.component.size - 1
        klass.component[1..-1].each_index do |i|
          begin
            tmp[klass.component[i + 1]] = array_hash[i].clone
          rescue TypeError
            tmp[klass.component[i + 1]] = array_hash[i]
          end
        end
      elsif array_hash.kind_of?(Hash)
        array_hash.each do |key, value|
          begin
            tmp[key] = value.clone
          rescue TypeError
            tmp[key] = value
          end
        end
      else
        raise ArgumentError,
          "expected Array of or Hash of components of #{klass.to_s} (#{klass.component[1..-1].join(', ')})"
      end
      tmp[:scheme] = klass.to_s.sub(/\A.*::/, '').downcase
      return tmp
    end
    module_function :make_components_hash
  end
  module Escape
    def escape(*arg)
      warn "#{caller(1)[0]}: warning: URI.escape is obsolete" if $VERBOSE
      DEFAULT_PARSER.escape(*arg)
    end
    alias encode escape
    def unescape(*arg)
      warn "#{caller(1)[0]}: warning: URI.unescape is obsolete" if $VERBOSE
      DEFAULT_PARSER.unescape(*arg)
    end
    alias decode unescape
  end
  extend Escape
  include REGEXP
  @@schemes = {}
  def self.scheme_list
    @@schemes
  end
  class Error < StandardError; end
  class InvalidURIError < Error; end
  class InvalidComponentError < Error; end
  class BadURIError < Error; end
  def self.split(uri)
    DEFAULT_PARSER.split(uri)
  end
  def self.parse(uri)
    DEFAULT_PARSER.parse(uri)
  end
  def self.join(*str)
    DEFAULT_PARSER.join(*str)
  end
  def self.extract(str, schemes = nil, &block)
    DEFAULT_PARSER.extract(str, schemes, &block)
  end
  def self.regexp(schemes = nil)
    DEFAULT_PARSER.make_regexp(schemes)
  end
  TBLENCWWWCOMP_ = {} # :nodoc:
  TBLDECWWWCOMP_ = {} # :nodoc:
  HTML5ASCIIINCOMPAT = [Encoding::UTF_7, Encoding::UTF_16BE, Encoding::UTF_16LE,
    Encoding::UTF_32BE, Encoding::UTF_32LE] # :nodoc:
  def self.encode_www_form_component(str)
    if TBLENCWWWCOMP_.empty?
      256.times do |i|
        TBLENCWWWCOMP_[i.chr] = '%%%02X' % i
      end
      TBLENCWWWCOMP_[' '] = '+'
      TBLENCWWWCOMP_.freeze
    end
    str = str.to_s
    if HTML5ASCIIINCOMPAT.include?(str.encoding)
      str = str.encode(Encoding::UTF_8)
    else
      str = str.dup
    end
    str.force_encoding(Encoding::ASCII_8BIT)
    str.gsub!(/[^*\-.0-9A-Z_a-z]/, TBLENCWWWCOMP_)
    str.force_encoding(Encoding::US_ASCII)
  end
  def self.decode_www_form_component(str, enc=Encoding::UTF_8)
    if TBLDECWWWCOMP_.empty?
      256.times do |i|
        h, l = i>>4, i&15
        TBLDECWWWCOMP_['%%%X%X' % [h, l]] = i.chr
        TBLDECWWWCOMP_['%%%x%X' % [h, l]] = i.chr
        TBLDECWWWCOMP_['%%%X%x' % [h, l]] = i.chr
        TBLDECWWWCOMP_['%%%x%x' % [h, l]] = i.chr
      end
      TBLDECWWWCOMP_['+'] = ' '
      TBLDECWWWCOMP_.freeze
    end
    raise ArgumentError, "invalid %-encoding (#{str})" unless /\A(?:%\h\h|[^%]+)*\z/ =~ str
    str.gsub(/\+|%\h\h/, TBLDECWWWCOMP_).force_encoding(enc)
  end
  def self.encode_www_form(enum)
    str = nil
    enum.each do |k,v|
      if str
        str << '&'
      else
        str = nil.to_s
      end
      str << encode_www_form_component(k)
      str << '='
      str << encode_www_form_component(v)
    end
    str
  end
  WFKV_ = '(?:%\h\h|[^%#=;&]+)' # :nodoc:
  def self.decode_www_form(str, enc=Encoding::UTF_8)
    return [] if str.empty?
    unless /\A#{WFKV_}*=#{WFKV_}*(?:[;&]#{WFKV_}*=#{WFKV_}*)*\z/o =~ str
      raise ArgumentError, "invalid data of application/x-www-form-urlencoded (#{str})"
    end
    ary = []
    $&.scan(/([^=;&]+)=([^;&]*)/) do
      ary << [decode_www_form_component($1, enc), decode_www_form_component($2, enc)]
    end
    ary
  end
end
module Kernel
  def URI(uri_str) # :doc:
    URI.parse(uri_str)
  end
  module_function :URI
end