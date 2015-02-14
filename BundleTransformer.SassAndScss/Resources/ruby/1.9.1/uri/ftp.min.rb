#
# = uri/ftp.rb
#
# Author:: Akira Yamada <akira@ruby-lang.org>
# License:: You can redistribute it and/or modify it under the same term as Ruby.
# Revision:: $Id: ftp.rb 27350 2010-04-15 13:41:19Z mame $
#
require 'uri/generic'
module URI
  class FTP < Generic
    DEFAULT_PORT = 21
    COMPONENT = [
      :scheme,
      :userinfo, :host, :port,
      :path, :typecode
    ].freeze
    TYPECODE = ['a', 'i', 'd'].freeze
    TYPECODE_PREFIX = ';type='.freeze
    def self.new2(user, password, host, port, path,
                  typecode = nil, arg_check = true)
      typecode = nil if typecode.size == 0
      if typecode && !TYPECODE.include?(typecode)
        raise ArgumentError,
          "bad typecode is specified: #{typecode}"
      end
      self.new('ftp',
               [user, password],
               host, port, nil,
               typecode ? path + TYPECODE_PREFIX + typecode : path,
               nil, nil, nil, arg_check)
    end
    def self.build(args)
      if args.kind_of?(Array)
        args[3] = '/' + args[3].sub(/^\//, '%2F')
      else
        args[:path] = '/' + args[:path].sub(/^\//, '%2F')
      end
      tmp = Util::make_components_hash(self, args)
      if tmp[:typecode]
        if tmp[:typecode].size == 1
          tmp[:typecode] = TYPECODE_PREFIX + tmp[:typecode]
        end
        tmp[:path] << tmp[:typecode]
      end
      return super(tmp)
    end
    def initialize(*arg)
      arg[5] = arg[5].sub(/^\//,'').sub(/^%2F/,'/')
      super(*arg)
      @typecode = nil
      tmp = @path.index(TYPECODE_PREFIX)
      if tmp
        typecode = @path[tmp + TYPECODE_PREFIX.size..-1]
        @path = @path[0..tmp - 1]
        if arg[-1]
          self.typecode = typecode
        else
          self.set_typecode(typecode)
        end
      end
    end
    attr_reader :typecode
    def check_typecode(v)
      if TYPECODE.include?(v)
        return true
      else
        raise InvalidComponentError,
          "bad typecode(expected #{TYPECODE.join(', ')}): #{v}"
      end
    end
    private :check_typecode
    def set_typecode(v)
      @typecode = v
    end
    protected :set_typecode
    def typecode=(typecode)
      check_typecode(typecode)
      set_typecode(typecode)
      typecode
    end
    def merge(oth) # :nodoc:
      tmp = super(oth)
      if self != tmp
        tmp.set_typecode(oth.typecode)
      end
      return tmp
    end
    def path
      return @path.sub(/^\//,'').sub(/^%2F/,'/')
    end
    def set_path(v)
      super("/" + v.sub(/^\//, "%2F"))
    end
    protected :set_path
    def to_s
      save_path = nil
      if @typecode
        save_path = @path
        @path = @path + TYPECODE_PREFIX + @typecode
      end
      str = super
      if @typecode
        @path = save_path
      end
      return str
    end
  end
  @@schemes['FTP'] = FTP
end