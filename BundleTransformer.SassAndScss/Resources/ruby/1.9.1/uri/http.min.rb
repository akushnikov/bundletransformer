#
# = uri/http.rb
#
# Author:: Akira Yamada <akira@ruby-lang.org>
# License:: You can redistribute it and/or modify it under the same term as Ruby.
# Revision:: $Id: http.rb 25189 2009-10-02 12:04:37Z akr $
#
require 'uri/generic'
module URI
  class HTTP < Generic
    DEFAULT_PORT = 80
    COMPONENT = [
      :scheme,
      :userinfo, :host, :port,
      :path,
      :query,
      :fragment
    ].freeze
    def self.build(args)
      tmp = Util::make_components_hash(self, args)
      return super(tmp)
    end
    def initialize(*arg)
      super(*arg)
    end
    def request_uri
      r = path_query
      if r[0] != ?/
        r = '/' + r
      end
      r
    end
  end
  @@schemes['HTTP'] = HTTP
end