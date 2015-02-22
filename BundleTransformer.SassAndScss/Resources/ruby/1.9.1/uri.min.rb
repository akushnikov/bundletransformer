#
# URI support for Ruby
#
# Author:: Akira Yamada <akira@ruby-lang.org>
# Documentation:: Akira Yamada <akira@ruby-lang.org>, Dmitry V. Sabanin <sdmitry@lrn.ru>
# License::
#  Copyright (c) 2001 akira yamada <akira@ruby-lang.org>
#  You can redistribute it and/or modify it under the same term as Ruby.
# Revision:: $Id: uri.rb 25189 2009-10-02 12:04:37Z akr $
#
# See URI for documentation
#
module URI
  VERSION_CODE = '000911'.freeze
  VERSION = VERSION_CODE.scan(/../).collect{|n| n.to_i}.join('.').freeze
end
require 'uri/common.min.rb'
require 'uri/generic.min.rb'
require 'uri/ftp.min.rb'
require 'uri/http.min.rb'
require 'uri/https.min.rb'
require 'uri/ldap.min.rb'
require 'uri/ldaps.min.rb'
require 'uri/mailto.min.rb'