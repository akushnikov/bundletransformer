require 'uri/ldap.min.rb'
module URI
  class LDAPS < LDAP
    DEFAULT_PORT = 636
  end
  @@schemes['LDAPS'] = LDAPS
end