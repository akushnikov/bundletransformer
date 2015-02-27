##################################################################################
# Sass v3.4.12
# http://sass-lang.com
#
# Copyright (c) 2006-2014 Hampton Catlin, Natalie Weizenbaum, and Chris Eppstein
# Released under the MIT License
##################################################################################
dir = File.dirname(__FILE__)
$LOAD_PATH.unshift dir unless $LOAD_PATH.include?(dir)
require 'set.min.rb'
require 'enumerator.min.rb'
require 'stringio.min.rb'
require 'rbconfig.min.rb'
require 'uri.min.rb'
require 'pathname.min.rb'
module Sass
  ROOT_DIR = File.expand_path(File.join(__FILE__, "../../.."))
end
module Sass
  module Util
    class SubsetMap
      def initialize
        @hash = {}
        @vals = []
      end
      def empty?
        @hash.empty?
      end
      def []=(set, value)
        raise ArgumentError.new("SubsetMap keys may not be empty.") if set.empty?
        index = @vals.size
        @vals << value
        set.each do |k|
          @hash[k] ||= []
          @hash[k] << [set, set.to_set, index]
        end
      end
      def get(set)
        res = set.map do |k|
          subsets = @hash[k]
          next unless subsets
          subsets.map do |subenum, subset, index|
            next unless subset.subset?(set)
            [index, subenum]
          end
        end
        res = Sass::Util.flatten(res, 1)
        res.compact!
        res.uniq!
        res.sort!
        res.map! {|i, s| [@vals[i], s]}
        res
      end
      def [](set)
        get(set).map {|v, _| v}
      end
      def each_value
        @vals.each {|v| yield v}
      end
    end
  end
end
module Sass
  module Util
    extend self
    RUBY_VERSION_COMPONENTS = RUBY_VERSION.split(".").map {|s| s.to_i}
    RUBY_ENGINE = defined?(::RUBY_ENGINE) ? ::RUBY_ENGINE : "ruby"
    def scope(file)
      File.join(Sass::ROOT_DIR, file)
    end
    def to_hash(arr)
      ordered_hash(*arr.compact)
    end
    def map_keys(hash)
      map_hash(hash) {|k, v| [yield(k), v]}
    end
    def map_vals(hash)
      rv = hash.class.new
      hash = hash.as_stored if hash.is_a?(NormalizedMap)
      hash.each do |k, v|
        rv[k] = yield(v)
      end
      rv
    end
    def map_hash(hash)
      rv = hash.class.new
      hash.each do |k, v|
        new_key, new_value = yield(k, v)
        new_key = hash.denormalize(new_key) if hash.is_a?(NormalizedMap) && new_key == k
        rv[new_key] = new_value
      end
      rv
    end
    def powerset(arr)
      arr.inject([Set.new].to_set) do |powerset, el|
        new_powerset = Set.new
        powerset.each do |subset|
          new_powerset << subset
          new_powerset << subset + [el]
        end
        new_powerset
      end
    end
    def restrict(value, range)
      [[value, range.first].max, range.last].min
    end
    def merge_adjacent_strings(arr)
      return arr if arr.size < 2
      arr.inject([]) do |a, e|
        if e.is_a?(String)
          if a.last.is_a?(String)
            a.last << e
          else
            a << e.dup
          end
        else
          a << e
        end
        a
      end
    end
    def replace_subseq(arr, subseq, replacement)
      new = []
      matched = []
      i = 0
      arr.each do |elem|
        if elem != subseq[i]
          new.push(*matched)
          matched = []
          i = 0
          new << elem
          next
        end
        if i == subseq.length - 1
          matched = []
          i = 0
          new.push(*replacement)
        else
          matched << elem
          i += 1
        end
      end
      new.push(*matched)
      new
    end
    def intersperse(enum, val)
      enum.inject([]) {|a, e| a << e << val}[0...-1]
    end
    def slice_by(enum)
      results = []
      enum.each do |value|
        key = yield(value)
        if !results.empty? && results.last.first == key
          results.last.last << value
        else
          results << [key, [value]]
        end
      end
      results
    end
    def substitute(ary, from, to)
      res = ary.dup
      i = 0
      while i < res.size
        if res[i...i + from.size] == from
          res[i...i + from.size] = to
        end
        i += 1
      end
      res
    end
    def strip_string_array(arr)
      arr.first.lstrip! if arr.first.is_a?(String)
      arr.last.rstrip! if arr.last.is_a?(String)
      arr
    end
    def paths(arrs)
      arrs.inject([[]]) do |paths, arr|
        flatten(arr.map {|e| paths.map {|path| path + [e]}}, 1)
      end
    end
    def lcs(x, y, &block)
      x = [nil, *x]
      y = [nil, *y]
      block ||= proc {|a, b| a == b && a}
      lcs_backtrace(lcs_table(x, y, &block), x, y, x.size - 1, y.size - 1, &block)
    end
    def hash_to_a(hash)
      return hash.to_a unless ruby1_8? || defined?(Test::Unit)
      hash.sort_by {|k, v| k}
    end
    def group_by_to_a(enum)
      return enum.group_by {|e| yield(e)}.to_a unless ruby1_8?
      order = {}
      arr = []
      groups = enum.group_by do |e|
        res = yield(e)
        unless order.include?(res)
          order[res] = order.size
        end
        res
      end
      groups.each do |key, vals|
        arr[order[key]] = [key, vals]
      end
      arr
    end
    def array_minus(minuend, subtrahend)
      return minuend - subtrahend unless rbx?
      set = Set.new(minuend) - subtrahend
      minuend.select {|e| set.include?(e)}
    end
    def max(val1, val2)
      val1 > val2 ? val1 : val2
    end
    def min(val1, val2)
      val1 <= val2 ? val1 : val2
    end
    def undefined_conversion_error_char(e)
      return e.error_char if rbx?
      return e.error_char.dump unless jruby?
      e.message[/^"[^"]+"/] # "
    end
    def check_range(name, range, value, unit = '')
      grace = (-0.00001..0.00001)
      str = value.to_s
      value = value.value if value.is_a?(Sass::Script::Value::Number)
      return value if range.include?(value)
      return range.first if grace.include?(value - range.first)
      return range.last if grace.include?(value - range.last)
      raise ArgumentError.new(
        "#{name} #{str} must be between #{range.first}#{unit} and #{range.last}#{unit}")
    end
    def subsequence?(seq1, seq2)
      i = j = 0
      loop do
        return true if i == seq1.size
        return false if j == seq2.size
        i += 1 if seq1[i] == seq2[j]
        j += 1
      end
    end
    def caller_info(entry = nil)
      entry ||= caller[1]
      info = entry.scan(/^((?:[A-Za-z]:)?.*?):(-?.*?)(?::.*`(.+)')?$/).first
      info[1] = info[1].to_i
      info[2].sub!(/ \{\}\Z/, '') if info[2]
      info
    end
    def version_gt(v1, v2)
      Array.new([v1.length, v2.length].max).zip(v1.split("."), v2.split(".")) do |_, p1, p2|
        p1 ||= "0"
        p2 ||= "0"
        release1 = p1 =~ /^[0-9]+$/
        release2 = p2 =~ /^[0-9]+$/
        if release1 && release2
          p1, p2 = p1.to_i, p2.to_i
          next if p1 == p2
          return p1 > p2
        elsif !release1 && !release2
          next if p1 == p2
          return p1 > p2
        else
          return release1
        end
      end
    end
    def version_geq(v1, v2)
      version_gt(v1, v2) || !version_gt(v2, v1)
    end
    def abstract(obj)
      raise NotImplementedError.new("#{obj.class} must implement ##{caller_info[2]}")
    end
    def deprecated(obj, message = nil)
      obj_class = obj.is_a?(Class) ? "#{obj}." : "#{obj.class}#"
      full_message = "DEPRECATION WARNING: #{obj_class}#{caller_info[2]} " +
        "will be removed in a future version of Sass.#{("\n" + message) if message}"
      Sass::Util.sass_warn full_message
    end
    def silence_warnings
      the_real_stderr, $stderr = $stderr, StringIO.new
      yield
    ensure
      $stderr = the_real_stderr
    end
    def silence_sass_warnings
      old_level, Sass.logger.log_level = Sass.logger.log_level, :error
      yield
    ensure
      Sass.logger.log_level = old_level
    end
    def sass_warn(msg)
      msg = msg + "\n" unless ruby1?
      Sass.logger.warn(msg)
    end
    def rails_root
      if defined?(::Rails.root)
        return ::Rails.root.to_s if ::Rails.root
        raise "ERROR: Rails.root is nil!"
      end
      return RAILS_ROOT.to_s if defined?(RAILS_ROOT)
      nil
    end
    def rails_env
      return ::Rails.env.to_s if defined?(::Rails.env)
      return RAILS_ENV.to_s if defined?(RAILS_ENV)
      nil
    end
    def ap_geq_3?
      ap_geq?("3.0.0.beta1")
    end
    def ap_geq?(version)
      return false unless defined?(ActionPack) && defined?(ActionPack::VERSION) &&
        defined?(ActionPack::VERSION::STRING)
      version_geq(ActionPack::VERSION::STRING, version)
    end
    def listen_geq_2?
      return @listen_geq_2 unless @listen_geq_2.nil?
      @listen_geq_2 =
        begin
          require 'listen/version.min.rb'
          version_geq(::Listen::VERSION, '2.0.0')
        rescue LoadError
          false
        end
    end
    def av_template_class(name)
      return ActionView.const_get("Template#{name}") if ActionView.const_defined?("Template#{name}")
      ActionView::Template.const_get(name.to_s)
    end
    def windows?
      return @windows if defined?(@windows)
      @windows = (RbConfig::CONFIG['host_os'] =~ /mswin|windows|mingw/i)
    end
    def ironruby?
      return @ironruby if defined?(@ironruby)
      @ironruby = RUBY_ENGINE == "ironruby"
    end
    def rbx?
      return @rbx if defined?(@rbx)
      @rbx = RUBY_ENGINE == "rbx"
    end
    def jruby?
      return @jruby if defined?(@jruby)
      @jruby = RUBY_PLATFORM =~ /java/
    end
    def jruby_version
      @jruby_version ||= ::JRUBY_VERSION.split(".").map {|s| s.to_i}
    end
    def glob(path)
      path = path.gsub('\\', '/') if windows?
      if block_given?
        Dir.glob(path) {|f| yield(f)}
      else
        Dir.glob(path)
      end
    end
    def pathname(path)
      path = path.tr("/", "\\") if windows?
      Pathname.new(path)
    end
    def cleanpath(path)
      path = Pathname.new(path) unless path.is_a?(Pathname)
      pathname(path.cleanpath.to_s)
    end
    def realpath(path)
      path = Pathname.new(path) unless path.is_a?(Pathname)
      begin
        path.realpath
      rescue SystemCallError
        path
      end
    end
    def relative_path_from(path, from)
      pathname(path.to_s).relative_path_from(pathname(from.to_s))
    rescue NoMethodError => e
      raise e unless e.name == :zero?
      path = path.to_s
      from = from.to_s
      raise ArgumentError("Incompatible path encodings: #{path.inspect} is #{path.encoding}, " +
        "#{from.inspect} is #{from.encoding}")
    end
    def file_uri_from_path(path)
      path = path.to_s if path.is_a?(Pathname)
      path = path.tr('\\', '/') if windows?
      path = Sass::Util.escape_uri(path)
      return path.start_with?('/') ? "file://" + path : path unless windows?
      return "file:///" + path.tr("\\", "/") if path =~ /^[a-zA-Z]:[\/\\]/
      return "file:" + path.tr("\\", "/") if path =~ /\\\\[^\\]+\\[^\\\/]+/
      path.tr("\\", "/")
    end
    def retry_on_windows
      return yield unless windows?
      begin
        yield
      rescue SystemCallError
        sleep 0.1
        yield
      end
    end
    def destructure(val)
      val || []
    end
    def ruby1?
      return @ruby1 if defined?(@ruby1)
      @ruby1 = RUBY_VERSION_COMPONENTS[0] <= 1
    end
    def ruby1_8?
      return @ruby1_8 if defined?(@ruby1_8)
      @ruby1_8 = ironruby? ||
                   (RUBY_VERSION_COMPONENTS[0] == 1 && RUBY_VERSION_COMPONENTS[1] < 9)
    end
    def ruby1_8_6?
      return @ruby1_8_6 if defined?(@ruby1_8_6)
      @ruby1_8_6 = ruby1_8? && RUBY_VERSION_COMPONENTS[2] < 7
    end
    def ruby1_9_2?
      return @ruby1_9_2 if defined?(@ruby1_9_2)
      @ruby1_9_2 = RUBY_VERSION_COMPONENTS == [1, 9, 2]
    end
    def jruby1_6?
      return @jruby1_6 if defined?(@jruby1_6)
      @jruby1_6 = jruby? && jruby_version[0] == 1 && jruby_version[1] < 7
    end
    def macruby?
      return @macruby if defined?(@macruby)
      @macruby = RUBY_ENGINE == 'macruby'
    end
class OrderedHash < ::Hash
  def initialize(*args)
    super
    @keys = []
  end
  def self.[](*args)
    ordered_hash = new
    if args.length == 1 && args.first.is_a?(Array)
      args.first.each do |key_value_pair|
        next unless key_value_pair.is_a?(Array)
        ordered_hash[key_value_pair[0]] = key_value_pair[1]
      end
      return ordered_hash
    end
    unless args.size.even?
      raise ArgumentError.new("odd number of arguments for Hash")
    end
    args.each_with_index do |val, ind|
      next if ind.odd?
      ordered_hash[val] = args[ind + 1]
    end
    ordered_hash
  end
  def initialize_copy(other)
    super
    @keys = other.keys
  end
  def []=(key, value)
    @keys << key unless has_key?(key)
    super
  end
  def delete(key)
    if has_key? key
      index = @keys.index(key)
      @keys.delete_at index
    end
    super
  end
  def delete_if
    super
    sync_keys!
    self
  end
  def reject!
    super
    sync_keys!
    self
  end
  def reject
    dup.reject! {|h, k| yield h, k}
  end
  def keys
    @keys.dup
  end
  def values
    @keys.map {|key| self[key]}
  end
  def to_hash
    self
  end
  def to_a
    @keys.map {|key| [key, self[key]]}
  end
  def each_key
    return to_enum(:each_key) unless block_given?
    @keys.each {|key| yield key}
    self
  end
  def each_value
    return to_enum(:each_value) unless block_given?
    @keys.each {|key| yield self[key]}
    self
  end
  def each
    return to_enum(:each) unless block_given?
    @keys.each {|key| yield [key, self[key]]}
    self
  end
  def each_pair
    return to_enum(:each_pair) unless block_given?
    @keys.each {|key| yield key, self[key]}
    self
  end
  alias_method :select, :find_all
  def clear
    super
    @keys.clear
    self
  end
  def shift
    k = @keys.first
    v = delete(k)
    [k, v]
  end
  def merge!(other_hash)
    if block_given?
      other_hash.each {|k, v| self[k] = key?(k) ? yield(k, self[k], v) : v}
    else
      other_hash.each {|k, v| self[k] = v}
    end
    self
  end
  alias_method :update, :merge!
  def merge(other_hash)
    if block_given?
      dup.merge!(other_hash) {|k, v1, v2| yield k, v1, v2}
    else
      dup.merge!(other_hash)
    end
  end
  def replace(other)
    super
    @keys = other.keys
    self
  end
  def invert
    OrderedHash[to_a.map! {|key_value_pair| key_value_pair.reverse}]
  end
  def inspect
    "#<OrderedHash #{super}>"
  end
  private
  def sync_keys!
    @keys.delete_if {|k| !has_key?(k)}
  end
end
    def ordered_hash(*pairs_or_hash)
      if pairs_or_hash.length == 1 && pairs_or_hash.first.is_a?(Hash)
        hash = pairs_or_hash.first
        return hash unless ruby1_8?
        return OrderedHash.new.merge hash
      end
      return Hash[pairs_or_hash] unless ruby1_8?
      (pairs_or_hash.is_a?(NormalizedMap) ? NormalizedMap : OrderedHash)[*flatten(pairs_or_hash, 1)]
    end
    unless ruby1_8?
      CHARSET_REGEXP = /\A@charset "([^"]+)"/
      UTF_8_BOM = "\xEF\xBB\xBF".force_encoding('BINARY')
      UTF_16BE_BOM = "\xFE\xFF".force_encoding('BINARY')
      UTF_16LE_BOM = "\xFF\xFE".force_encoding('BINARY')
    end
    def check_sass_encoding(str)
      if ruby1_8?
        return str.gsub(/\A\xEF\xBB\xBF/, '').gsub(/\r\n?|\f/, "\n"), nil
      end
      binary = str.dup.force_encoding("BINARY")
      if binary.start_with?(UTF_8_BOM)
        binary.slice! 0, UTF_8_BOM.length
        str = binary.force_encoding('UTF-8')
      elsif binary.start_with?(UTF_16BE_BOM)
        binary.slice! 0, UTF_16BE_BOM.length
        str = binary.force_encoding('UTF-16BE')
      elsif binary.start_with?(UTF_16LE_BOM)
        binary.slice! 0, UTF_16LE_BOM.length
        str = binary.force_encoding('UTF-16LE')
      elsif binary =~ CHARSET_REGEXP
        charset = $1.force_encoding('US-ASCII')
        if ruby1_9_2? && charset.downcase == 'utf-16'
          encoding = Encoding.find('UTF-8')
        else
          encoding = Encoding.find(charset)
          if encoding.name == 'UTF-16' || encoding.name == 'UTF-16BE'
            encoding = Encoding.find('UTF-8')
          end
        end
        str = binary.force_encoding(encoding)
      elsif str.encoding.name == "ASCII-8BIT"
        str = str.force_encoding('utf-8')
      end
      find_encoding_error(str) unless str.valid_encoding?
      begin
        return str.encode("UTF-8").gsub(/\r\n?|\f/, "\n").tr("\u0000", "�"), str.encoding
      rescue EncodingError
        find_encoding_error(str)
      end
    end
    def has?(attr, klass, method)
      klass.send("#{attr}s").include?(ruby1_8? ? method.to_s : method.to_sym)
    end
    def enum_with_index(enum)
      hash = Hash.new #BT+
	  index = -1 #BT+
	  enum.each do |item| #BT+
		index += 1 #BT+
		hash[item] = index #BT+
	  end #BT+
	  return hash #BT+
    end
    def enum_cons(enum, n)
      ruby1_8? ? enum.enum_cons(n) : enum.each_cons(n)
    end
    def enum_slice(enum, n)
      ruby1_8? ? enum.enum_slice(n) : enum.each_slice(n)
    end
    def extract!(array)
      out = []
      array.reject! do |e|
        next false unless yield e
        out << e
        true
      end
      out
    end
    def ord(c)
      ruby1_8? ? c[0] : c.ord
    end
    def flatten(arr, n)
      return arr.flatten(n) unless ruby1_8_6?
      return arr if n == 0
      arr.inject([]) {|res, e| e.is_a?(Array) ? res.concat(flatten(e, n - 1)) : res << e}
    end
    def flatten_vertically(arrs)
      result = []
      arrs = arrs.map {|sub| sub.is_a?(Array) ? sub.dup : Array(sub)}
      until arrs.empty?
        arrs.reject! do |arr|
          result << arr.shift
          arr.empty?
        end
      end
      result
    end
    def set_hash(set)
      return set.hash unless ruby1_8_6?
      set.map {|e| e.hash}.uniq.sort.hash
    end
    def set_eql?(set1, set2)
      return set1.eql?(set2) unless ruby1_8_6?
      set1.to_a.uniq.sort_by {|e| e.hash}.eql?(set2.to_a.uniq.sort_by {|e| e.hash})
    end
    def inspect_obj(obj)
      return obj.inspect unless version_geq(RUBY_VERSION, "1.9.2")
      return ':' + inspect_obj(obj.to_s) if obj.is_a?(Symbol)
      return obj.inspect unless obj.is_a?(String)
      '"' + obj.gsub(/[\x00-\x7F]+/) {|s| s.inspect[1...-1]} + '"'
    end
    def extract_values(arr)
      values = []
      mapped = arr.map do |e|
        next e.gsub('{', '{{') if e.is_a?(String)
        values << e
        next "{#{values.count - 1}}"
      end
      return mapped.join, values
    end
    def inject_values(str, values)
      return [str.gsub('{{', '{')] if values.empty?
      result = (str + '{{').scan(/(.*?)(?:(\{\{)|\{(\d+)\})/m).map do |(pre, esc, n)|
        [pre, esc ? '{' : '', n ? values[n.to_i] : '']
      end.flatten(1)
      result[-2] = '' # Get rid of the extra {
      merge_adjacent_strings(result).reject {|s| s == ''}
    end
    def with_extracted_values(arr)
      str, vals = extract_values(arr)
      str = yield str
      inject_values(str, vals)
    end
    def sourcemap_name(css)
      css + ".map"
    end
    def json_escape_string(s)
      return s if s !~ /["\\\b\f\n\r\t]/
      result = ""
      s.split("").each do |c|
        case c
        when '"', "\\"
          result << "\\" << c
        when "\n" then result << "\\n"
        when "\t" then result << "\\t"
        when "\r" then result << "\\r"
        when "\f" then result << "\\f"
        when "\b" then result << "\\b"
        else
          result << c
        end
      end
      result
    end
    def json_value_of(v)
      case v
      when Fixnum
        v.to_s
      when String
        "\"" + json_escape_string(v) + "\""
      when Array
        "[" + v.map {|x| json_value_of(x)}.join(",") + "]"
      when NilClass
        "null"
      when TrueClass
        "true"
      when FalseClass
        "false"
      else
        raise ArgumentError.new("Unknown type: #{v.class.name}")
      end
    end
    VLQ_BASE_SHIFT = 5
    VLQ_BASE = 1 << VLQ_BASE_SHIFT
    VLQ_BASE_MASK = VLQ_BASE - 1
    VLQ_CONTINUATION_BIT = VLQ_BASE
    BASE64_DIGITS = ('A'..'Z').to_a  + ('a'..'z').to_a + ('0'..'9').to_a  + ['+', '/']
    BASE64_DIGIT_MAP = begin
      map = {}
      Sass::Util.enum_with_index(BASE64_DIGITS).map do |digit, i|
        map[digit] = i
      end
      map
    end
    def encode_vlq(value)
      if value < 0
        value = ((-value) << 1) | 1
      else
        value <<= 1
      end
      result = ''
      begin
        digit = value & VLQ_BASE_MASK
        value >>= VLQ_BASE_SHIFT
        if value > 0
          digit |= VLQ_CONTINUATION_BIT
        end
        result << BASE64_DIGITS[digit]
      end while value > 0
      result
    end
    URI_ESCAPE = URI.const_defined?("DEFAULT_PARSER") ? URI::DEFAULT_PARSER : URI
    def escape_uri(string)
      URI_ESCAPE.escape string
    end
    def absolute_path(path, dir_string = nil)
      return File.absolute_path(path, dir_string) unless ruby1_8?
      return File.expand_path(path, dir_string) unless path[0] == ?~
      File.expand_path(File.join(".", path), dir_string)
    end
    class StaticConditionalContext
      def initialize(set)
        @set = set
      end
      def method_missing(name, *args)
        super unless args.empty? && !block_given?
        @set.include?(name)
      end
    end
    private
    def find_encoding_error(str)
      encoding = str.encoding
      cr = Regexp.quote("\r".encode(encoding).force_encoding('BINARY'))
      lf = Regexp.quote("\n".encode(encoding).force_encoding('BINARY'))
      ff = Regexp.quote("\f".encode(encoding).force_encoding('BINARY'))
      line_break = /#{cr}#{lf}?|#{ff}|#{lf}/
      str.force_encoding("binary").split(line_break).each_with_index do |line, i|
        begin
          line.encode(encoding)
        rescue Encoding::UndefinedConversionError => e
          raise Sass::SyntaxError.new(
            "Invalid #{encoding.name} character #{undefined_conversion_error_char(e)}",
            :line => i + 1)
        end
      end
      return str, str.encoding
    end
    def lcs_table(x, y)
      c = Array.new(x.size) {[]}
      x.size.times {|i| c[i][0] = 0}
      y.size.times {|j| c[0][j] = 0}
      (1...x.size).each do |i|
        (1...y.size).each do |j|
          c[i][j] =
            if yield x[i], y[j]
              c[i - 1][j - 1] + 1
            else
              [c[i][j - 1], c[i - 1][j]].max
            end
        end
      end
      c
    end
    def lcs_backtrace(c, x, y, i, j, &block)
      return [] if i == 0 || j == 0
      if (v = yield(x[i], y[j]))
        return lcs_backtrace(c, x, y, i - 1, j - 1, &block) << v
      end
      return lcs_backtrace(c, x, y, i, j - 1, &block) if c[i][j - 1] > c[i - 1][j]
      lcs_backtrace(c, x, y, i - 1, j, &block)
    end
    singleton_methods.each {|method| module_function method}
  end
end
require 'strscan.min.rb'
  Sass::Util::MultibyteStringScanner = StringScanner
module Sass
  module Util
    class NormalizedMap
      def initialize(map = nil)
        @key_strings = {}
        @map = Util.ruby1_8? ? OrderedHash.new : {}
        map.each {|key, value| self[key] = value} if map
      end
      def normalize(key)
        key.tr("-", "_")
      end
      def denormalize(key)
        @key_strings[normalize(key)] || key
      end
      def []=(k, v)
        normalized = normalize(k)
        @map[normalized] = v
        @key_strings[normalized] = k
        v
      end
      def [](k)
        @map[normalize(k)]
      end
      def has_key?(k)
        @map.has_key?(normalize(k))
      end
      def delete(k)
        normalized = normalize(k)
        @key_strings.delete(normalized)
        @map.delete(normalized)
      end
      def as_stored
        Sass::Util.map_keys(@map) {|k| @key_strings[k]}
      end
      def empty?
        @map.empty?
      end
      def values
        @map.values
      end
      def keys
        @map.keys
      end
      def each
        @map.each {|k, v| yield(k, v)}
      end
      def size
        @map.size
      end
      def to_hash
        @map.dup
      end
      def to_a
        @map.to_a
      end
      def map
        @map.map {|k, v| yield(k, v)}
      end
      def dup
        d = super
        d.send(:instance_variable_set, "@map", @map.dup)
        d
      end
      def sort_by
        @map.sort_by {|k, v| yield k, v}
      end
      def update(map)
        map = map.as_stored if map.is_a?(NormalizedMap)
        map.each {|k, v| self[k] = v}
      end
      def method_missing(method, *args, &block)
        if Sass.tests_running
          raise ArgumentError.new("The method #{method} must be implemented explicitly")
        end
        @map.send(method, *args, &block)
      end
      if Sass::Util.ruby1_8?
        def respond_to?(method, include_private = false)
          super || @map.respond_to?(method, include_private)
        end
      end
      def respond_to_missing?(method, include_private = false)
        @map.respond_to?(method, include_private)
      end
    end
  end
end
module Sass
  module Util
    class CrossPlatformRandom
      def initialize(seed = nil)
        if Sass::Util.ruby1_8?
          srand(seed) if seed
        else
          @random = seed ? ::Random.new(seed) : ::Random.new
        end
      end
      def rand(*args)
        return @random.rand(*args) if @random
        Kernel.rand(*args)
      end
    end
  end
end
module Sass
  class << self
    attr_accessor :tests_running
  end
  def self.load_paths
    @load_paths ||= if ENV['SASS_PATH']
                      ENV['SASS_PATH'].split(Sass::Util.windows? ? ';' : ':')
                    else
                      []
                    end
  end
  def self.compile(contents, options = {})
    options[:syntax] ||= :scss
    Engine.new(contents, options).to_css
  end
  def self.compile_file(filename, *args)
    options = args.last.is_a?(Hash) ? args.pop : {}
    css_filename = args.shift
    result = Sass::Engine.for_file(filename, options).render
    if css_filename
      options[:css_filename] ||= css_filename
      open(css_filename, "w") {|css_file| css_file.write(result)}
      nil
    else
      result
    end
  end
end
module Sass::Logger; end
module Sass
  module Logger
    module LogLevel
      def self.included(base)
        base.extend(ClassMethods)
      end
      module ClassMethods
        def inherited(subclass)
          subclass.log_levels = subclass.superclass.log_levels.dup
        end
        attr_writer :log_levels
        def log_levels
          @log_levels ||= {}
        end
        def log_level?(level, min_level)
          log_levels[level] >= log_levels[min_level]
        end
        def log_level(name, options = {})
          if options[:prepend]
            level = log_levels.values.min
            level = level.nil? ? 0 : level - 1
          else
            level = log_levels.values.max
            level = level.nil? ? 0 : level + 1
          end
          log_levels.update(name => level)
          define_logger(name)
        end
        def define_logger(name, options = {})
          class_eval <<-RUBY, __FILE__, __LINE__ + 1
            def #{name}(message)
            end
          RUBY
        end
      end
    end
  end
end
class Sass::Logger::Base
  include Sass::Logger::LogLevel
  attr_accessor :log_level
  attr_accessor :disabled
  log_level :trace
  log_level :debug
  log_level :info
  log_level :warn
  log_level :error
  def initialize(log_level = :debug)
    self.log_level = log_level
  end
  def logging_level?(level)
    !disabled && self.class.log_level?(level, log_level)
  end
  def log(level, message)
    _log(level, message) if logging_level?(level)
  end
  def _log(level, message)
    Kernel.warn(message)
  end
end
module Sass
  class << self
    attr_accessor :logger
  end
  self.logger = Sass::Logger::Base.new
end
require 'digest/sha1.min.rb'
module Sass::Source
  class Position
    attr_accessor :line
    attr_accessor :offset
    def initialize(line, offset)
      @line = line
      @offset = offset
    end
    def inspect
      "#{line.inspect}:#{offset.inspect}"
    end
    def after(str)
      newlines = str.count("\n")
      Position.new(line + newlines,
        if newlines == 0
          offset + str.length
        else
          str.length - str.rindex("\n") - 1
        end)
    end
  end
end
module Sass::Source
  class Range
    attr_accessor :start_pos
    attr_accessor :end_pos
    attr_accessor :file
    attr_accessor :importer
    def initialize(start_pos, end_pos, file, importer = nil)
      @start_pos = start_pos
      @end_pos = end_pos
      @file = file
      @importer = importer
    end
    def inspect
      "(#{start_pos.inspect} to #{end_pos.inspect}#{" in #{@file}" if @file})"
    end
  end
end
module Sass::Source
  class Map
    class Mapping < Struct.new(:input, :output)
      def inspect
        "#{input.inspect} => #{output.inspect}"
      end
    end
    attr_reader :data
    def initialize
      @data = []
    end
    def add(input, output)
      @data.push(Mapping.new(input, output))
    end
    def shift_output_lines(delta)
      return if delta == 0
      @data.each do |m|
        m.output.start_pos.line += delta
        m.output.end_pos.line += delta
      end
    end
    def shift_output_offsets(delta)
      return if delta == 0
      @data.each do |m|
        break if m.output.start_pos.line > 1
        m.output.start_pos.offset += delta
        m.output.end_pos.offset += delta if m.output.end_pos.line > 1
      end
    end
    def to_json(options)
      css_uri, css_path, sourcemap_path =
        options[:css_uri], options[:css_path], options[:sourcemap_path]
      unless css_uri || (css_path && sourcemap_path)
        raise ArgumentError.new("Sass::Source::Map#to_json requires either " \
          "the :css_uri option or both the :css_path and :soucemap_path options.")
      end
      css_path &&= Sass::Util.pathname(Sass::Util.absolute_path(css_path))
      sourcemap_path &&= Sass::Util.pathname(Sass::Util.absolute_path(sourcemap_path))
      css_uri ||= Sass::Util.file_uri_from_path(
        Sass::Util.relative_path_from(css_path, sourcemap_path.dirname))
      result = "{\n"
      write_json_field(result, "version", 3, true)
      source_uri_to_id = {}
      id_to_source_uri = {}
      id_to_contents = {} if options[:type] == :inline
      next_source_id = 0
      line_data = []
      segment_data_for_line = []
      previous_target_line = nil
      previous_target_offset = 1
      previous_source_line = 1
      previous_source_offset = 1
      previous_source_id = 0
      @data.each do |m|
        file, importer = m.input.file, m.input.importer
        if options[:type] == :inline
          source_uri = file
        else
          sourcemap_dir = sourcemap_path && sourcemap_path.dirname.to_s
          sourcemap_dir = nil if options[:type] == :file
          source_uri = importer && importer.public_url(file, sourcemap_dir)
          next unless source_uri
        end
        current_source_id = source_uri_to_id[source_uri]
        unless current_source_id
          current_source_id = next_source_id
          next_source_id += 1
          source_uri_to_id[source_uri] = current_source_id
          id_to_source_uri[current_source_id] = source_uri
          if options[:type] == :inline
            id_to_contents[current_source_id] =
              importer.find(file, {}).instance_variable_get('@template')
          end
        end
        [
          [m.input.start_pos, m.output.start_pos],
          [m.input.end_pos, m.output.end_pos]
        ].each do |source_pos, target_pos|
          if previous_target_line != target_pos.line
            line_data.push(segment_data_for_line.join(",")) unless segment_data_for_line.empty?
            (target_pos.line - 1 - (previous_target_line || 0)).times {line_data.push("")}
            previous_target_line = target_pos.line
            previous_target_offset = 1
            segment_data_for_line = []
          end
          segment = ""
          segment << Sass::Util.encode_vlq(target_pos.offset - previous_target_offset)
          previous_target_offset = target_pos.offset
          segment << Sass::Util.encode_vlq(current_source_id - previous_source_id)
          previous_source_id = current_source_id
          segment << Sass::Util.encode_vlq(source_pos.line - previous_source_line)
          previous_source_line = source_pos.line
          segment << Sass::Util.encode_vlq(source_pos.offset - previous_source_offset)
          previous_source_offset = source_pos.offset
          segment_data_for_line.push(segment)
          previous_target_line = target_pos.line
        end
      end
      line_data.push(segment_data_for_line.join(","))
      write_json_field(result, "mappings", line_data.join(";"))
      source_names = []
      (0...next_source_id).each {|id| source_names.push(id_to_source_uri[id].to_s)}
      write_json_field(result, "sources", source_names)
      if options[:type] == :inline
        write_json_field(result, "sourcesContent",
          (0...next_source_id).map {|id| id_to_contents[id]})
      end
      write_json_field(result, "names", [])
      write_json_field(result, "file", css_uri)
      result << "\n}"
      result
    end
    private
    def write_json_field(out, name, value, is_first = false)
      out << (is_first ? "" : ",\n") <<
        "\"" <<
        Sass::Util.json_escape_string(name) <<
        "\": " <<
        Sass::Util.json_value_of(value)
    end
  end
end
module Sass
  module Tree
    class Node
      include Enumerable
      def self.inherited(base)
        node_name = base.name.gsub(/.*::(.*?)Node$/, '\\1').downcase
        base.instance_eval <<-METHODS
          def node_name
            :#{node_name}
          end
          def visit_method
            :visit_#{node_name}
          end
          def invalid_child_method_name
            :"invalid_#{node_name}_child?"
          end
          def invalid_parent_method_name
            :"invalid_#{node_name}_parent?"
          end
        METHODS
      end
      attr_reader :children
      attr_accessor :has_children
      attr_accessor :line
      attr_accessor :source_range
      attr_writer :filename
      attr_reader :options
      def initialize
        @children = []
      end
      def options=(options)
        Sass::Tree::Visitors::SetOptions.visit(self, options)
      end
      def children=(children)
        self.has_children ||= !children.empty?
        @children = children
      end
      def filename
        @filename || (@options && @options[:filename])
      end
      def <<(child)
        return if child.nil?
        if child.is_a?(Array)
          child.each {|c| self << c}
        else
          self.has_children = true
          @children << child
        end
      end
      def ==(other)
        self.class == other.class && other.children == children
      end
      def invisible?; false; end
      def style
        @options[:style]
      end
      def css
        Sass::Tree::Visitors::ToCss.new.visit(self)
      end
      def css_with_sourcemap
        visitor = Sass::Tree::Visitors::ToCss.new(:build_source_mapping)
        result = visitor.visit(self)
        return result, visitor.source_mapping
      end
      def inspect
        return self.class.to_s unless has_children
        "(#{self.class} #{children.map {|c| c.inspect}.join(' ')})"
      end
      def each
        yield self
        children.each {|c| c.each {|n| yield n}}
      end
      def to_sass(options = {})
        Sass::Tree::Visitors::Convert.visit(self, options, :sass)
      end
      def to_scss(options = {})
        Sass::Tree::Visitors::Convert.visit(self, options, :scss)
      end
      def deep_copy
        Sass::Tree::Visitors::DeepCopy.visit(self)
      end
      def bubbles?
        false
      end
      protected
      def balance(*args)
        res = Sass::Shared.balance(*args)
        return res if res
        raise Sass::SyntaxError.new("Unbalanced brackets.", :line => line)
      end
    end
  end
end
module Sass
  module Tree
    class RootNode < Node
      attr_reader :template
      def initialize(template)
        super()
        @template = template
      end
      def render
        css_tree.css
      end
      def render_with_sourcemap
        css_tree.css_with_sourcemap
      end
      private
      def css_tree
        Visitors::CheckNesting.visit(self)
        result = Visitors::Perform.visit(self)
        Visitors::CheckNesting.visit(result) # Check again to validate mixins
        result, extends = Visitors::Cssize.visit(result)
        Visitors::Extend.visit(result, extends)
        result
      end
    end
  end
end
module Sass::Tree
  class RuleNode < Node
    PARENT = '&'
    attr_accessor :rule
    attr_accessor :parsed_rules
    attr_accessor :resolved_rules
    attr_accessor :tabs
    attr_accessor :selector_source_range
    attr_accessor :group_end
    attr_accessor :stack_trace
    def initialize(rule, selector_source_range = nil)
      if rule.is_a?(Sass::Selector::CommaSequence)
        @rule = [rule.to_s]
        @parsed_rules = rule
      else
        merged = Sass::Util.merge_adjacent_strings(rule)
        @rule = Sass::Util.strip_string_array(merged)
        try_to_parse_non_interpolated_rules
      end
      @selector_source_range = selector_source_range
      @tabs = 0
      super()
    end
    def line=(line)
      @parsed_rules.line = line if @parsed_rules
      super
    end
    def filename=(filename)
      @parsed_rules.filename = filename if @parsed_rules
      super
    end
    def ==(other)
      self.class == other.class && rule == other.rule && super
    end
    def add_rules(node)
      @rule = Sass::Util.strip_string_array(
        Sass::Util.merge_adjacent_strings(@rule + ["\n"] + node.rule))
      try_to_parse_non_interpolated_rules
    end
    def continued?
      last = @rule.last
      last.is_a?(String) && last[-1] == ?,
    end
    def debug_info
      {:filename => filename && ("file://" + Sass::Util.escape_uri(filename)), #BT+
       :line => line}
    end
    def invisible?
      resolved_rules.members.all? {|seq| seq.has_placeholder?}
    end
    private
    def try_to_parse_non_interpolated_rules
      @parsed_rules = nil
      return unless @rule.all? {|t| t.kind_of?(String)}
      parser = Sass::SCSS::StaticParser.new(@rule.join.strip, nil, nil, 1)
      @parsed_rules = parser.parse_selector rescue nil
    end
  end
end
module Sass::Tree
  class CommentNode < Node
    attr_accessor :value
    attr_accessor :resolved_value
    attr_accessor :type
    def initialize(value, type)
      @value = Sass::Util.with_extracted_values(value) {|str| normalize_indentation str}
      @type = type
      super()
    end
    def ==(other)
      self.class == other.class && value == other.value && type == other.type
    end
    def invisible?
      case @type
      when :loud; false
      when :silent; true
      else; style == :compressed
      end
    end
    def lines
      @value.inject(0) do |s, e|
        next s + e.count("\n") if e.is_a?(String)
        next s
      end
    end
    private
    def normalize_indentation(str)
      ind = str.split("\n").inject(str[/^[ \t]*/].split("")) do |pre, line|
        line[/^[ \t]*/].split("").zip(pre).inject([]) do |arr, (a, b)|
          break arr if a != b
          arr << a
        end
      end.join
      str.gsub(/^#{ind}/, '')
    end
  end
end
module Sass::Tree
  class PropNode < Node
    attr_accessor :name
    attr_accessor :resolved_name
    attr_accessor :value
    attr_accessor :resolved_value
    attr_accessor :tabs
    attr_accessor :name_source_range
    attr_accessor :value_source_range
    def initialize(name, value, prop_syntax)
      @name = Sass::Util.strip_string_array(
        Sass::Util.merge_adjacent_strings(name))
      @value = value
      @tabs = 0
      @prop_syntax = prop_syntax
      super()
    end
    def ==(other)
      self.class == other.class && name == other.name && value == other.value && super
    end
    def pseudo_class_selector_message
      if @prop_syntax == :new ||
          !value.is_a?(Sass::Script::Tree::Literal) ||
          !value.value.is_a?(Sass::Script::Value::String) ||
          !value.value.value.empty?
        return ""
      end
      "\nIf #{declaration.dump} should be a selector, use \"\\#{declaration}\" instead."
    end
    def declaration(opts = {:old => @prop_syntax == :old}, fmt = :sass)
      name = self.name.map {|n| n.is_a?(String) ? n : n.to_sass(opts)}.join
      if name[0] == ?:
        raise Sass::SyntaxError.new("The \"#{name}: #{self.class.val_to_sass(value, opts)}\"" +
                                    " hack is not allowed in the Sass indented syntax")
      end
      old = opts[:old] && fmt == :sass
      initial = old ? ':' : ''
      mid = old ? '' : ':'
      "#{initial}#{name}#{mid} #{self.class.val_to_sass(value, opts)}".rstrip
    end
    def invisible?
      resolved_value.empty?
    end
    private
    def check!
      if @options[:property_syntax] && @options[:property_syntax] != @prop_syntax
        raise Sass::SyntaxError.new(
          "Illegal property syntax: can't use #{@prop_syntax} syntax when " +
          ":property_syntax => #{@options[:property_syntax].inspect} is set.")
      end
    end
    class << self
      def val_to_sass(value, opts)
        val_to_sass_comma(value, opts).to_sass(opts)
      end
      private
      def val_to_sass_comma(node, opts)
        return node unless node.is_a?(Sass::Script::Tree::Operation)
        return val_to_sass_concat(node, opts) unless node.operator == :comma
        Sass::Script::Tree::Operation.new(
          val_to_sass_concat(node.operand1, opts),
          val_to_sass_comma(node.operand2, opts),
          node.operator)
      end
      def val_to_sass_concat(node, opts)
        return node unless node.is_a?(Sass::Script::Tree::Operation)
        return val_to_sass_div(node, opts) unless node.operator == :space
        Sass::Script::Tree::Operation.new(
          val_to_sass_div(node.operand1, opts),
          val_to_sass_concat(node.operand2, opts),
          node.operator)
      end
      def val_to_sass_div(node, opts)
        unless node.is_a?(Sass::Script::Tree::Operation) && node.operator == :div &&
            node.operand1.is_a?(Sass::Script::Tree::Literal) &&
            node.operand1.value.is_a?(Sass::Script::Value::Number) &&
            node.operand2.is_a?(Sass::Script::Tree::Literal) &&
            node.operand2.value.is_a?(Sass::Script::Value::Number) &&
            (!node.operand1.value.original || !node.operand2.value.original)
          return node
        end
        Sass::Script::Value::String.new("(#{node.to_sass(opts)})")
      end
    end
  end
end
module Sass::Tree
  class DirectiveNode < Node
    attr_accessor :value
    attr_accessor :resolved_value
    attr_accessor :tabs
    attr_accessor :group_end
    def initialize(value)
      @value = value
      @tabs = 0
      super()
    end
    def self.resolved(value)
      node = new([value])
      node.resolved_value = value
      node
    end
    def name
      @name ||= value.first.gsub(/ .*$/, '')
    end
    def normalized_name
      @normalized_name ||= name.gsub(/^(@)(?:-[a-zA-Z0-9]+-)?/, '\1').downcase
    end
    def bubbles?
      has_children
    end
  end
end
module Sass::Tree
  class MediaNode < DirectiveNode
    attr_accessor :query
    attr_accessor :resolved_query
    def initialize(query)
      @query = query
      super('')
    end
    def value; raise NotImplementedError; end
    def name; '@media'; end
    def resolved_value
      @resolved_value ||= "@media #{resolved_query.to_css}"
    end
    def invisible?
      children.all? {|c| c.invisible?}
    end
  end
end
module Sass::Tree
  class SupportsNode < DirectiveNode
    attr_accessor :name
    attr_accessor :condition
    def initialize(name, condition)
      @name = name
      @condition = condition
      super('')
    end
    def value; raise NotImplementedError; end
    def resolved_value
      @resolved_value ||= "@#{name} #{condition.to_css}"
    end
    def invisible?
      children.all? {|c| c.invisible?}
    end
  end
end
module Sass::Tree
  class CssImportNode < DirectiveNode
    attr_accessor :uri
    attr_accessor :resolved_uri
    attr_accessor :query
    attr_accessor :resolved_query
    def initialize(uri, query = [])
      @uri = uri
      @query = query
      super('')
    end
    def self.resolved(uri)
      node = new(uri)
      node.resolved_uri = uri
      node
    end
    def value; raise NotImplementedError; end
    def resolved_value
      @resolved_value ||=
        begin
          str = "@import #{resolved_uri}"
          str << " #{resolved_query.to_css}" if resolved_query
          str
        end
    end
  end
end
module Sass
  module Tree
    class VariableNode < Node
      attr_reader :name
      attr_accessor :expr
      attr_reader :guarded
      attr_reader :global
      def initialize(name, expr, guarded, global)
        @name = name
        @expr = expr
        @guarded = guarded
        @global = global
        super()
      end
    end
  end
end
module Sass
  module Tree
    class MixinDefNode < Node
      attr_reader :name
      attr_accessor :args
      attr_accessor :splat
      attr_accessor :has_content
      def initialize(name, args, splat)
        @name = name
        @args = args
        @splat = splat
        super()
      end
    end
  end
end
module Sass::Tree
  class MixinNode < Node
    attr_reader :name
    attr_accessor :args
    attr_accessor :keywords
    attr_accessor :splat
    attr_accessor :kwarg_splat
    def initialize(name, args, keywords, splat, kwarg_splat)
      @name = name
      @args = args
      @keywords = keywords
      @splat = splat
      @kwarg_splat = kwarg_splat
      super()
    end
  end
end
module Sass::Tree
  class TraceNode < Node
    attr_reader :name
    def initialize(name)
      @name = name
      self.has_children = true
      super()
    end
    def self.from_node(name, node)
      trace = new(name)
      trace.line = node.line
      trace.filename = node.filename
      trace.options = node.options
      trace
    end
  end
end
module Sass
  module Tree
    class ContentNode < Node
    end
  end
end
module Sass
  module Tree
    class FunctionNode < Node
      attr_reader :name
      attr_accessor :args
      attr_accessor :splat
      def normalized_name
        @normalized_name ||= name.gsub(/^(?:-[a-zA-Z0-9]+-)?/, '\1')
      end
      def initialize(name, args, splat)
        @name = name
        @args = args
        @splat = splat
        super()
        if %w[and or not].include?(name)
          raise Sass::SyntaxError.new("Invalid function name \"#{name}\".")
        end
      end
    end
  end
end
module Sass
  module Tree
    class ReturnNode < Node
      attr_accessor :expr
      def initialize(expr)
        @expr = expr
        super()
      end
    end
  end
end
module Sass::Tree
  class ExtendNode < Node
    attr_accessor :resolved_selector
    attr_accessor :selector
    attr_accessor :selector_source_range
    def optional?; @optional; end
    def initialize(selector, optional, selector_source_range)
      @selector = selector
      @optional = optional
      @selector_source_range = selector_source_range
      super()
    end
  end
end
module Sass::Tree
  class IfNode < Node
    attr_accessor :expr
    attr_accessor :else
    def initialize(expr)
      @expr = expr
      @last_else = self
      super()
    end
    def add_else(node)
      @last_else.else = node
      @last_else = node
    end
    def _dump(f)
      Marshal.dump([expr, self.else, children])
    end
    def self._load(data)
      expr, else_, children = Marshal.load(data)
      node = IfNode.new(expr)
      node.else = else_
      node.children = children
      node.instance_variable_set('@last_else',
        node.else ? node.else.instance_variable_get('@last_else') : node)
      node
    end
  end
end
module Sass::Tree
  class WhileNode < Node
    attr_accessor :expr
    def initialize(expr)
      @expr = expr
      super()
    end
  end
end
module Sass::Tree
  class ForNode < Node
    attr_reader :var
    attr_accessor :from
    attr_accessor :to
    attr_reader :exclusive
    def initialize(var, from, to, exclusive)
      @var = var
      @from = from
      @to = to
      @exclusive = exclusive
      super()
    end
  end
end
module Sass::Tree
  class EachNode < Node
    attr_reader :vars
    attr_accessor :list
    def initialize(vars, list)
      @vars = vars
      @list = list
      super()
    end
  end
end
module Sass
  module Tree
    class DebugNode < Node
      attr_accessor :expr
      def initialize(expr)
        @expr = expr
        super()
      end
    end
  end
end
module Sass
  module Tree
    class WarnNode < Node
      attr_accessor :expr
      def initialize(expr)
        @expr = expr
        super()
      end
    end
  end
end
module Sass
  module Tree
    class ImportNode < RootNode
      attr_reader :imported_filename
      attr_writer :imported_file
      def initialize(imported_filename)
        @imported_filename = imported_filename
        super(nil)
      end
      def invisible?; to_s.empty?; end
      def imported_file
        @imported_file ||= import
      end
      def css_import?
        if @imported_filename =~ /\.css$/
          @imported_filename
        elsif imported_file.is_a?(String) && imported_file =~ /\.css$/
          imported_file
        end
      end
      private
      def import
        paths = @options[:load_paths]
        if @options[:importer]
          f = @options[:importer].find_relative(
            @imported_filename, @options[:filename], options_for_importer)
          return f if f
        end
        paths.each do |p|
          f = p.find(@imported_filename, options_for_importer)
          return f if f
        end
        message = "File to import not found or unreadable: #{@imported_filename}.\n"
        if paths.size == 1
          message << "Load path: #{paths.first}"
        else
          message << "Load paths:\n  " << paths.join("\n  ")
        end
        raise SyntaxError.new(message)
      rescue SyntaxError => e
        raise SyntaxError.new(e.message, :line => line, :filename => @filename)
      end
      def options_for_importer
        @options.merge(:_from_import_node => true)
      end
    end
  end
end
module Sass::Tree
  class CharsetNode < Node
    attr_accessor :name
    def initialize(name)
      @name = name
      super()
    end
    def invisible?
      !Sass::Util.ruby1_8?
    end
  end
end
module Sass
  module Tree
    class AtRootNode < Node
      attr_accessor :query
      attr_accessor :resolved_type
      attr_accessor :resolved_value
      attr_accessor :tabs
      attr_accessor :group_end
      def initialize(query = nil)
        super()
        @query = Sass::Util.strip_string_array(Sass::Util.merge_adjacent_strings(query)) if query
        @tabs = 0
      end
      def exclude?(directive)
        if resolved_type == :with
          return false if resolved_value.include?('all')
          !resolved_value.include?(directive)
        else # resolved_type == :without
          return true if resolved_value.include?('all')
          resolved_value.include?(directive)
        end
      end
      def exclude_node?(node)
        return exclude?(node.name.gsub(/^@/, '')) if node.is_a?(Sass::Tree::DirectiveNode)
        return exclude?('keyframes') if node.is_a?(Sass::Tree::KeyframeRuleNode)
        exclude?('rule') && node.is_a?(Sass::Tree::RuleNode)
      end
      def bubbles?
        true
      end
    end
  end
end
module Sass::Tree
  class KeyframeRuleNode < Node
    attr_accessor :resolved_value
    def initialize(resolved_value)
      @resolved_value = resolved_value
      super()
    end
  end
end
module Sass
  module Tree
    class ErrorNode < Node
      attr_accessor :expr
      def initialize(expr)
        @expr = expr
        super()
      end
    end
  end
end
module Sass::Tree::Visitors
  class Base
    def self.visit(root)
      new.send(:visit, root)
    end
    protected
    def visit(node)
      if respond_to?(node.class.visit_method, true)
        send(node.class.visit_method, node) {visit_children(node)}
      else
        visit_children(node)
      end
    end
    def visit_children(parent)
      parent.children.map {|c| visit(c)}
    end
    def self.node_name(node)
      Sass::Util.deprecated(self, "Call node.class.node_name instead.")
      node.class.node_name
    end
    def visit_if(node)
      yield
      visit(node.else) if node.else
      node
    end
  end
end
class Sass::Tree::Visitors::Perform < Sass::Tree::Visitors::Base
  class << self
    def visit(root, environment = nil)
      new(environment).send(:visit, root)
    end
    def perform_arguments(callable, args, splat, environment)
      desc = "#{callable.type.capitalize} #{callable.name}"
      downcase_desc = "#{callable.type} #{callable.name}"
      old_keywords_accessed = splat.keywords_accessed
      keywords = splat.keywords
      splat.keywords_accessed = old_keywords_accessed
      begin
        unless keywords.empty?
          unknown_args = Sass::Util.array_minus(keywords.keys,
            callable.args.map {|var| var.first.underscored_name})
          if callable.splat && unknown_args.include?(callable.splat.underscored_name)
            raise Sass::SyntaxError.new("Argument $#{callable.splat.name} of #{downcase_desc} " +
                                        "cannot be used as a named argument.")
          elsif unknown_args.any?
            description = unknown_args.length > 1 ? 'the following arguments:' : 'an argument named'
            raise Sass::SyntaxError.new("#{desc} doesn't have #{description} " +
                                        "#{unknown_args.map {|name| "$#{name}"}.join ', '}.")
          end
        end
      rescue Sass::SyntaxError => keyword_exception
      end
      return if keyword_exception && !callable.splat
      splat_sep = :comma
      if splat
        args += splat.to_a
        splat_sep = splat.separator
      end
      if args.size > callable.args.size && !callable.splat
        extra_args_because_of_splat = splat && args.size - splat.to_a.size <= callable.args.size
        takes = callable.args.size
        passed = args.size
        message = "#{desc} takes #{takes} argument#{'s' unless takes == 1} " +
          "but #{passed} #{passed == 1 ? 'was' : 'were'} passed."
        raise Sass::SyntaxError.new(message) unless extra_args_because_of_splat
        Sass::Util.sass_warn("WARNING: #{message}\n" +
          environment.stack.to_s.gsub(/^/m, " " * 8) + "\n" +
          "This will be an error in future versions of Sass.")
      end
      env = Sass::Environment.new(callable.environment)
      callable.args.zip(args[0...callable.args.length]) do |(var, default), value|
        if value && keywords.has_key?(var.name)
          raise Sass::SyntaxError.new("#{desc} was passed argument $#{var.name} " +
                                      "both by position and by name.")
        end
        value ||= keywords.delete(var.name)
        value ||= default && default.perform(env)
        raise Sass::SyntaxError.new("#{desc} is missing argument #{var.inspect}.") unless value
        env.set_local_var(var.name, value)
      end
      if callable.splat
        rest = args[callable.args.length..-1] || []
        arg_list = Sass::Script::Value::ArgList.new(rest, keywords, splat_sep)
        arg_list.options = env.options
        env.set_local_var(callable.splat.name, arg_list)
      end
      yield env
    rescue StandardError => e
    ensure
      if keyword_exception &&
          !(arg_list && arg_list.keywords_accessed) &&
          (e.nil? || e.is_a?(Sass::SyntaxError))
        raise keyword_exception
      elsif e
        raise e
      end
    end
    def perform_splat(splat, performed_keywords, kwarg_splat, environment)
      args, kwargs, separator = [], nil, :comma
      if splat
        splat = splat.perform(environment)
        separator = splat.separator || separator
        if splat.is_a?(Sass::Script::Value::ArgList)
          args = splat.to_a
          kwargs = splat.keywords
        elsif splat.is_a?(Sass::Script::Value::Map)
          kwargs = arg_hash(splat)
        else
          args = splat.to_a
        end
      end
      kwargs ||= Sass::Util::NormalizedMap.new
      kwargs.update(performed_keywords)
      if kwarg_splat
        kwarg_splat = kwarg_splat.perform(environment)
        unless kwarg_splat.is_a?(Sass::Script::Value::Map)
          raise Sass::SyntaxError.new("Variable keyword arguments must be a map " +
                                      "(was #{kwarg_splat.inspect}).")
        end
        kwargs.update(arg_hash(kwarg_splat))
      end
      Sass::Script::Value::ArgList.new(args, kwargs, separator)
    end
    private
    def arg_hash(map)
      Sass::Util.map_keys(map.to_h) do |key|
        next key.value if key.is_a?(Sass::Script::Value::String)
        raise Sass::SyntaxError.new("Variable keyword argument map must have string keys.\n" +
          "#{key.inspect} is not a string in #{map.inspect}.")
      end
    end
  end
  protected
  def initialize(env)
    @environment = env
  end
  def visit(node)
    return super(node.dup) unless @environment
    @environment.stack.with_base(node.filename, node.line) {super(node.dup)}
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:filename => node.filename, :line => node.line)
    raise e
  end
  def visit_children(parent)
    with_environment Sass::Environment.new(@environment, parent.options) do
      parent.children = super.flatten
      parent
    end
  end
  def with_environment(env)
    old_env, @environment = @environment, env
    yield
  ensure
    @environment = old_env
  end
  def visit_root(node)
    yield
  rescue Sass::SyntaxError => e
    e.sass_template ||= node.template
    raise e
  end
  def visit_comment(node)
    return [] if node.invisible?
    node.resolved_value = run_interp_no_strip(node.value)
    node.resolved_value.gsub!(/\\([\\#])/, '\1')
    node
  end
  def visit_debug(node)
    res = node.expr.perform(@environment)
    if res.is_a?(Sass::Script::Value::String)
      res = res.value
    else
      res = res.to_sass
    end
    if node.filename
      Sass::Util.sass_warn "#{node.filename}:#{node.line} DEBUG: #{res}"
    else
      Sass::Util.sass_warn "Line #{node.line} DEBUG: #{res}"
    end
    []
  end
  def visit_error(node)
    res = node.expr.perform(@environment)
    if res.is_a?(Sass::Script::Value::String)
      res = res.value
    else
      res = res.to_sass
    end
    raise Sass::SyntaxError.new(res)
  end
  def visit_each(node)
    list = node.list.perform(@environment)
    with_environment Sass::SemiGlobalEnvironment.new(@environment) do
      list.to_a.map do |value|
        if node.vars.length == 1
          @environment.set_local_var(node.vars.first, value)
        else
          node.vars.zip(value.to_a) do |(var, sub_value)|
            @environment.set_local_var(var, sub_value || Sass::Script::Value::Null.new)
          end
        end
        node.children.map {|c| visit(c)}
      end.flatten
    end
  end
  def visit_extend(node)
    parser = Sass::SCSS::StaticParser.new(run_interp(node.selector),
      node.filename, node.options[:importer], node.line)
    node.resolved_selector = parser.parse_selector
    node
  end
  def visit_for(node)
    from = node.from.perform(@environment)
    to = node.to.perform(@environment)
    from.assert_int!
    to.assert_int!
    to = to.coerce(from.numerator_units, from.denominator_units)
    direction = from.to_i > to.to_i ? -1 : 1
    range = Range.new(direction * from.to_i, direction * to.to_i, node.exclusive)
    with_environment Sass::SemiGlobalEnvironment.new(@environment) do
      range.map do |i|
        @environment.set_local_var(node.var,
          Sass::Script::Value::Number.new(direction * i,
            from.numerator_units, from.denominator_units))
        node.children.map {|c| visit(c)}
      end.flatten
    end
  end
  def visit_function(node)
    env = Sass::Environment.new(@environment, node.options)
    if node.normalized_name == 'calc' || node.normalized_name == 'element' ||
        node.name == 'expression' || node.name == 'url'
      Sass::Util.sass_warn <<WARNING
DEPRECATION WARNING on line #{node.line}#{" of #{node.filename}" if node.filename}:
Naming a function "#{node.name}" is disallowed and will be an error in future versions of Sass.
This name conflicts with an existing CSS function with special parse rules.
WARNING
    end
    @environment.set_local_function(node.name,
      Sass::Callable.new(node.name, node.args, node.splat, env,
                         node.children, !:has_content, "function"))
    []
  end
  def visit_if(node)
    if node.expr.nil? || node.expr.perform(@environment).to_bool
      with_environment Sass::SemiGlobalEnvironment.new(@environment) do
        node.children.map {|c| visit(c)}
      end.flatten
    elsif node.else
      visit(node.else)
    else
      []
    end
  end
  def visit_import(node)
    if (path = node.css_import?)
      resolved_node = Sass::Tree::CssImportNode.resolved("url(#{path})")
      resolved_node.source_range = node.source_range
      return resolved_node
    end
    file = node.imported_file
    if @environment.stack.frames.any? {|f| f.is_import? && f.filename == file.options[:filename]}
      handle_import_loop!(node)
    end
    begin
      @environment.stack.with_import(node.filename, node.line) do
        root = file.to_tree
        Sass::Tree::Visitors::CheckNesting.visit(root)
        node.children = root.children.map {|c| visit(c)}.flatten
        node
      end
    rescue Sass::SyntaxError => e
      e.modify_backtrace(:filename => node.imported_file.options[:filename])
      e.add_backtrace(:filename => node.filename, :line => node.line)
      raise e
    end
  end
  def visit_mixindef(node)
    env = Sass::Environment.new(@environment, node.options)
    @environment.set_local_mixin(node.name,
      Sass::Callable.new(node.name, node.args, node.splat, env,
                         node.children, node.has_content, "mixin"))
    []
  end
  def visit_mixin(node)
    @environment.stack.with_mixin(node.filename, node.line, node.name) do
      mixin = @environment.mixin(node.name)
      raise Sass::SyntaxError.new("Undefined mixin '#{node.name}'.") unless mixin
      if node.children.any? && !mixin.has_content
        raise Sass::SyntaxError.new(%Q{Mixin "#{node.name}" does not accept a content block.})
      end
      args = node.args.map {|a| a.perform(@environment)}
      keywords = Sass::Util.map_vals(node.keywords) {|v| v.perform(@environment)}
      splat = self.class.perform_splat(node.splat, keywords, node.kwarg_splat, @environment)
      self.class.perform_arguments(mixin, args, splat, @environment) do |env|
        env.caller = Sass::Environment.new(@environment)
        env.content = [node.children, @environment] if node.has_children
        trace_node = Sass::Tree::TraceNode.from_node(node.name, node)
        with_environment(env) {trace_node.children = mixin.tree.map {|c| visit(c)}.flatten}
        trace_node
      end
    end
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:mixin => node.name, :line => node.line)
    e.add_backtrace(:line => node.line)
    raise e
  end
  def visit_content(node)
    content, content_env = @environment.content
    return [] unless content
    @environment.stack.with_mixin(node.filename, node.line, '@content') do
      trace_node = Sass::Tree::TraceNode.from_node('@content', node)
      content_env = Sass::Environment.new(content_env)
      content_env.caller = Sass::Environment.new(@environment)
      with_environment(content_env) do
        trace_node.children = content.map {|c| visit(c.dup)}.flatten
      end
      trace_node
    end
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:mixin => '@content', :line => node.line)
    e.add_backtrace(:line => node.line)
    raise e
  end
  def visit_prop(node)
    node.resolved_name = run_interp(node.name)
    val = node.value.perform(@environment)
    node.resolved_value = val.to_s
    node.value_source_range = val.source_range if val.source_range
    yield
  end
  def visit_return(node)
    throw :_sass_return, node.expr.perform(@environment)
  end
  def visit_rule(node)
    old_at_root_without_rule = @at_root_without_rule
    parser = Sass::SCSS::StaticParser.new(run_interp(node.rule),
      node.filename, node.options[:importer], node.line)
    if @in_keyframes
      keyframe_rule_node = Sass::Tree::KeyframeRuleNode.new(parser.parse_keyframes_selector)
      keyframe_rule_node.options = node.options
      keyframe_rule_node.line = node.line
      keyframe_rule_node.filename = node.filename
      keyframe_rule_node.source_range = node.source_range
      keyframe_rule_node.has_children = node.has_children
      with_environment Sass::Environment.new(@environment, node.options) do
        keyframe_rule_node.children = node.children.map {|c| visit(c)}.flatten
      end
      keyframe_rule_node
    else
      @at_root_without_rule = false
      node.parsed_rules ||= parser.parse_selector
      node.resolved_rules = node.parsed_rules.resolve_parent_refs(
        @environment.selector, !old_at_root_without_rule)
      node.stack_trace = @environment.stack.to_s if node.options[:trace_selectors]
      with_environment Sass::Environment.new(@environment, node.options) do
        @environment.selector = node.resolved_rules
        node.children = node.children.map {|c| visit(c)}.flatten
      end
      node
    end
  ensure
    @at_root_without_rule = old_at_root_without_rule
  end
  def visit_atroot(node)
    if node.query
      parser = Sass::SCSS::StaticParser.new(run_interp(node.query),
        node.filename, node.options[:importer], node.line)
      node.resolved_type, node.resolved_value = parser.parse_static_at_root_query
    else
      node.resolved_type, node.resolved_value = :without, ['rule']
    end
    old_at_root_without_rule = @at_root_without_rule
    old_in_keyframes = @in_keyframes
    @at_root_without_rule = true if node.exclude?('rule')
    @in_keyframes = false if node.exclude?('keyframes')
    yield
  ensure
    @in_keyframes = old_in_keyframes
    @at_root_without_rule = old_at_root_without_rule
  end
  def visit_variable(node)
    env = @environment
    env = env.global_env if node.global
    if node.guarded
      var = env.var(node.name)
      return [] if var && !var.null?
    end
    val = node.expr.perform(@environment)
    if node.expr.source_range
      val.source_range = node.expr.source_range
    else
      val.source_range = node.source_range
    end
    env.set_var(node.name, val)
    []
  end
  def visit_warn(node)
    res = node.expr.perform(@environment)
    res = res.value if res.is_a?(Sass::Script::Value::String)
    msg = "WARNING: #{res}\n         "
    msg << @environment.stack.to_s.gsub("\n", "\n         ") << "\n"
    Sass::Util.sass_warn msg
    []
  end
  def visit_while(node)
    children = []
    with_environment Sass::SemiGlobalEnvironment.new(@environment) do
      children += node.children.map {|c| visit(c)} while node.expr.perform(@environment).to_bool
    end
    children.flatten
  end
  def visit_directive(node)
    node.resolved_value = run_interp(node.value)
    old_in_keyframes, @in_keyframes = @in_keyframes, node.normalized_name == "@keyframes"
    with_environment Sass::Environment.new(@environment) do
      node.children = node.children.map {|c| visit(c)}.flatten
      node
    end
  ensure
    @in_keyframes = old_in_keyframes
  end
  def visit_media(node)
    parser = Sass::SCSS::StaticParser.new(run_interp(node.query),
      node.filename, node.options[:importer], node.line)
    node.resolved_query ||= parser.parse_media_query_list
    yield
  end
  def visit_supports(node)
    node.condition = node.condition.deep_copy
    node.condition.perform(@environment)
    yield
  end
  def visit_cssimport(node)
    node.resolved_uri = run_interp([node.uri])
    if node.query && !node.query.empty?
      parser = Sass::SCSS::StaticParser.new(run_interp(node.query),
        node.filename, node.options[:importer], node.line)
      node.resolved_query ||= parser.parse_media_query_list
    end
    yield
  end
  private
  def run_interp_no_strip(text)
    text.map do |r|
      next r if r.is_a?(String)
      r.perform(@environment).to_s(:quote => :none)
    end.join
  end
  def run_interp(text)
    run_interp_no_strip(text).strip
  end
  def handle_import_loop!(node)
    msg = "An @import loop has been found:"
    files = @environment.stack.frames.select {|f| f.is_import?}.map {|f| f.filename}.compact
    if node.filename == node.imported_file.options[:filename]
      raise Sass::SyntaxError.new("#{msg} #{node.filename} imports itself")
    end
    files << node.filename << node.imported_file.options[:filename]
    msg << "\n" << Sass::Util.enum_cons(files, 2).map do |m1, m2|
      "    #{m1} imports #{m2}"
    end.join("\n")
    raise Sass::SyntaxError.new(msg)
  end
end
class Sass::Tree::Visitors::Cssize < Sass::Tree::Visitors::Base
  def self.visit(root); super; end
  protected
  def parent
    @parents.last
  end
  def initialize
    @parents = []
    @extends = Sass::Util::SubsetMap.new
  end
  def visit(node)
    super(node)
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:filename => node.filename, :line => node.line)
    raise e
  end
  def visit_children(parent)
    with_parent parent do
      parent.children = visit_children_without_parent(parent)
      parent
    end
  end
  def visit_children_without_parent(node)
    node.children.map {|c| visit(c)}.flatten
  end
  def with_parent(parent)
    @parents.push parent
    yield
  ensure
    @parents.pop
  end
  def visit_root(node)
    yield
    if parent.nil?
      if Sass::Util.ruby1_8?
        charset = node.children.find {|c| c.is_a?(Sass::Tree::CharsetNode)}
        node.children.reject! {|c| c.is_a?(Sass::Tree::CharsetNode)}
        node.children.unshift charset if charset
      end
      imports_to_move = []
      import_limit = nil
      i = -1
      node.children.reject! do |n|
        i += 1
        if import_limit
          next false unless n.is_a?(Sass::Tree::CssImportNode)
          imports_to_move << n
          next true
        end
        if !n.is_a?(Sass::Tree::CommentNode) &&
            !n.is_a?(Sass::Tree::CharsetNode) &&
            !n.is_a?(Sass::Tree::CssImportNode)
          import_limit = i
        end
        false
      end
      if import_limit
        node.children = node.children[0...import_limit] + imports_to_move +
          node.children[import_limit..-1]
      end
    end
    return node, @extends
  rescue Sass::SyntaxError => e
    e.sass_template ||= node.template
    raise e
  end
  Extend = Struct.new(:extender, :target, :node, :directives, :result)
  def visit_extend(node)
    parent.resolved_rules.populate_extends(@extends, node.resolved_selector, node,
      @parents.select {|p| p.is_a?(Sass::Tree::DirectiveNode)})
    []
  end
  def visit_import(node)
    visit_children_without_parent(node)
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:filename => node.children.first.filename)
    e.add_backtrace(:filename => node.filename, :line => node.line)
    raise e
  end
  def visit_trace(node)
    visit_children_without_parent(node)
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:mixin => node.name, :filename => node.filename, :line => node.line)
    e.add_backtrace(:filename => node.filename, :line => node.line)
    raise e
  end
  def visit_prop(node)
    if parent.is_a?(Sass::Tree::PropNode)
      node.resolved_name = "#{parent.resolved_name}-#{node.resolved_name}"
      node.tabs = parent.tabs + (parent.resolved_value.empty? ? 0 : 1) if node.style == :nested
    end
    yield
    result = node.children.dup
    if !node.resolved_value.empty? || node.children.empty?
      node.send(:check!)
      result.unshift(node)
    end
    result
  end
  def visit_atroot(node)
    if @parents.none? {|n| node.exclude_node?(n)}
      results = visit_children_without_parent(node)
      results.each {|c| c.tabs += node.tabs if bubblable?(c)}
      if !results.empty? && bubblable?(results.last)
        results.last.group_end = node.group_end
      end
      return results
    end
    return Bubble.new(node) if node.exclude_node?(parent)
    bubble(node)
  end
  def visit_rule(node)
    yield
    rules = node.children.select {|c| bubblable?(c)}
    props = node.children.reject {|c| bubblable?(c) || c.invisible?}
    unless props.empty?
      node.children = props
      rules.each {|r| r.tabs += 1} if node.style == :nested
      rules.unshift(node)
    end
    rules = debubble(rules)
    unless parent.is_a?(Sass::Tree::RuleNode) || rules.empty? || !bubblable?(rules.last)
      rules.last.group_end = true
    end
    rules
  end
  def visit_keyframerule(node)
    return node unless node.has_children
    yield
    debubble(node.children, node)
  end
  def visit_directive(node)
    return node unless node.has_children
    if parent.is_a?(Sass::Tree::RuleNode)
      return node.normalized_name == '@keyframes' ? Bubble.new(node) : bubble(node)
    end
    yield
    directive_exists = node.children.any? do |child|
      next true unless child.is_a?(Bubble)
      next false unless child.node.is_a?(Sass::Tree::DirectiveNode)
      child.node.resolved_value == node.resolved_value
    end
    if directive_exists || node.name == '@keyframes'
      []
    else
      empty_node = node.dup
      empty_node.children = []
      [empty_node]
    end + debubble(node.children, node)
  end
  def visit_media(node)
    return bubble(node) if parent.is_a?(Sass::Tree::RuleNode)
    return Bubble.new(node) if parent.is_a?(Sass::Tree::MediaNode)
    yield
    debubble(node.children, node) do |child|
      next child unless child.is_a?(Sass::Tree::MediaNode)
      next child if child.resolved_query == node.resolved_query
      next child if child.resolved_query = child.resolved_query.merge(node.resolved_query)
    end
  end
  def visit_supports(node)
    return node unless node.has_children
    return bubble(node) if parent.is_a?(Sass::Tree::RuleNode)
    yield
    debubble(node.children, node)
  end
  private
  def bubble(node)
    new_rule = parent.dup
    new_rule.children = node.children
    node.children = [new_rule]
    Bubble.new(node)
  end
  def debubble(children, parent = nil)
    previous_parent = nil
    Sass::Util.slice_by(children) {|c| c.is_a?(Bubble)}.map do |(is_bubble, slice)|
      unless is_bubble
        next slice unless parent
        if previous_parent
          previous_parent.children.push(*slice)
          next []
        else
          previous_parent = new_parent = parent.dup
          new_parent.children = slice
          next new_parent
        end
      end
      slice.map do |bubble|
        next unless (node = block_given? ? yield(bubble.node) : bubble.node)
        node.tabs += bubble.tabs
        node.group_end = bubble.group_end
        results = [visit(node)].flatten
        previous_parent = nil unless results.empty?
        results
      end.compact
    end.flatten
  end
  def bubblable?(node)
    node.is_a?(Sass::Tree::RuleNode) || node.bubbles?
  end
  class Bubble
    attr_accessor :node
    attr_accessor :tabs
    attr_accessor :group_end
    def initialize(node)
      @node = node
      @tabs = 0
    end
    def bubbles?
      true
    end
    def inspect
      "(Bubble #{node.inspect})"
    end
  end
end
class Sass::Tree::Visitors::Extend < Sass::Tree::Visitors::Base
  def self.visit(root, extends)
    return if extends.empty?
    new(extends).send(:visit, root)
    check_extends_fired! extends
  end
  protected
  def initialize(extends)
    @parent_directives = []
    @extends = extends
  end
  def visit(node)
    super(node)
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:filename => node.filename, :line => node.line)
    raise e
  end
  def visit_children(parent)
    @parent_directives.push parent if parent.is_a?(Sass::Tree::DirectiveNode)
    super
  ensure
    @parent_directives.pop if parent.is_a?(Sass::Tree::DirectiveNode)
  end
  def visit_rule(node)
    node.resolved_rules = node.resolved_rules.do_extend(@extends, @parent_directives)
  end
  private
  def self.check_extends_fired!(extends)
    extends.each_value do |ex|
      next if ex.result == :succeeded || ex.node.optional?
      message = "\"#{ex.extender}\" failed to @extend \"#{ex.target.join}\"."
      reason =
        if ex.result == :not_found
          "The selector \"#{ex.target.join}\" was not found."
        else
          "No selectors matching \"#{ex.target.join}\" could be unified with \"#{ex.extender}\"."
        end
      raise Sass::SyntaxError.new(<<MESSAGE, :filename => ex.node.filename, :line => ex.node.line)
Use "@extend #{ex.target.join} !optional" if the extend should be able to fail.
MESSAGE
    end
  end
end
class Sass::Tree::Visitors::Convert < Sass::Tree::Visitors::Base
  def self.visit(root, options, format)
    new(options, format).send(:visit, root)
  end
  protected
  def initialize(options, format)
    @options = options
    @format = format
    @tabs = 0
    @tab_chars = @options[:indent] || "  "
  end
  def visit_children(parent)
    @tabs += 1
    return @format == :sass ? "\n" : " {}\n" if parent.children.empty?
    if @format == :sass
      "\n"  + super.join.rstrip + "\n"
    else
      " {\n" + super.join.rstrip + "\n#{ @tab_chars * (@tabs - 1)}}\n"
    end
  ensure
    @tabs -= 1
  end
  def visit_root(node)
    Sass::Util.enum_cons(node.children + [nil], 2).map do |child, nxt|
      visit(child) +
        if nxt &&
            (child.is_a?(Sass::Tree::CommentNode) &&
              child.line + child.lines + 1 == nxt.line) ||
            (child.is_a?(Sass::Tree::ImportNode) && nxt.is_a?(Sass::Tree::ImportNode) &&
              child.line + 1 == nxt.line) ||
            (child.is_a?(Sass::Tree::VariableNode) && nxt.is_a?(Sass::Tree::VariableNode) &&
              child.line + 1 == nxt.line)
          ""
        else
          "\n"
        end
    end.join.rstrip + "\n"
  end
  def visit_charset(node)
    "#{tab_str}@charset \"#{node.name}\"#{semi}\n"
  end
  def visit_comment(node)
    value = interp_to_src(node.value)
    if @format == :sass
      content = value.gsub(/\*\/$/, '').rstrip
      if content =~ /\A[ \t]/
        content.gsub!(/^/, '   ')
        content.sub!(/\A([ \t]*)\/\*/, '/*\1')
      end
      if content.include?("\n")
        content.gsub!(/\n \*/, "\n  ")
        spaces = content.scan(/\n( *)/).map {|s| s.first.size}.min
        sep = node.type == :silent ? "\n//" : "\n *"
        if spaces >= 2
          content.gsub!(/\n  /, sep)
        else
          content.gsub!(/\n#{' ' * spaces}/, sep)
        end
      end
      content.gsub!(/\A\/\*/, '//') if node.type == :silent
      content.gsub!(/^/, tab_str)
      content = content.rstrip + "\n"
    else
      spaces = (@tab_chars * [@tabs - value[/^ */].size, 0].max)
      content = if node.type == :silent
                  value.gsub(/^[\/ ]\*/, '//').gsub(/ *\*\/$/, '')
                else
                  value
                end.gsub(/^/, spaces) + "\n"
    end
    content
  end
  def visit_debug(node)
    "#{tab_str}@debug #{node.expr.to_sass(@options)}#{semi}\n"
  end
  def visit_error(node)
    "#{tab_str}@error #{node.expr.to_sass(@options)}#{semi}\n"
  end
  def visit_directive(node)
    res = "#{tab_str}#{interp_to_src(node.value)}"
    res.gsub!(/^@import \#\{(.*)\}([^}]*)$/, '@import \1\2')
    return res + "#{semi}\n" unless node.has_children
    res + yield + "\n"
  end
  def visit_each(node)
    vars = node.vars.map {|var| "$#{dasherize(var)}"}.join(", ")
    "#{tab_str}@each #{vars} in #{node.list.to_sass(@options)}#{yield}"
  end
  def visit_extend(node)
    "#{tab_str}@extend #{selector_to_src(node.selector).lstrip}" +
      "#{" !optional" if node.optional?}#{semi}\n"
  end
  def visit_for(node)
    "#{tab_str}@for $#{dasherize(node.var)} from #{node.from.to_sass(@options)} " +
      "#{node.exclusive ? "to" : "through"} #{node.to.to_sass(@options)}#{yield}"
  end
  def visit_function(node)
    args = node.args.map do |v, d|
      d ? "#{v.to_sass(@options)}: #{d.to_sass(@options)}" : v.to_sass(@options)
    end.join(", ")
    if node.splat
      args << ", " unless node.args.empty?
      args << node.splat.to_sass(@options) << "..."
    end
    "#{tab_str}@function #{dasherize(node.name)}(#{args})#{yield}"
  end
  def visit_if(node)
    name =
      if !@is_else
        "if"
      elsif node.expr
        "else if"
      else
        "else"
      end
    @is_else = false
    str = "#{tab_str}@#{name}"
    str << " #{node.expr.to_sass(@options)}" if node.expr
    str << yield
    @is_else = true
    str << visit(node.else) if node.else
    str
  ensure
    @is_else = false
  end
  def visit_import(node)
    quote = @format == :scss ? '"' : ''
    "#{tab_str}@import #{quote}#{node.imported_filename}#{quote}#{semi}\n"
  end
  def visit_media(node)
    "#{tab_str}@media #{query_interp_to_src(node.query)}#{yield}"
  end
  def visit_supports(node)
    "#{tab_str}@#{node.name} #{node.condition.to_src(@options)}#{yield}"
  end
  def visit_cssimport(node)
    if node.uri.is_a?(Sass::Script::Tree::Node)
      str = "#{tab_str}@import #{node.uri.to_sass(@options)}"
    else
      str = "#{tab_str}@import #{node.uri}"
    end
    str << " #{interp_to_src(node.query)}" unless node.query.empty?
    "#{str}#{semi}\n"
  end
  def visit_mixindef(node)
    args =
      if node.args.empty? && node.splat.nil?
        ""
      else
        str = '('
        str << node.args.map do |v, d|
          if d
            "#{v.to_sass(@options)}: #{d.to_sass(@options)}"
          else
            v.to_sass(@options)
          end
        end.join(", ")
        if node.splat
          str << ", " unless node.args.empty?
          str << node.splat.to_sass(@options) << '...'
        end
        str << ')'
      end
    "#{tab_str}#{@format == :sass ? '=' : '@mixin '}#{dasherize(node.name)}#{args}#{yield}"
  end
  def visit_mixin(node)
    arg_to_sass = lambda do |arg|
      sass = arg.to_sass(@options)
      sass = "(#{sass})" if arg.is_a?(Sass::Script::Tree::ListLiteral) && arg.separator == :comma
      sass
    end
    unless node.args.empty? && node.keywords.empty? && node.splat.nil?
      args = node.args.map(&arg_to_sass)
      keywords = Sass::Util.hash_to_a(node.keywords.as_stored).
        map {|k, v| "$#{dasherize(k)}: #{arg_to_sass[v]}"}
      if node.splat
        splat = "#{arg_to_sass[node.splat]}..."
        kwarg_splat = "#{arg_to_sass[node.kwarg_splat]}..." if node.kwarg_splat
      end
      arglist = "(#{[args, splat, keywords, kwarg_splat].flatten.compact.join(', ')})"
    end
    "#{tab_str}#{@format == :sass ? '+' : '@include '}" +
      "#{dasherize(node.name)}#{arglist}#{node.has_children ? yield : semi}\n"
  end
  def visit_content(node)
    "#{tab_str}@content#{semi}\n"
  end
  def visit_prop(node)
    res = tab_str + node.declaration(@options, @format)
    return res + semi + "\n" if node.children.empty?
    res + yield.rstrip + semi + "\n"
  end
  def visit_return(node)
    "#{tab_str}@return #{node.expr.to_sass(@options)}#{semi}\n"
  end
  def visit_rule(node)
    rule = node.parsed_rules ? [node.parsed_rules.to_s] : node.rule
    if @format == :sass
      name = selector_to_sass(rule)
      name = "\\" + name if name[0] == ?:
      name.gsub(/^/, tab_str) + yield
    elsif @format == :scss
      name = selector_to_scss(rule)
      res = name + yield
      if node.children.last.is_a?(Sass::Tree::CommentNode) && node.children.last.type == :silent
        res.slice!(-3..-1)
        res << "\n" << tab_str << "}\n"
      end
      res
    end
  end
  def visit_variable(node)
    "#{tab_str}$#{dasherize(node.name)}: #{node.expr.to_sass(@options)}" +
      "#{' !global' if node.global}#{' !default' if node.guarded}#{semi}\n"
  end
  def visit_warn(node)
    "#{tab_str}@warn #{node.expr.to_sass(@options)}#{semi}\n"
  end
  def visit_while(node)
    "#{tab_str}@while #{node.expr.to_sass(@options)}#{yield}"
  end
  def visit_atroot(node)
    if node.query
      "#{tab_str}@at-root #{query_interp_to_src(node.query)}#{yield}"
    elsif node.children.length == 1 && node.children.first.is_a?(Sass::Tree::RuleNode)
      rule = node.children.first
      "#{tab_str}@at-root #{selector_to_src(rule.rule).lstrip}#{visit_children(rule)}"
    else
      "#{tab_str}@at-root#{yield}"
    end
  end
  private
  def interp_to_src(interp)
    interp.map {|r| r.is_a?(String) ? r : r.to_sass(@options)}.join
  end
  def query_interp_to_src(interp)
    interp = interp.map do |e|
      next e unless e.is_a?(Sass::Script::Tree::Literal)
      next e unless e.value.is_a?(Sass::Script::Value::String)
      e.value.value
    end
    interp_to_src(interp)
  end
  def selector_to_src(sel)
    @format == :sass ? selector_to_sass(sel) : selector_to_scss(sel)
  end
  def selector_to_sass(sel)
    sel.map do |r|
      if r.is_a?(String)
        r.gsub(/(,)?([ \t]*)\n\s*/) {$1 ? "#{$1}#{$2}\n" : " "}
      else
        r.to_sass(@options)
      end
    end.join
  end
  def selector_to_scss(sel)
    interp_to_src(sel).gsub(/^[ \t]*/, tab_str).gsub(/[ \t]*$/, '')
  end
  def semi
    @format == :sass ? "" : ";"
  end
  def tab_str
    @tab_chars * @tabs
  end
  def dasherize(s)
    if @options[:dasherize]
      s.gsub('_', '-')
    else
      s
    end
  end
end
class Sass::Tree::Visitors::ToCss < Sass::Tree::Visitors::Base
  attr_reader :source_mapping
  def initialize(build_source_mapping = false)
    @tabs = 0
    @line = 1
    @offset = 1
    @result = ""
    @source_mapping = Sass::Source::Map.new if build_source_mapping
  end
  def visit(node)
    super
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:filename => node.filename, :line => node.line)
    raise e
  end
  protected
  def with_tabs(tabs)
    old_tabs, @tabs = @tabs, tabs
    yield
  ensure
    @tabs = old_tabs
  end
  def for_node(node, attr_prefix = nil)
    return yield unless @source_mapping
    start_pos = Sass::Source::Position.new(@line, @offset)
    yield
    range_attr = attr_prefix ? :"#{attr_prefix}_source_range" : :source_range
    return if node.invisible? || !node.send(range_attr)
    source_range = node.send(range_attr)
    target_end_pos = Sass::Source::Position.new(@line, @offset)
    target_range = Sass::Source::Range.new(start_pos, target_end_pos, nil)
    @source_mapping.add(source_range, target_range)
  end
  def erase!(chars)
    return if chars == 0
    str = @result.slice!(-chars..-1)
    newlines = str.count("\n")
    if newlines > 0
      @line -= newlines
      @offset = @result[@result.rindex("\n") || 0..-1].size
    else
      @offset -= chars
    end
  end
  NEWLINE = "\n"
  def output(s)
    if @lstrip
      s = s.gsub(/\A\s+/, "")
      @lstrip = false
    end
    newlines = s.count(NEWLINE)
    if newlines > 0
      @line += newlines
      @offset = s[s.rindex(NEWLINE)..-1].size
    else
      @offset += s.size
    end
    @result << s
  end
  def rstrip!
    erase! @result.length - 1 - (@result.rindex(/[^\s]/) || -1)
  end
  def lstrip
    old_lstrip = @lstrip
    @lstrip = true
    yield
  ensure
    @lstrip = @lstrip && old_lstrip
  end
  def prepend!(prefix)
    @result.insert 0, prefix
    return unless @source_mapping
    line_delta = prefix.count("\n")
    offset_delta = prefix.gsub(/.*\n/, '').size
    @source_mapping.shift_output_offsets(offset_delta)
    @source_mapping.shift_output_lines(line_delta)
  end
  def visit_root(node)
    node.children.each do |child|
      next if child.invisible?
      visit(child)
      unless node.style == :compressed
        output "\n"
        if child.is_a?(Sass::Tree::DirectiveNode) && child.has_children && !child.bubbles?
          output "\n"
        end
      end
    end
    rstrip!
    return "" if @result.empty?
    output "\n"
    unless Sass::Util.ruby1_8? || @result.ascii_only?
      if node.style == :compressed
        prepend! "\uFEFF"
      else
        prepend! "@charset \"UTF-8\";\n"
      end
    end
    @result
  rescue Sass::SyntaxError => e
    e.sass_template ||= node.template
    raise e
  end
  def visit_charset(node)
    for_node(node) {output("@charset \"#{node.name}\";")}
  end
  def visit_comment(node)
    return if node.invisible?
    spaces = ('  ' * [@tabs - node.resolved_value[/^ */].size, 0].max)
    content = node.resolved_value.gsub(/^/, spaces)
    if node.type == :silent
      content.gsub!(%r{^(\s*)//(.*)$}) {|md| "#{$1}/*#{$2} */"}
    end
    if (node.style == :compact || node.style == :compressed) && node.type != :loud
      content.gsub!(/\n +(\* *(?!\/))?/, ' ')
    end
    for_node(node) {output(content)}
  end
  def visit_directive(node)
    was_in_directive = @in_directive
    tab_str = '  ' * @tabs
    if !node.has_children || node.children.empty?
      output(tab_str)
      for_node(node) {output(node.resolved_value)}
      output(!node.has_children ? ";" : " {}")
      return
    end
    @in_directive = @in_directive || !node.is_a?(Sass::Tree::MediaNode)
    output(tab_str) if node.style != :compressed
    for_node(node) {output(node.resolved_value)}
    output(node.style == :compressed ? "{" : " {")
    output(node.style == :compact ? ' ' : "\n") if node.style != :compressed
    was_prop = false
    first = true
    node.children.each do |child|
      next if child.invisible?
      if node.style == :compact
        if child.is_a?(Sass::Tree::PropNode)
          with_tabs(first || was_prop ? 0 : @tabs + 1) do
            visit(child)
            output(' ')
          end
        else
          if was_prop
            erase! 1
            output "\n"
          end
          if first
            lstrip {with_tabs(@tabs + 1) {visit(child)}}
          else
            with_tabs(@tabs + 1) {visit(child)}
          end
          rstrip!
          output "\n"
        end
        was_prop = child.is_a?(Sass::Tree::PropNode)
        first = false
      elsif node.style == :compressed
        output(was_prop ? ";" : "")
        with_tabs(0) {visit(child)}
        was_prop = child.is_a?(Sass::Tree::PropNode)
      else
        with_tabs(@tabs + 1) {visit(child)}
        output "\n"
      end
    end
    rstrip!
    if node.style == :expanded
      output("\n#{tab_str}")
    elsif node.style != :compressed
      output(" ")
    end
    output("}")
  ensure
    @in_directive = was_in_directive
  end
  def visit_media(node)
    with_tabs(@tabs + node.tabs) {visit_directive(node)}
    output("\n") if node.style != :compressed && node.group_end
  end
  def visit_supports(node)
    visit_media(node)
  end
  def visit_cssimport(node)
    visit_directive(node)
  end
  def visit_prop(node)
    return if node.resolved_value.empty?
    tab_str = '  ' * (@tabs + node.tabs)
    output(tab_str)
    for_node(node, :name) {output(node.resolved_name)}
    if node.style == :compressed
      output(":")
      for_node(node, :value) {output(node.resolved_value)}
    else
      output(": ")
      for_node(node, :value) {output(node.resolved_value)}
      output(";")
    end
  end
  def visit_rule(node)
    with_tabs(@tabs + node.tabs) do
      rule_separator = node.style == :compressed ? ',' : ', '
      line_separator =
        case node.style
        when :nested, :expanded; "\n"
        when :compressed; ""
        else; " "
        end
      rule_indent = '  ' * @tabs
      per_rule_indent, total_indent = if [:nested, :expanded].include?(node.style)
                                        [rule_indent, '']
                                      else
                                        ['', rule_indent]
                                      end
      joined_rules = node.resolved_rules.members.map do |seq|
        next if seq.has_placeholder?
        rule_part = seq.to_s
        if node.style == :compressed
          rule_part.gsub!(/([^,])\s*\n\s*/m, '\1 ')
          rule_part.gsub!(/\s*([,+>])\s*/m, '\1')
          rule_part.strip!
        end
        rule_part
      end.compact.join(rule_separator)
      joined_rules.lstrip!
      joined_rules.gsub!(/\s*\n\s*/, "#{line_separator}#{per_rule_indent}")
      old_spaces = '  ' * @tabs
      if node.style != :compressed
        if node.options[:debug_info] && !@in_directive
          visit(debug_info_rule(node.debug_info, node.options))
          output "\n"
        elsif node.options[:trace_selectors]
          output("#{old_spaces}/* ")
          output(node.stack_trace.gsub("\n", "\n   #{old_spaces}"))
          output(" */\n")
        elsif node.options[:line_comments]
          output("#{old_spaces}/* line #{node.line}")
          if node.filename
            relative_filename =
              if node.options[:css_filename]
                begin
                  Sass::Util.relative_path_from(
                    node.filename, File.dirname(node.options[:css_filename])).to_s
                rescue ArgumentError
                  nil
                end
              end
            relative_filename ||= node.filename
            output(", #{relative_filename}")
          end
          output(" */\n")
        end
      end
      end_props, trailer, tabs  = '', '', 0
      if node.style == :compact
        separator, end_props, bracket = ' ', ' ', ' { '
        trailer = "\n" if node.group_end
      elsif node.style == :compressed
        separator, bracket = ';', '{'
      else
        tabs = @tabs + 1
        separator, bracket = "\n", " {\n"
        trailer = "\n" if node.group_end
        end_props = (node.style == :expanded ? "\n" + old_spaces : ' ')
      end
      output(total_indent + per_rule_indent)
      for_node(node, :selector) {output(joined_rules)}
      output(bracket)
      with_tabs(tabs) do
        node.children.each_with_index do |child, i|
          output(separator) if i > 0
          visit(child)
        end
      end
      output(end_props)
      output("}" + trailer)
    end
  end
  def visit_keyframerule(node)
    visit_directive(node)
  end
  private
  def debug_info_rule(debug_info, options)
    node = Sass::Tree::DirectiveNode.resolved("@media -sass-debug-info")
    Sass::Util.hash_to_a(debug_info.map {|k, v| [k.to_s, v.to_s]}).each do |k, v|
      rule = Sass::Tree::RuleNode.new([""])
      rule.resolved_rules = Sass::Selector::CommaSequence.new(
        [Sass::Selector::Sequence.new(
            [Sass::Selector::SimpleSequence.new(
                [Sass::Selector::Element.new(k.to_s.gsub(/[^\w-]/, "\\\\\\0"), nil)],
                false)
            ])
        ])
      prop = Sass::Tree::PropNode.new([""], Sass::Script::Value::String.new(''), :new)
      prop.resolved_name = "font-family"
	  prop.resolved_value = !(v =~ /^\d+$/).nil? ? ("\\00003" + v) : Sass::SCSS::RX.escape_ident(v.to_s) #BT+
      rule << prop
      node << rule
    end
    node.options = options.merge(:debug_info => false,
                                 :line_comments => false,
                                 :style => :compressed)
    node
  end
end
class Sass::Tree::Visitors::DeepCopy < Sass::Tree::Visitors::Base
  protected
  def visit(node)
    super(node.dup)
  end
  def visit_children(parent)
    parent.children = parent.children.map {|c| visit(c)}
    parent
  end
  def visit_debug(node)
    node.expr = node.expr.deep_copy
    yield
  end
  def visit_error(node)
    node.expr = node.expr.deep_copy
    yield
  end
  def visit_each(node)
    node.list = node.list.deep_copy
    yield
  end
  def visit_extend(node)
    node.selector = node.selector.map {|c| c.is_a?(Sass::Script::Tree::Node) ? c.deep_copy : c}
    yield
  end
  def visit_for(node)
    node.from = node.from.deep_copy
    node.to = node.to.deep_copy
    yield
  end
  def visit_function(node)
    node.args = node.args.map {|k, v| [k.deep_copy, v && v.deep_copy]}
    yield
  end
  def visit_if(node)
    node.expr = node.expr.deep_copy if node.expr
    node.else = visit(node.else) if node.else
    yield
  end
  def visit_mixindef(node)
    node.args = node.args.map {|k, v| [k.deep_copy, v && v.deep_copy]}
    yield
  end
  def visit_mixin(node)
    node.args = node.args.map {|a| a.deep_copy}
    node.keywords = Hash[node.keywords.map {|k, v| [k, v.deep_copy]}]
    yield
  end
  def visit_prop(node)
    node.name = node.name.map {|c| c.is_a?(Sass::Script::Tree::Node) ? c.deep_copy : c}
    node.value = node.value.deep_copy
    yield
  end
  def visit_return(node)
    node.expr = node.expr.deep_copy
    yield
  end
  def visit_rule(node)
    node.rule = node.rule.map {|c| c.is_a?(Sass::Script::Tree::Node) ? c.deep_copy : c}
    yield
  end
  def visit_variable(node)
    node.expr = node.expr.deep_copy
    yield
  end
  def visit_warn(node)
    node.expr = node.expr.deep_copy
    yield
  end
  def visit_while(node)
    node.expr = node.expr.deep_copy
    yield
  end
  def visit_directive(node)
    node.value = node.value.map {|c| c.is_a?(Sass::Script::Tree::Node) ? c.deep_copy : c}
    yield
  end
  def visit_media(node)
    node.query = node.query.map {|c| c.is_a?(Sass::Script::Tree::Node) ? c.deep_copy : c}
    yield
  end
  def visit_supports(node)
    node.condition = node.condition.deep_copy
    yield
  end
end
class Sass::Tree::Visitors::SetOptions < Sass::Tree::Visitors::Base
  def self.visit(root, options); new(options).send(:visit, root); end
  protected
  def initialize(options)
    @options = options
  end
  def visit(node)
    node.instance_variable_set('@options', @options)
    super
  end
  def visit_comment(node)
    node.value.each {|c| c.options = @options if c.is_a?(Sass::Script::Tree::Node)}
    yield
  end
  def visit_debug(node)
    node.expr.options = @options
    yield
  end
  def visit_error(node)
    node.expr.options = @options
    yield
  end
  def visit_each(node)
    node.list.options = @options
    yield
  end
  def visit_extend(node)
    node.selector.each {|c| c.options = @options if c.is_a?(Sass::Script::Tree::Node)}
    yield
  end
  def visit_for(node)
    node.from.options = @options
    node.to.options = @options
    yield
  end
  def visit_function(node)
    node.args.each do |k, v|
      k.options = @options
      v.options = @options if v
    end
    node.splat.options = @options if node.splat
    yield
  end
  def visit_if(node)
    node.expr.options = @options if node.expr
    visit(node.else) if node.else
    yield
  end
  def visit_import(node)
    node.imported_file = nil
    yield
  end
  def visit_mixindef(node)
    node.args.each do |k, v|
      k.options = @options
      v.options = @options if v
    end
    node.splat.options = @options if node.splat
    yield
  end
  def visit_mixin(node)
    node.args.each {|a| a.options = @options}
    node.keywords.each {|k, v| v.options = @options}
    node.splat.options = @options if node.splat
    node.kwarg_splat.options = @options if node.kwarg_splat
    yield
  end
  def visit_prop(node)
    node.name.each {|c| c.options = @options if c.is_a?(Sass::Script::Tree::Node)}
    node.value.options = @options
    yield
  end
  def visit_return(node)
    node.expr.options = @options
    yield
  end
  def visit_rule(node)
    node.rule.each {|c| c.options = @options if c.is_a?(Sass::Script::Tree::Node)}
    yield
  end
  def visit_variable(node)
    node.expr.options = @options
    yield
  end
  def visit_warn(node)
    node.expr.options = @options
    yield
  end
  def visit_while(node)
    node.expr.options = @options
    yield
  end
  def visit_directive(node)
    node.value.each {|c| c.options = @options if c.is_a?(Sass::Script::Tree::Node)}
    yield
  end
  def visit_media(node)
    node.query.each {|c| c.options = @options if c.is_a?(Sass::Script::Tree::Node)}
    yield
  end
  def visit_cssimport(node)
    node.query.each {|c| c.options = @options if c.is_a?(Sass::Script::Tree::Node)} if node.query
    yield
  end
  def visit_supports(node)
    node.condition.options = @options
    yield
  end
end
class Sass::Tree::Visitors::CheckNesting < Sass::Tree::Visitors::Base
  protected
  def initialize
    @parents = []
  end
  def visit(node)
    if (error = @parent && (
        try_send(@parent.class.invalid_child_method_name, @parent, node) ||
        try_send(node.class.invalid_parent_method_name, @parent, node)))
      raise Sass::SyntaxError.new(error)
    end
    super
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:filename => node.filename, :line => node.line)
    raise e
  end
  CONTROL_NODES = [Sass::Tree::EachNode, Sass::Tree::ForNode, Sass::Tree::IfNode,
                   Sass::Tree::WhileNode, Sass::Tree::TraceNode]
  SCRIPT_NODES = [Sass::Tree::ImportNode] + CONTROL_NODES
  def visit_children(parent)
    old_parent = @parent
    if parent.is_a?(Sass::Tree::AtRootNode) && parent.resolved_value
      old_parents = @parents
      @parents = @parents.reject {|p| parent.exclude_node?(p)}
      @parent = Sass::Util.enum_with_index(@parents.reverse).
        find {|p, i| !transparent_parent?(p, @parents[-i - 2])}.first
      begin
        return super
      ensure
        @parents = old_parents
        @parent = old_parent
      end
    end
    unless transparent_parent?(parent, old_parent)
      @parent = parent
    end
    @parents.push parent
    begin
      super
    ensure
      @parent = old_parent
      @parents.pop
    end
  end
  def visit_root(node)
    yield
  rescue Sass::SyntaxError => e
    e.sass_template ||= node.template
    raise e
  end
  def visit_import(node)
    yield
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:filename => node.children.first.filename)
    e.add_backtrace(:filename => node.filename, :line => node.line)
    raise e
  end
  def visit_mixindef(node)
    @current_mixin_def, old_mixin_def = node, @current_mixin_def
    yield
  ensure
    @current_mixin_def = old_mixin_def
  end
  def invalid_content_parent?(parent, child)
    if @current_mixin_def
      @current_mixin_def.has_content = true
      nil
    else
      "@content may only be used within a mixin."
    end
  end
  def invalid_charset_parent?(parent, child)
    "@charset may only be used at the root of a document." unless parent.is_a?(Sass::Tree::RootNode)
  end
  VALID_EXTEND_PARENTS = [Sass::Tree::RuleNode, Sass::Tree::MixinDefNode, Sass::Tree::MixinNode]
  def invalid_extend_parent?(parent, child)
    unless is_any_of?(parent, VALID_EXTEND_PARENTS)
      return "Extend directives may only be used within rules."
    end
  end
  INVALID_IMPORT_PARENTS = CONTROL_NODES +
    [Sass::Tree::MixinDefNode, Sass::Tree::MixinNode]
  def invalid_import_parent?(parent, child)
    unless (@parents.map {|p| p.class} & INVALID_IMPORT_PARENTS).empty?
      return "Import directives may not be used within control directives or mixins."
    end
    return if parent.is_a?(Sass::Tree::RootNode)
    return "CSS import directives may only be used at the root of a document." if child.css_import?
  rescue Sass::SyntaxError => e
    e.modify_backtrace(:filename => child.imported_file.options[:filename])
    e.add_backtrace(:filename => child.filename, :line => child.line)
    raise e
  end
  def invalid_mixindef_parent?(parent, child)
    unless (@parents.map {|p| p.class} & INVALID_IMPORT_PARENTS).empty?
      return "Mixins may not be defined within control directives or other mixins."
    end
  end
  def invalid_function_parent?(parent, child)
    unless (@parents.map {|p| p.class} & INVALID_IMPORT_PARENTS).empty?
      return "Functions may not be defined within control directives or other mixins."
    end
  end
  VALID_FUNCTION_CHILDREN = [
    Sass::Tree::CommentNode,  Sass::Tree::DebugNode, Sass::Tree::ReturnNode,
    Sass::Tree::VariableNode, Sass::Tree::WarnNode, Sass::Tree::ErrorNode
  ] + CONTROL_NODES
  def invalid_function_child?(parent, child)
    unless is_any_of?(child, VALID_FUNCTION_CHILDREN)
      "Functions can only contain variable declarations and control directives."
    end
  end
  VALID_PROP_CHILDREN =  CONTROL_NODES + [Sass::Tree::CommentNode,
                                          Sass::Tree::PropNode,
                                          Sass::Tree::MixinNode]
  def invalid_prop_child?(parent, child)
    unless is_any_of?(child, VALID_PROP_CHILDREN)
      "Illegal nesting: Only properties may be nested beneath properties."
    end
  end
  VALID_PROP_PARENTS = [Sass::Tree::RuleNode, Sass::Tree::KeyframeRuleNode, Sass::Tree::PropNode,
                        Sass::Tree::MixinDefNode, Sass::Tree::DirectiveNode, Sass::Tree::MixinNode]
  def invalid_prop_parent?(parent, child)
    unless is_any_of?(parent, VALID_PROP_PARENTS)
      "Properties are only allowed within rules, directives, mixin includes, or other properties." +
        child.pseudo_class_selector_message
    end
  end
  def invalid_return_parent?(parent, child)
    "@return may only be used within a function." unless parent.is_a?(Sass::Tree::FunctionNode)
  end
  private
  def transparent_parent?(parent, grandparent)
    is_any_of?(parent, SCRIPT_NODES) ||
      (parent.bubbles? &&
       !grandparent.is_a?(Sass::Tree::RootNode) &&
       !grandparent.is_a?(Sass::Tree::AtRootNode))
  end
  def is_any_of?(val, classes)
    classes.each do |c|
      return true if val.is_a?(c)
    end
    false
  end
  def try_send(method, *args)
    return unless respond_to?(method, true)
    send(method, *args)
  end
end
module Sass
  module Selector
    class Simple
      attr_accessor :line
      attr_accessor :filename
      def inspect
        to_s
      end
      def to_s
        Sass::Util.abstract(self)
      end
      def hash
        @_hash ||= equality_key.hash
      end
      def eql?(other)
        other.class == self.class && other.hash == hash && other.equality_key == equality_key
      end
      alias_method :==, :eql?
      def unify(sels)
        return sels if sels.any? {|sel2| eql?(sel2)}
        sels_with_ix = Sass::Util.enum_with_index(sels)
        _, i =
          if is_a?(Pseudo)
            sels_with_ix.find {|sel, _| sel.is_a?(Pseudo) && (sels.last.type == :element)}
          else
            sels_with_ix.find {|sel, _| sel.is_a?(Pseudo)}
          end
        return sels + [self] unless i
        sels[0...i] + [self] + sels[i..-1]
      end
      protected
      def equality_key
        @equality_key ||= to_s
      end
      def unify_namespaces(ns1, ns2)
        return nil, false unless ns1 == ns2 || ns1.nil? || ns1 == '*' || ns2.nil? || ns2 == '*'
        return ns2, true if ns1 == '*'
        return ns1, true if ns2 == '*'
        [ns1 || ns2, true]
      end
    end
  end
end
module Sass
  module Selector
    class AbstractSequence
      attr_reader :line
      attr_reader :filename
      def line=(line)
        members.each {|m| m.line = line}
        @line = line
      end
      def filename=(filename)
        members.each {|m| m.filename = filename}
        @filename = filename
      end
      def hash
        @_hash ||= _hash
      end
      def eql?(other)
        other.class == self.class && other.hash == hash && _eql?(other)
      end
      alias_method :==, :eql?
      def has_placeholder?
        @has_placeholder ||= members.any? do |m|
          next m.has_placeholder? if m.is_a?(AbstractSequence)
          next m.selector && m.selector.has_placeholder? if m.is_a?(Pseudo)
          m.is_a?(Placeholder)
        end
      end
      def to_s
        Sass::Util.abstract(self)
      end
      def specificity
        _specificity(members)
      end
      protected
      def _specificity(arr)
        min = 0
        max = 0
        arr.each do |m|
          next if m.is_a?(String)
          spec = m.specificity
          if spec.is_a?(Range)
            min += spec.begin
            max += spec.end
          else
            min += spec
            max += spec
          end
        end
        min == max ? min : (min..max)
      end
    end
  end
end
module Sass
  module Selector
    class CommaSequence < AbstractSequence
      attr_reader :members
      def initialize(seqs)
        @members = seqs
      end
      def resolve_parent_refs(super_cseq, implicit_parent = true)
        if super_cseq.nil?
          if contains_parent_ref?
            raise Sass::SyntaxError.new(
              "Base-level rules cannot contain the parent-selector-referencing character '&'.")
          end
          return self
        end
        CommaSequence.new(Sass::Util.flatten_vertically(@members.map do |seq|
          seq.resolve_parent_refs(super_cseq, implicit_parent).members
        end))
      end
      def contains_parent_ref?
        @members.any? {|sel| sel.contains_parent_ref?}
      end
      def do_extend(extends, parent_directives = [], replace = false, seen = Set.new,
          original = true)
        CommaSequence.new(members.map do |seq|
          seq.do_extend(extends, parent_directives, replace, seen, original)
        end.flatten)
      end
      def superselector?(cseq)
        cseq.members.all? {|seq1| members.any? {|seq2| seq2.superselector?(seq1)}}
      end
      def populate_extends(extends, extendee, extend_node = nil, parent_directives = [])
        extendee.members.each do |seq|
          if seq.members.size > 1
            raise Sass::SyntaxError.new("Can't extend #{seq}: can't extend nested selectors")
          end
          sseq = seq.members.first
          if !sseq.is_a?(Sass::Selector::SimpleSequence)
            raise Sass::SyntaxError.new("Can't extend #{seq}: invalid selector")
          elsif sseq.members.any? {|ss| ss.is_a?(Sass::Selector::Parent)}
            raise Sass::SyntaxError.new("Can't extend #{seq}: can't extend parent selectors")
          end
          sel = sseq.members
          members.each do |member|
            unless member.members.last.is_a?(Sass::Selector::SimpleSequence)
              raise Sass::SyntaxError.new("#{member} can't extend: invalid selector")
            end
            extends[sel] = Sass::Tree::Visitors::Cssize::Extend.new(
              member, sel, extend_node, parent_directives, :not_found)
          end
        end
      end
      def unify(other)
        results = members.map {|seq1| other.members.map {|seq2| seq1.unify(seq2)}}.flatten.compact
        results.empty? ? nil : CommaSequence.new(results.map {|cseq| cseq.members}.flatten)
      end
      def to_sass_script
        Sass::Script::Value::List.new(members.map do |seq|
          Sass::Script::Value::List.new(seq.members.map do |component|
            next if component == "\n"
            Sass::Script::Value::String.new(component.to_s)
          end.compact, :space)
        end, :comma)
      end
      def inspect
        members.map {|m| m.inspect}.join(", ")
      end
      def to_s
        @members.join(", ").gsub(", \n", ",\n")
      end
      private
      def _hash
        members.hash
      end
      def _eql?(other)
        other.class == self.class && other.members.eql?(members)
      end
    end
  end
end
module Sass
  module Selector
    class Pseudo < Simple
      ACTUALLY_ELEMENTS = %w[after before first-line first-letter].to_set
      attr_reader :syntactic_type
      attr_reader :name
      attr_reader :arg
      attr_reader :selector
      def initialize(syntactic_type, name, arg, selector)
        @syntactic_type = syntactic_type
        @name = name
        @arg = arg
        @selector = selector
      end
      def with_selector(new_selector)
        result = Pseudo.new(syntactic_type, name, arg,
          CommaSequence.new(new_selector.members.map do |seq|
            next seq unless seq.members.length == 1
            sseq = seq.members.first
            next seq unless sseq.is_a?(SimpleSequence) && sseq.members.length == 1
            sel = sseq.members.first
            next seq unless sel.is_a?(Pseudo) && sel.selector
            case normalized_name
            when 'not'
              next [] unless sel.normalized_name == 'matches'
              sel.selector.members
            when 'matches', 'any', 'current', 'nth-child', 'nth-last-child'
              next [] unless sel.name == name && sel.arg == arg
              sel.selector.members
            when 'has', 'host', 'host-context'
              sel
            else
              []
            end
          end.flatten))
        return [result] unless normalized_name == 'not'
        return [result] if selector.members.length > 1
        result.selector.members.map do |seq|
          Pseudo.new(syntactic_type, name, arg, CommaSequence.new([seq]))
        end
      end
      def type
        ACTUALLY_ELEMENTS.include?(normalized_name) ? :element : syntactic_type
      end
      def normalized_name
        @normalized_name ||= name.gsub(/^-[a-zA-Z0-9]+-/, '')
      end
      def to_s
        res = (syntactic_type == :class ? ":" : "::") + @name
        if @arg || @selector
          res << "("
          res << @arg.strip if @arg
          res << " " if @arg && @selector
          res << @selector.to_s if @selector
          res << ")"
        end
        res
      end
      def unify(sels)
        return if type == :element && sels.any? do |sel|
          sel.is_a?(Pseudo) && sel.type == :element &&
            (sel.name != name || sel.arg != arg || sel.selector != selector)
        end
        super
      end
      def superselector?(their_sseq, parents = [])
        case normalized_name
        when 'matches', 'any'
          (their_sseq.selector_pseudo_classes[normalized_name] || []).any? do |their_sel|
            next false unless their_sel.is_a?(Pseudo)
            next false unless their_sel.name == name
            selector.superselector?(their_sel.selector)
          end || selector.members.any? do |our_seq|
            their_seq = Sequence.new(parents + [their_sseq])
            our_seq.superselector?(their_seq)
          end
        when 'has', 'host', 'host-context'
          (their_sseq.selector_pseudo_classes[normalized_name] || []).any? do |their_sel|
            next false unless their_sel.is_a?(Pseudo)
            next false unless their_sel.name == name
            selector.superselector?(their_sel.selector)
          end
        when 'not'
          selector.members.all? do |our_seq|
            their_sseq.members.any? do |their_sel|
              if their_sel.is_a?(Element) || their_sel.is_a?(Id)
                our_sseq = our_seq.members.last
                next false unless our_sseq.is_a?(SimpleSequence)
                our_sseq.members.any? do |our_sel|
                  our_sel.class == their_sel.class && our_sel != their_sel
                end
              else
                next false unless their_sel.is_a?(Pseudo)
                next false unless their_sel.name == name
                their_sel.selector.superselector?(CommaSequence.new([our_seq]))
              end
            end
          end
        when 'current'
          (their_sseq.selector_pseudo_classes['current'] || []).any? do |their_current|
            next false if their_current.name != name
            selector == their_current.selector
          end
        when 'nth-child', 'nth-last-child'
          their_sseq.members.any? do |their_sel|
            next false unless their_sel.is_a?(Pseudo)
            next false unless their_sel.name == name
            next false unless their_sel.arg == arg
            selector.superselector?(their_sel.selector)
          end
        else
          throw "[BUG] Unknown selector pseudo class #{name}"
        end
      end
      def specificity
        return 1 if type == :element
        return SPECIFICITY_BASE unless selector
        @specificity ||=
          if normalized_name == 'not'
            min = 0
            max = 0
            selector.members.each do |seq|
              spec = seq.specificity
              if spec.is_a?(Range)
                min = Sass::Util.max(spec.begin, min)
                max = Sass::Util.max(spec.end, max)
              else
                min = Sass::Util.max(spec, min)
                max = Sass::Util.max(spec, max)
              end
            end
            min == max ? max : (min..max)
          else
            min = 0
            max = 0
            selector.members.each do |seq|
              spec = seq.specificity
              if spec.is_a?(Range)
                min = Sass::Util.min(spec.begin, min)
                max = Sass::Util.max(spec.end, max)
              else
                min = Sass::Util.min(spec, min)
                max = Sass::Util.max(spec, max)
              end
            end
            min == max ? max : (min..max)
          end
      end
    end
  end
end
module Sass
  module Selector
    class Sequence < AbstractSequence
      def line=(line)
        members.each {|m| m.line = line if m.is_a?(SimpleSequence)}
        line
      end
      def filename=(filename)
        members.each {|m| m.filename = filename if m.is_a?(SimpleSequence)}
        filename
      end
      attr_reader :members
      def initialize(seqs_and_ops)
        @members = seqs_and_ops
      end
      def resolve_parent_refs(super_cseq, implicit_parent)
        members = @members.dup
        nl = (members.first == "\n" && members.shift)
        contains_parent_ref = contains_parent_ref?
        return CommaSequence.new([self]) if !implicit_parent && !contains_parent_ref
        unless contains_parent_ref
          old_members, members = members, []
          members << nl if nl
          members << SimpleSequence.new([Parent.new], false)
          members += old_members
        end
        CommaSequence.new(Sass::Util.paths(members.map do |sseq_or_op|
          next [sseq_or_op] unless sseq_or_op.is_a?(SimpleSequence)
          sseq_or_op.resolve_parent_refs(super_cseq).members
        end).map do |path|
          Sequence.new(path.map do |seq_or_op|
            next seq_or_op unless seq_or_op.is_a?(Sequence)
            seq_or_op.members
          end.flatten)
        end)
      end
      def contains_parent_ref?
        members.any? do |sseq_or_op|
          next false unless sseq_or_op.is_a?(SimpleSequence)
          next true if sseq_or_op.members.first.is_a?(Parent)
          sseq_or_op.members.any? do |sel|
            sel.is_a?(Pseudo) && sel.selector && sel.selector.contains_parent_ref?
          end
        end
      end
      def do_extend(extends, parent_directives, replace, seen, original)
        extended_not_expanded = members.map do |sseq_or_op|
          next [[sseq_or_op]] unless sseq_or_op.is_a?(SimpleSequence)
          extended = sseq_or_op.do_extend(extends, parent_directives, replace, seen)
          extended.first.add_sources!([self]) if original && !has_placeholder?
          extended.map {|seq| seq.members}
        end
        weaves = Sass::Util.paths(extended_not_expanded).map {|path| weave(path)}
        trim(weaves).map {|p| Sequence.new(p)}
      end
      def unify(other)
        base = members.last
        other_base = other.members.last
        return unless base.is_a?(SimpleSequence) && other_base.is_a?(SimpleSequence)
        return unless (unified = other_base.unify(base))
        woven = weave([members[0...-1], other.members[0...-1] + [unified]])
        CommaSequence.new(woven.map {|w| Sequence.new(w)})
      end
      def superselector?(seq)
        _superselector?(members, seq.members)
      end
      def to_s
        @members.join(" ").gsub(/ ?\n ?/, "\n")
      end
      def inspect
        members.map {|m| m.inspect}.join(" ")
      end
      def add_sources!(sources)
        members.map! {|m| m.is_a?(SimpleSequence) ? m.with_more_sources(sources) : m}
      end
      def subjectless
        pre_subject = []
        has = []
        subject = nil
        members.each do |sseq_or_op|
          if subject
            has << sseq_or_op
          elsif sseq_or_op.is_a?(String) || !sseq_or_op.subject?
            pre_subject << sseq_or_op
          else
            subject = sseq_or_op.dup
            subject.members = sseq_or_op.members.dup
            subject.subject = false
            has = []
          end
        end
        return self unless subject
        unless has.empty?
          subject.members << Pseudo.new(:class, 'has', nil, CommaSequence.new([Sequence.new(has)]))
        end
        Sequence.new(pre_subject + [subject])
      end
      private
      def weave(path)
        prefixes = [[]]
        path.each do |current|
          next if current.empty?
          current = current.dup
          last_current = [current.pop]
          prefixes = Sass::Util.flatten(prefixes.map do |prefix|
            sub = subweave(prefix, current)
            next [] unless sub
            sub.map {|seqs| seqs + last_current}
          end, 1)
        end
        prefixes
      end
      def subweave(seq1, seq2)
        return [seq2] if seq1.empty?
        return [seq1] if seq2.empty?
        seq1, seq2 = seq1.dup, seq2.dup
        init = merge_initial_ops(seq1, seq2)
        return unless init
        fin = merge_final_ops(seq1, seq2)
        return unless fin
        seq1 = group_selectors(seq1)
        seq2 = group_selectors(seq2)
        lcs = Sass::Util.lcs(seq2, seq1) do |s1, s2|
          next s1 if s1 == s2
          next unless s1.first.is_a?(SimpleSequence) && s2.first.is_a?(SimpleSequence)
          next s2 if parent_superselector?(s1, s2)
          next s1 if parent_superselector?(s2, s1)
        end
        diff = [[init]]
        until lcs.empty?
          diff << chunks(seq1, seq2) {|s| parent_superselector?(s.first, lcs.first)} << [lcs.shift]
          seq1.shift
          seq2.shift
        end
        diff << chunks(seq1, seq2) {|s| s.empty?}
        diff += fin.map {|sel| sel.is_a?(Array) ? sel : [sel]}
        diff.reject! {|c| c.empty?}
        Sass::Util.paths(diff).map {|p| p.flatten}.reject {|p| path_has_two_subjects?(p)}
      end
      def merge_initial_ops(seq1, seq2)
        ops1, ops2 = [], []
        ops1 << seq1.shift while seq1.first.is_a?(String)
        ops2 << seq2.shift while seq2.first.is_a?(String)
        newline = false
        newline ||= !!ops1.shift if ops1.first == "\n"
        newline ||= !!ops2.shift if ops2.first == "\n"
        lcs = Sass::Util.lcs(ops1, ops2)
        return unless lcs == ops1 || lcs == ops2
        (newline ? ["\n"] : []) + (ops1.size > ops2.size ? ops1 : ops2)
      end
      def merge_final_ops(seq1, seq2, res = [])
        ops1, ops2 = [], []
        ops1 << seq1.pop while seq1.last.is_a?(String)
        ops2 << seq2.pop while seq2.last.is_a?(String)
        ops1.reject! {|o| o == "\n"}
        ops2.reject! {|o| o == "\n"}
        return res if ops1.empty? && ops2.empty?
        if ops1.size > 1 || ops2.size > 1
          lcs = Sass::Util.lcs(ops1, ops2)
          return unless lcs == ops1 || lcs == ops2
          res.unshift(*(ops1.size > ops2.size ? ops1 : ops2).reverse)
          return res
        end
        op1, op2 = ops1.first, ops2.first
        if op1 && op2
          sel1 = seq1.pop
          sel2 = seq2.pop
          if op1 == '~' && op2 == '~'
            if sel1.superselector?(sel2)
              res.unshift sel2, '~'
            elsif sel2.superselector?(sel1)
              res.unshift sel1, '~'
            else
              merged = sel1.unify(sel2)
              res.unshift [
                [sel1, '~', sel2, '~'],
                [sel2, '~', sel1, '~'],
                ([merged, '~'] if merged)
              ].compact
            end
          elsif (op1 == '~' && op2 == '+') || (op1 == '+' && op2 == '~')
            if op1 == '~'
              tilde_sel, plus_sel = sel1, sel2
            else
              tilde_sel, plus_sel = sel2, sel1
            end
            if tilde_sel.superselector?(plus_sel)
              res.unshift plus_sel, '+'
            else
              merged = plus_sel.unify(tilde_sel)
              res.unshift [
                [tilde_sel, '~', plus_sel, '+'],
                ([merged, '+'] if merged)
              ].compact
            end
          elsif op1 == '>' && %w[~ +].include?(op2)
            res.unshift sel2, op2
            seq1.push sel1, op1
          elsif op2 == '>' && %w[~ +].include?(op1)
            res.unshift sel1, op1
            seq2.push sel2, op2
          elsif op1 == op2
            merged = sel1.unify(sel2)
            return unless merged
            res.unshift merged, op1
          else
            return
          end
          return merge_final_ops(seq1, seq2, res)
        elsif op1
          seq2.pop if op1 == '>' && seq2.last && seq2.last.superselector?(seq1.last)
          res.unshift seq1.pop, op1
          return merge_final_ops(seq1, seq2, res)
        else # op2
          seq1.pop if op2 == '>' && seq1.last && seq1.last.superselector?(seq2.last)
          res.unshift seq2.pop, op2
          return merge_final_ops(seq1, seq2, res)
        end
      end
      def chunks(seq1, seq2)
        chunk1 = []
        chunk1 << seq1.shift until yield seq1
        chunk2 = []
        chunk2 << seq2.shift until yield seq2
        return [] if chunk1.empty? && chunk2.empty?
        return [chunk2] if chunk1.empty?
        return [chunk1] if chunk2.empty?
        [chunk1 + chunk2, chunk2 + chunk1]
      end
      def group_selectors(seq)
        newseq = []
        tail = seq.dup
        until tail.empty?
          head = []
          begin
            head << tail.shift
          end while !tail.empty? && head.last.is_a?(String) || tail.first.is_a?(String)
          newseq << head
        end
        newseq
      end
      def _superselector?(seq1, seq2)
        seq1 = seq1.reject {|e| e == "\n"}
        seq2 = seq2.reject {|e| e == "\n"}
        return if seq1.last.is_a?(String) || seq2.last.is_a?(String) ||
          seq1.first.is_a?(String) || seq2.first.is_a?(String)
        return if seq1.size > seq2.size
        return seq1.first.superselector?(seq2.last, seq2[0...-1]) if seq1.size == 1
        _, si = Sass::Util.enum_with_index(seq2).find do |e, i|
          return if i == seq2.size - 1
          next if e.is_a?(String)
          seq1.first.superselector?(e, seq2[0...i])
        end
        return unless si
        if seq1[1].is_a?(String)
          return unless seq2[si + 1].is_a?(String)
          return unless seq1[1] == "~" ? seq2[si + 1] != ">" : seq1[1] == seq2[si + 1]
          return if seq1.length == 3 && seq2.length > 3
          return _superselector?(seq1[2..-1], seq2[si + 2..-1])
        elsif seq2[si + 1].is_a?(String)
          return unless seq2[si + 1] == ">"
          return _superselector?(seq1[1..-1], seq2[si + 2..-1])
        else
          return _superselector?(seq1[1..-1], seq2[si + 1..-1])
        end
      end
      def parent_superselector?(seq1, seq2)
        base = Sass::Selector::SimpleSequence.new([Sass::Selector::Placeholder.new('<temp>')],
                                                  false)
        seq1 = [] if seq1.nil? #BT+
        seq2 = [] if seq2.nil? #BT+
        _superselector?(seq1 + [base], seq2 + [base])
      end
      def trim(seqses)
        return Sass::Util.flatten(seqses, 1) if seqses.size > 100
        result = seqses.dup
        seqses.each_with_index do |seqs1, i|
          result[i] = seqs1.reject do |seq1|
            max_spec = _sources(seq1).map do |seq|
              spec = seq.specificity
              spec.is_a?(Range) ? spec.max : spec
            end.max || 0
            result.any? do |seqs2|
              next if seqs1.equal?(seqs2)
              seqs2.any? do |seq2|
                spec2 = _specificity(seq2)
                spec2 = spec2.begin if spec2.is_a?(Range)
                spec2 >= max_spec && _superselector?(seq2, seq1)
              end
            end
          end
        end
        Sass::Util.flatten(result, 1)
      end
      def _hash
        members.reject {|m| m == "\n"}.hash
      end
      def _eql?(other)
        other.members.reject {|m| m == "\n"}.eql?(members.reject {|m| m == "\n"})
      end
      private
      def path_has_two_subjects?(path)
        subject = false
        path.each do |sseq_or_op|
          next unless sseq_or_op.is_a?(SimpleSequence)
          next unless sseq_or_op.subject?
          return true if subject
          subject = true
        end
        false
      end
      def _sources(seq)
        s = Set.new
        seq.map {|sseq_or_op| s.merge sseq_or_op.sources if sseq_or_op.is_a?(SimpleSequence)}
        s
      end
      def extended_not_expanded_to_s(extended_not_expanded)
        extended_not_expanded.map do |choices|
          choices = choices.map do |sel|
            next sel.first.to_s if sel.size == 1
            "#{sel.join ' '}"
          end
          next choices.first if choices.size == 1 && !choices.include?(' ')
          "(#{choices.join ', '})"
        end.join ' '
      end
    end
  end
end
module Sass
  module Selector
    class SimpleSequence < AbstractSequence
      attr_accessor :members
      attr_accessor :sources
      attr_accessor :source_range
      attr_writer :subject
      def base
        @base ||= (members.first if members.first.is_a?(Element) || members.first.is_a?(Universal))
      end
      def pseudo_elements
        @pseudo_elements ||= members.select {|sel| sel.is_a?(Pseudo) && sel.type == :element}
      end
      def selector_pseudo_classes
        @selector_pseudo_classes ||= members.
          select {|sel| sel.is_a?(Pseudo) && sel.type == :class && sel.selector}.
          group_by {|sel| sel.normalized_name}
      end
      def rest
        @rest ||= Set.new(members - [base] - pseudo_elements)
      end
      def subject?
        @subject
      end
      def initialize(selectors, subject, source_range = nil)
        @members = selectors
        @subject = subject
        @sources = Set.new
        @source_range = source_range
      end
      def resolve_parent_refs(super_cseq)
        resolved_members = @members.map do |sel|
          next sel unless sel.is_a?(Pseudo) && sel.selector
          sel.with_selector(sel.selector.resolve_parent_refs(super_cseq, !:implicit_parent))
        end.flatten
        unless (parent = resolved_members.first).is_a?(Parent)
          return CommaSequence.new([Sequence.new([SimpleSequence.new(resolved_members, subject?)])])
        end
        return super_cseq if @members.size == 1 && parent.suffix.nil?
        CommaSequence.new(super_cseq.members.map do |super_seq|
          members = super_seq.members.dup
          newline = members.pop if members.last == "\n"
          unless members.last.is_a?(SimpleSequence)
            raise Sass::SyntaxError.new("Invalid parent selector for \"#{self}\": \"" +
              super_seq.to_s + '"')
          end
          parent_sub = members.last.members
          unless parent.suffix.nil?
            parent_sub = parent_sub.dup
            parent_sub[-1] = parent_sub.last.dup
            case parent_sub.last
            when Sass::Selector::Class, Sass::Selector::Id, Sass::Selector::Placeholder
              parent_sub[-1] = parent_sub.last.class.new(parent_sub.last.name + parent.suffix)
            when Sass::Selector::Element
              parent_sub[-1] = parent_sub.last.class.new(
                parent_sub.last.name + parent.suffix,
                parent_sub.last.namespace)
            when Sass::Selector::Pseudo
              if parent_sub.last.arg || parent_sub.last.selector
                raise Sass::SyntaxError.new("Invalid parent selector for \"#{self}\": \"" +
                  super_seq.to_s + '"')
              end
              parent_sub[-1] = Sass::Selector::Pseudo.new(
                parent_sub.last.type,
                parent_sub.last.name + parent.suffix,
                nil, nil)
            else
              raise Sass::SyntaxError.new("Invalid parent selector for \"#{self}\": \"" +
                super_seq.to_s + '"')
            end
          end
          Sequence.new(members[0...-1] +
            [SimpleSequence.new(parent_sub + resolved_members[1..-1], subject?)] +
            [newline].compact)
          end)
      end
      def do_extend(extends, parent_directives, replace, seen)
        seen_with_pseudo_selectors = seen.dup
        modified_original = false
        members = Sass::Util.enum_with_index(self.members).map do |sel, i|
          next sel unless sel.is_a?(Pseudo) && sel.selector
          next sel if seen.include?([sel])
          extended = sel.selector.do_extend(extends, parent_directives, replace, seen, !:original)
          next sel if extended == sel.selector
          extended.members.reject! {|seq| seq.has_placeholder?}
          if sel.normalized_name == 'not' &&
              (sel.selector.members.none? {|seq| seq.members.length > 1} &&
               extended.members.any? {|seq| seq.members.length == 1})
            extended.members.reject! {|seq| seq.members.length > 1}
          end
          modified_original = true
          result = sel.with_selector(extended)
          result.each {|new_sel| seen_with_pseudo_selectors << [new_sel]}
          result
        end.flatten
        groups = Sass::Util.group_by_to_a(extends[members.to_set]) {|ex| ex.extender}
        groups.map! do |seq, group|
          sels = group.map {|e| e.target}.flatten
          self_without_sel = Sass::Util.array_minus(members, sels)
          group.each {|e| e.result = :failed_to_unify unless e.result == :succeeded}
          unified = seq.members.last.unify(SimpleSequence.new(self_without_sel, subject?))
          next unless unified
          group.each {|e| e.result = :succeeded}
          group.each {|e| check_directives_match!(e, parent_directives)}
          new_seq = Sequence.new(seq.members[0...-1] + [unified])
          new_seq.add_sources!(sources + [seq])
          [sels, new_seq]
        end
        groups.compact!
        groups.map! do |sels, seq|
          next [] if seen.include?(sels)
          seq.do_extend(
            extends, parent_directives, !:replace, seen_with_pseudo_selectors + [sels], !:original)
        end
        groups.flatten!
        if modified_original || !replace || groups.empty?
          original = Sequence.new([SimpleSequence.new(members, @subject, source_range)])
          original.add_sources! sources
          groups.unshift original
        end
        groups.uniq!
        groups
      end
      def unify(other)
        sseq = members.inject(other.members) do |member, sel|
          return unless member
          sel.unify(member)
        end
        return unless sseq
        SimpleSequence.new(sseq, other.subject? || subject?)
      end
      def superselector?(their_sseq, parents = [])
        return false unless base.nil? || base.eql?(their_sseq.base)
        return false unless pseudo_elements.eql?(their_sseq.pseudo_elements)
        our_spcs = selector_pseudo_classes
        their_spcs = their_sseq.selector_pseudo_classes
        their_subselector_pseudos = %w[matches any nth-child nth-last-child].
          map {|name| their_spcs[name] || []}.flatten
        return false unless rest.all? do |our_sel|
          next true if our_sel.is_a?(Pseudo) && our_sel.selector
          next true if their_sseq.rest.include?(our_sel)
          their_subselector_pseudos.any? do |their_pseudo|
            their_pseudo.selector.members.all? do |their_seq|
              next false unless their_seq.members.length == 1
              their_sseq = their_seq.members.first
              next false unless their_sseq.is_a?(SimpleSequence)
              their_sseq.rest.include?(our_sel)
            end
          end
        end
        our_spcs.all? do |name, pseudos|
          pseudos.all? {|pseudo| pseudo.superselector?(their_sseq, parents)}
        end
      end
      def to_s
        res = @members.join
        res << '!' if subject?
        res
      end
      def inspect
        res = members.map {|m| m.inspect}.join
        res << '!' if subject?
        res
      end
      def with_more_sources(sources)
        sseq = dup
        sseq.members = members.dup
        sseq.sources = self.sources | sources
        sseq
      end
      private
      def check_directives_match!(extend, parent_directives)
        dirs1 = extend.directives.map {|d| d.resolved_value}
        dirs2 = parent_directives.map {|d| d.resolved_value}
        return if Sass::Util.subsequence?(dirs1, dirs2)
        line = extend.node.line
        filename = extend.node.filename
        raise Sass::SyntaxError.new(<<MESSAGE)
You may not @extend an outer selector from within #{extend.directives.last.name}.
You may only @extend selectors within the same directive.
From "@extend #{extend.target.join(', ')}" on line #{line}#{" of #{filename}" if filename}.
MESSAGE
      end
      def _hash
        [base, Sass::Util.set_hash(rest)].hash
      end
      def _eql?(other)
        other.base.eql?(base) && other.pseudo_elements == pseudo_elements &&
          Sass::Util.set_eql?(other.rest, rest) && other.subject? == subject?
      end
    end
  end
end
module Sass
  module Selector
    SPECIFICITY_BASE = 1_000
    class Parent < Simple
      attr_reader :suffix
      def initialize(suffix = nil)
        @suffix = suffix
      end
      def to_s
        "&" + (@suffix || '')
      end
      def unify(sels)
        raise Sass::SyntaxError.new("[BUG] Cannot unify parent selectors.")
      end
    end
    class Class < Simple
      attr_reader :name
      def initialize(name)
        @name = name
      end
      def to_s
        "." + @name
      end
      def specificity
        SPECIFICITY_BASE
      end
    end
    class Id < Simple
      attr_reader :name
      def initialize(name)
        @name = name
      end
      def to_s
        "#" + @name
      end
      def unify(sels)
        return if sels.any? {|sel2| sel2.is_a?(Id) && name != sel2.name}
        super
      end
      def specificity
        SPECIFICITY_BASE**2
      end
    end
    class Placeholder < Simple
      attr_reader :name
      def initialize(name)
        @name = name
      end
      def to_s
        "%" + @name
      end
      def specificity
        SPECIFICITY_BASE
      end
    end
    class Universal < Simple
      attr_reader :namespace
      def initialize(namespace)
        @namespace = namespace
      end
      def to_s
        @namespace ? "#{@namespace}|*" : "*"
      end
      def unify(sels)
        name =
          case sels.first
          when Universal; :universal
          when Element; sels.first.name
          else
            return [self] + sels unless namespace.nil? || namespace == '*'
            return sels unless sels.empty?
            return [self]
          end
        ns, accept = unify_namespaces(namespace, sels.first.namespace)
        return unless accept
        [name == :universal ? Universal.new(ns) : Element.new(name, ns)] + sels[1..-1]
      end
      def specificity
        0
      end
    end
    class Element < Simple
      attr_reader :name
      attr_reader :namespace
      def initialize(name, namespace)
        @name = name
        @namespace = namespace
      end
      def to_s
        @namespace ? "#{@namespace}|#{@name}" : @name
      end
      def unify(sels)
        case sels.first
        when Universal;
        when Element; return unless name == sels.first.name
        else return [self] + sels
        end
        ns, accept = unify_namespaces(namespace, sels.first.namespace)
        return unless accept
        [Element.new(name, ns)] + sels[1..-1]
      end
      def specificity
        1
      end
    end
    class Attribute < Simple
      attr_reader :name
      attr_reader :namespace
      attr_reader :operator
      attr_reader :value
      attr_reader :flags
      def initialize(name, namespace, operator, value, flags)
        @name = name
        @namespace = namespace
        @operator = operator
        @value = value
        @flags = flags
      end
      def to_s
        res = "["
        res << @namespace << "|" if @namespace
        res << @name
        res << @operator << @value if @value
        res << " " << @flags if @flags
        res << "]"
      end
      def specificity
        SPECIFICITY_BASE
      end
    end
  end
end
module Sass
  class BaseEnvironment
    class << self
      def inherited_hash_accessor(name)
        inherited_hash_reader(name)
        inherited_hash_writer(name)
      end
      def inherited_hash_reader(name)
        class_eval <<-RUBY, __FILE__, __LINE__ + 1
          def #{name}(name)
            _#{name}(name.tr('_', '-'))
          end
          def _#{name}(name)
            (@#{name}s && @#{name}s[name]) || @parent && @parent._#{name}(name)
          end
          protected :_#{name}
          def is_#{name}_global?(name)
            return !@parent if @#{name}s && @#{name}s.has_key?(name)
            @parent && @parent.is_#{name}_global?(name)
          end
        RUBY
      end
      def inherited_hash_writer(name)
        class_eval <<-RUBY, __FILE__, __LINE__ + 1
          def set_#{name}(name, value)
            name = name.tr('_', '-')
            @#{name}s[name] = value unless try_set_#{name}(name, value)
          end
          def try_set_#{name}(name, value)
            @#{name}s ||= {}
            if @#{name}s.include?(name)
              @#{name}s[name] = value
              true
            elsif @parent && !@parent.global?
              @parent.try_set_#{name}(name, value)
            else
              false
            end
          end
          protected :try_set_#{name}
          def set_local_#{name}(name, value)
            @#{name}s ||= {}
            @#{name}s[name.tr('_', '-')] = value
          end
          def set_global_#{name}(name, value)
            global_env.set_#{name}(name, value)
          end
        RUBY
      end
    end
    attr_reader :options
    attr_writer :caller
    attr_writer :content
    attr_writer :selector
    inherited_hash_reader :var
    inherited_hash_reader :mixin
    inherited_hash_reader :function
    def initialize(parent = nil, options = nil)
      @parent = parent
      @options = options || (parent && parent.options) || {}
      @stack = Sass::Stack.new if @parent.nil?
    end
    def global?
      @parent.nil?
    end
    def caller
      @caller || (@parent && @parent.caller)
    end
    def content
      @content || (@parent && @parent.content)
    end
    def selector
      @selector || (@caller && @caller.selector) || (@parent && @parent.selector)
    end
    def global_env
      @global_env ||= global? ? self : @parent.global_env
    end
    def stack
      @stack || global_env.stack
    end
  end
  class Environment < BaseEnvironment
    attr_reader :parent
    inherited_hash_writer :var
    inherited_hash_writer :mixin
    inherited_hash_writer :function
  end
  class ReadOnlyEnvironment < BaseEnvironment
    def caller
      return @caller if @caller
      env = super
      @caller ||= env.is_a?(ReadOnlyEnvironment) ? env : ReadOnlyEnvironment.new(env, env.options)
    end
    def content
      return @content if @content
      env = super
      @content ||= env.is_a?(ReadOnlyEnvironment) ? env : ReadOnlyEnvironment.new(env, env.options)
    end
  end
  class SemiGlobalEnvironment < Environment
    def try_set_var(name, value)
      @vars ||= {}
      if @vars.include?(name)
        @vars[name] = value
        true
      elsif @parent
        @parent.try_set_var(name, value)
      else
        false
      end
    end
  end
end
module Sass
  module SCSS
    module RX
      def self.escape_ident(str)
        return "" if str.empty?
        return "\\#{str}" if str == '-' || str == '_'
        out = ""
        value = str.dup
        out << value.slice!(0...1) if value =~ /^[-_]/
        if value[0...1] =~ NMSTART
          out << value.slice!(0...1)
        else
          out << escape_char(value.slice!(0...1))
        end
        out << value.gsub(/[^a-zA-Z0-9_-]/) {|c| escape_char c}
        out
      end
      def self.escape_char(c)
        return "\\%06x" % Sass::Util.ord(c) unless c =~ /[ -\/:-~]/
        "\\#{c}"
      end
      def self.quote(str, flags = 0)
        Regexp.new(Regexp.quote(str), flags)
      end
      H        = /[0-9a-fA-F]/
      NL       = /\n|\r\n|\r|\f/
      UNICODE  = /\\#{H}{1,6}[ \t\r\n\f]?/
      s = if Sass::Util.ruby1_8?
            '\200-\377'
          elsif Sass::Util.macruby?
            '\u0080-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF'
          else
            '\u{80}-\u{D7FF}\u{E000}-\u{FFFD}\u{10000}-\u{10FFFF}'
          end
      NONASCII = /[#{s}]/
      ESCAPE   = /#{UNICODE}|\\[ -~#{s}]/
      NMSTART  = /[_a-zA-Z]|#{NONASCII}|#{ESCAPE}/
      NMCHAR   = /[a-zA-Z0-9_-]|#{NONASCII}|#{ESCAPE}/
      STRING1  = /\"((?:[^\n\r\f\\"]|\\#{NL}|#{ESCAPE})*)\"/
      STRING2  = /\'((?:[^\n\r\f\\']|\\#{NL}|#{ESCAPE})*)\'/
      IDENT    = /-*#{NMSTART}#{NMCHAR}*/
      NAME     = /#{NMCHAR}+/
      NUM      = //
      STRING   = /#{STRING1}|#{STRING2}/
      URLCHAR  = /[#%&*-~]|#{NONASCII}|#{ESCAPE}/
      URL      = /(#{URLCHAR}*)/
      W        = /[ \t\r\n\f]*/
      VARIABLE = /(\$)(#{Sass::SCSS::RX::IDENT})/
      RANGE    = /(?:#{H}|\?){1,6}/
      S = /[ \t\r\n\f]+/
      COMMENT = %r{(?<![^/]?/)/\*([^*]|\*+[^/*])*\**\*/} #BT+
      SINGLE_LINE_COMMENT = %r{//.*(\n[ \t]*//.*)*}
      CDO            = quote("<!--")
      CDC            = quote("-->")
      INCLUDES       = quote("~=")
      DASHMATCH      = quote("|=")
      PREFIXMATCH    = quote("^=")
      SUFFIXMATCH    = quote("$=")
      SUBSTRINGMATCH = quote("*=")
      HASH = /##{NAME}/
      IMPORTANT = /!#{W}important/i
      UNITLESS_NUMBER = /(?:[0-9]+|[0-9]*\.[0-9]+)(?:[eE][+-]?\d+)?/
      NUMBER = /#{UNITLESS_NUMBER}(?:#{IDENT}|%)?/
      PERCENTAGE = /#{UNITLESS_NUMBER}%/
      URI = /url\(#{W}(?:#{STRING}|#{URL})#{W}\)/i
      FUNCTION = /#{IDENT}\(/
      UNICODERANGE = /u\+(?:#{H}{1,6}-#{H}{1,6}|#{RANGE})/i
      PLUS = /#{W}\+/
      GREATER = /#{W}>/
      TILDE = /#{W}~/
      NOT = quote(":not(", Regexp::IGNORECASE)
      URL_PREFIX = /url-prefix\(#{W}(?:#{STRING}|#{URL})#{W}\)/i
      DOMAIN = /domain\(#{W}(?:#{STRING}|#{URL})#{W}\)/i
      HEXCOLOR = /\#[0-9a-fA-F]+/
      INTERP_START = /#\{/
      ANY = /:(-[-\w]+-)?any\(/i
      OPTIONAL = /!#{W}optional/i
      IDENT_START = /-|#{NMSTART}/
      UNIT = /-?#{NMSTART}(?:[a-zA-Z0-9_]|#{NONASCII}|#{ESCAPE}|-(?!\d))*|%/
      IDENT_HYPHEN_INTERP = /-(#\{)/
      STRING1_NOINTERP = /\"((?:[^\n\r\f\\"#]|#(?!\{)|#{ESCAPE})*)\"/
      STRING2_NOINTERP = /\'((?:[^\n\r\f\\'#]|#(?!\{)|#{ESCAPE})*)\'/
      STRING_NOINTERP = /#{STRING1_NOINTERP}|#{STRING2_NOINTERP}/
      STATIC_COMPONENT = /#{IDENT}|#{STRING_NOINTERP}|#{HEXCOLOR}|[+-]?#{NUMBER}|\!important/i
      STATIC_VALUE = /#{STATIC_COMPONENT}(\s*[\s,\/]\s*#{STATIC_COMPONENT})*([;}])/i
      STATIC_SELECTOR = /(#{NMCHAR}|[ \t]|[,>+*]|[:#.]#{NMSTART}){1,50}([{])/i
    end
  end
end
module Sass
  module Script
    MATCH = /^\$(#{Sass::SCSS::RX::IDENT})\s*:\s*(.+?)
      (!#{Sass::SCSS::RX::IDENT}(?:\s+!#{Sass::SCSS::RX::IDENT})*)?$/x
    VALIDATE = /^\$#{Sass::SCSS::RX::IDENT}$/
    def self.parse(value, line, offset, options = {})
      Parser.parse(value, line, offset, options)
    rescue Sass::SyntaxError => e
      e.message << ": #{value.inspect}." if e.message == "SassScript error"
      e.modify_backtrace(:line => line, :filename => options[:filename])
      raise e
    end
  end
end
module Sass::Script::Value
  module Helpers
    def bool(value)
      Bool.new(value)
    end
    def hex_color(value, alpha = nil)
      Color.from_hex(value, alpha)
    end
    def hsl_color(hue, saturation, lightness, alpha = nil)
      attrs = {:hue => hue, :saturation => saturation, :lightness => lightness}
      attrs[:alpha] = alpha if alpha
      Color.new(attrs)
    end
    def rgb_color(red, green, blue, alpha = nil)
      attrs = {:red => red, :green => green, :blue => blue}
      attrs[:alpha] = alpha if alpha
      Color.new(attrs)
    end
    def number(number, unit_string = nil)
      Number.new(number, *parse_unit_string(unit_string))
    end
    def list(*elements)
      unless elements.last.is_a?(Symbol)
        raise ArgumentError.new("A list type of :space or :comma must be specified.")
      end
      separator = elements.pop
      if elements.size == 1 && elements.first.is_a?(Array)
        elements = elements.first
      end
      Sass::Script::Value::List.new(elements, separator)
    end
    def map(hash)
      Map.new(hash)
    end
    def null
      Sass::Script::Value::Null.new
    end
    def quoted_string(str)
      Sass::Script::String.new(str, :string)
    end
    def unquoted_string(str)
      Sass::Script::String.new(str, :identifier)
    end
    alias_method :identifier, :unquoted_string
    def parse_selector(value, name = nil, allow_parent_ref = false)
      str = normalize_selector(value, name)
      begin
        Sass::SCSS::StaticParser.new(str, nil, nil, 1, 1, allow_parent_ref).parse_selector
      rescue Sass::SyntaxError => e
        err = "#{value.inspect} is not a valid selector: #{e}"
        err = "$#{name.to_s.gsub('_', '-')}: #{err}" if name
        raise ArgumentError.new(err)
      end
    end
    def parse_complex_selector(value, name = nil, allow_parent_ref = false)
      selector = parse_selector(value, name, allow_parent_ref)
      return seq if selector.members.length == 1
      err = "#{value.inspect} is not a complex selector"
      err = "$#{name.to_s.gsub('_', '-')}: #{err}" if name
      raise ArgumentError.new(err)
    end
    def parse_compound_selector(value, name = nil, allow_parent_ref = false)
      assert_type value, :String, name
      selector = parse_selector(value, name, allow_parent_ref)
      seq = selector.members.first
      sseq = seq.members.first
      if selector.members.length == 1 && seq.members.length == 1 &&
          sseq.is_a?(Sass::Selector::SimpleSequence)
        return sseq
      end
      err = "#{value.inspect} is not a compound selector"
      err = "$#{name.to_s.gsub('_', '-')}: #{err}" if name
      raise ArgumentError.new(err)
    end
    private
    def normalize_selector(value, name)
      if (str = selector_to_str(value))
        return str
      end
      err = "#{value.inspect} is not a valid selector: it must be a string,\n" +
        "a list of strings, or a list of lists of strings"
      err = "$#{name.to_s.gsub('_', '-')}: #{err}" if name
      raise ArgumentError.new(err)
    end
    def selector_to_str(value)
      return value.value if value.is_a?(Sass::Script::String)
      return unless value.is_a?(Sass::Script::List)
      if value.separator == :comma
        return value.to_a.map do |complex|
          next complex.value if complex.is_a?(Sass::Script::String)
          return unless complex.is_a?(Sass::Script::List) && complex.separator == :space
          return unless (str = selector_to_str(complex))
          str
        end.join(', ')
      end
      value.to_a.map do |compound|
        return unless compound.is_a?(Sass::Script::String)
        compound.value
      end.join(' ')
    end
    VALID_UNIT = /#{Sass::SCSS::RX::NMSTART}#{Sass::SCSS::RX::NMCHAR}|%*/
    def parse_unit_string(unit_string)
      denominator_units = numerator_units = Sass::Script::Value::Number::NO_UNITS
      return numerator_units, denominator_units unless unit_string && unit_string.length > 0
      num_over_denominator = unit_string.split(/ *\/ */)
      unless (1..2).include?(num_over_denominator.size)
        raise ArgumentError.new("Malformed unit string: #{unit_string}")
      end
      numerator_units = num_over_denominator[0].split(/ *\* */)
      denominator_units = (num_over_denominator[1] || "").split(/ *\* */)
      [[numerator_units, "numerator"], [denominator_units, "denominator"]].each do |units, name|
        if unit_string =~ /\// && units.size == 0
          raise ArgumentError.new("Malformed unit string: #{unit_string}")
        end
        if units.any? {|unit| unit !~ VALID_UNIT}
          raise ArgumentError.new("Malformed #{name} in unit string: #{unit_string}")
        end
      end
      [numerator_units, denominator_units]
    end
  end
end
module Sass::Script
  module Functions
    @signatures = {}
    Signature = Struct.new(:args, :delayed_args, :var_args, :var_kwargs, :deprecated)
    def self.declare(method_name, args, options = {})
      delayed_args = []
      args = args.map do |a|
        a = a.to_s
        if a[0] == ?&
          a = a[1..-1]
          delayed_args << a
        end
        a
      end
      if delayed_args.any? && method_name != :if
        raise ArgumentError.new("Delayed arguments are not allowed for method #{method_name}")
      end
      @signatures[method_name] ||= []
      @signatures[method_name] << Signature.new(
        args,
        delayed_args,
        options[:var_args],
        options[:var_kwargs],
        options[:deprecated] && options[:deprecated].map {|a| a.to_s})
    end
    def self.signature(method_name, arg_arity, kwarg_arity)
      return unless @signatures[method_name]
      @signatures[method_name].each do |signature|
        sig_arity = signature.args.size
        return signature if sig_arity == arg_arity + kwarg_arity
        next unless sig_arity < arg_arity + kwarg_arity
        t_arg_arity, t_kwarg_arity = arg_arity, kwarg_arity
        if sig_arity > t_arg_arity
          t_kwarg_arity -= (sig_arity - t_arg_arity)
          t_arg_arity = sig_arity
        end
        if   (t_arg_arity == sig_arity ||   t_arg_arity > sig_arity && signature.var_args) &&
           (t_kwarg_arity == 0         || t_kwarg_arity > 0         && signature.var_kwargs)
          return signature
        end
      end
      @signatures[method_name].first
    end
    def self.random_seed=(seed)
      @random_number_generator = Sass::Util::CrossPlatformRandom.new(seed)
    end
    def self.random_number_generator
      @random_number_generator ||= Sass::Util::CrossPlatformRandom.new
    end
    class EvaluationContext
      include Functions
      include Value::Helpers
      TYPE_NAMES = {:ArgList => 'variable argument list'}
      attr_reader :environment
      attr_reader :options
      def initialize(environment)
        @environment = environment
        @options = environment.options
      end
      def assert_type(value, type, name = nil)
        klass = Sass::Script::Value.const_get(type)
        return if value.is_a?(klass)
        return if value.is_a?(Sass::Script::Value::List) && type == :Map && value.value.empty?
        err = "#{value.inspect} is not a #{TYPE_NAMES[type] || type.to_s.downcase}"
        err = "$#{name.to_s.gsub('_', '-')}: " + err if name
        raise ArgumentError.new(err)
      end
      def assert_unit(number, unit, name = nil)
        assert_type number, :Number, name
        return if number.is_unit?(unit)
        expectation = unit ? "have a unit of #{unit}" : "be unitless"
        if name
          raise ArgumentError.new("Expected $#{name} to #{expectation} but got #{number}")
        else
          raise ArgumentError.new("Expected #{number} to #{expectation}")
        end
      end
      def assert_integer(number, name = nil)
        assert_type number, :Number, name
        return if number.int?
        if name
          raise ArgumentError.new("Expected $#{name} to be an integer but got #{number}")
        else
          raise ArgumentError.new("Expected #{number} to be an integer")
        end
      end
      def perform(node, env = environment.caller)
        if node.is_a?(Sass::Script::Value::Base)
          node
        else
          node.perform(env)
        end
      end
    end
    class << self
      alias_method :callable?, :public_method_defined?
      private
      def include(*args)
        r = super
        EvaluationContext.send :include, self
        r
      end
    end
    def rgb(red, green, blue)
      assert_type red, :Number, :red
      assert_type green, :Number, :green
      assert_type blue, :Number, :blue
      color_attrs = [[red, :red], [green, :green], [blue, :blue]].map do |(c, name)|
        if c.is_unit?("%")
          c.value * 255 / 100.0
        elsif c.unitless?
          c.value
        else
          raise ArgumentError.new("Expected #{c} to be unitless or have a unit of % but got #{c}")
        end
      end
      Sass::Script::Value::Color.new(color_attrs)
    end
    declare :rgb, [:red, :green, :blue]
    def rgba(*args)
      case args.size
      when 2
        color, alpha = args
        assert_type color, :Color, :color
        assert_type alpha, :Number, :alpha
        check_alpha_unit alpha, 'rgba'
        color.with(:alpha => alpha.value)
      when 4
        red, green, blue, alpha = args
        rgba(rgb(red, green, blue), alpha)
      else
        raise ArgumentError.new("wrong number of arguments (#{args.size} for 4)")
      end
    end
    declare :rgba, [:red, :green, :blue, :alpha]
    declare :rgba, [:color, :alpha]
    def hsl(hue, saturation, lightness)
      hsla(hue, saturation, lightness, number(1))
    end
    declare :hsl, [:hue, :saturation, :lightness]
    def hsla(hue, saturation, lightness, alpha)
      assert_type hue, :Number, :hue
      assert_type saturation, :Number, :saturation
      assert_type lightness, :Number, :lightness
      assert_type alpha, :Number, :alpha
      check_alpha_unit alpha, 'hsla'
      h = hue.value
      s = saturation.value
      l = lightness.value
      Sass::Script::Value::Color.new(
        :hue => h, :saturation => s, :lightness => l, :alpha => alpha.value)
    end
    declare :hsla, [:hue, :saturation, :lightness, :alpha]
    def red(color)
      assert_type color, :Color, :color
      number(color.red)
    end
    declare :red, [:color]
    def green(color)
      assert_type color, :Color, :color
      number(color.green)
    end
    declare :green, [:color]
    def blue(color)
      assert_type color, :Color, :color
      number(color.blue)
    end
    declare :blue, [:color]
    def hue(color)
      assert_type color, :Color, :color
      number(color.hue, "deg")
    end
    declare :hue, [:color]
    def saturation(color)
      assert_type color, :Color, :color
      number(color.saturation, "%")
    end
    declare :saturation, [:color]
    def lightness(color)
      assert_type color, :Color, :color
      number(color.lightness, "%")
    end
    declare :lightness, [:color]
    def alpha(*args)
      if args.all? do |a|
           a.is_a?(Sass::Script::Value::String) && a.type == :identifier &&
             a.value =~ /^[a-zA-Z]+\s*=/
         end
        return identifier("alpha(#{args.map {|a| a.to_s}.join(", ")})")
      end
      raise ArgumentError.new("wrong number of arguments (#{args.size} for 1)") if args.size != 1
      assert_type args.first, :Color, :color
      number(args.first.alpha)
    end
    declare :alpha, [:color]
    def opacity(color)
      if color.is_a?(Sass::Script::Value::Number)
        return identifier("opacity(#{color})")
      end
      assert_type color, :Color, :color
      number(color.alpha)
    end
    declare :opacity, [:color]
    def opacify(color, amount)
      _adjust(color, amount, :alpha, 0..1, :+)
    end
    declare :opacify, [:color, :amount]
    alias_method :fade_in, :opacify
    declare :fade_in, [:color, :amount]
    def transparentize(color, amount)
      _adjust(color, amount, :alpha, 0..1, :-)
    end
    declare :transparentize, [:color, :amount]
    alias_method :fade_out, :transparentize
    declare :fade_out, [:color, :amount]
    def lighten(color, amount)
      _adjust(color, amount, :lightness, 0..100, :+, "%")
    end
    declare :lighten, [:color, :amount]
    def darken(color, amount)
      _adjust(color, amount, :lightness, 0..100, :-, "%")
    end
    declare :darken, [:color, :amount]
    def saturate(color, amount = nil)
      return identifier("saturate(#{color})") if amount.nil?
      _adjust(color, amount, :saturation, 0..100, :+, "%")
    end
    declare :saturate, [:color, :amount]
    declare :saturate, [:amount]
    def desaturate(color, amount)
      _adjust(color, amount, :saturation, 0..100, :-, "%")
    end
    declare :desaturate, [:color, :amount]
    def adjust_hue(color, degrees)
      assert_type color, :Color, :color
      assert_type degrees, :Number, :degrees
      color.with(:hue => color.hue + degrees.value)
    end
    declare :adjust_hue, [:color, :degrees]
    def ie_hex_str(color)
      assert_type color, :Color, :color
      alpha = (color.alpha * 255).round.to_s(16).rjust(2, '0')
      identifier("##{alpha}#{color.send(:hex_str)[1..-1]}".upcase)
    end
    declare :ie_hex_str, [:color]
    def adjust_color(color, kwargs)
      assert_type color, :Color, :color
      with = Sass::Util.map_hash(
          "red" => [-255..255, ""],
          "green" => [-255..255, ""],
          "blue" => [-255..255, ""],
          "hue" => nil,
          "saturation" => [-100..100, "%"],
          "lightness" => [-100..100, "%"],
          "alpha" => [-1..1, ""]
        ) do |name, (range, units)|
        val = kwargs.delete(name)
        next unless val
        assert_type val, :Number, name
        Sass::Util.check_range("$#{name}: Amount", range, val, units) if range
        adjusted = color.send(name) + val.value
        adjusted = [0, Sass::Util.restrict(adjusted, range)].max if range
        [name.to_sym, adjusted]
      end
      unless kwargs.empty?
        name, val = kwargs.to_a.first
        raise ArgumentError.new("Unknown argument $#{name} (#{val})")
      end
      color.with(with)
    end
    declare :adjust_color, [:color], :var_kwargs => true
    def scale_color(color, kwargs)
      assert_type color, :Color, :color
      with = Sass::Util.map_hash(
          "red" => 255,
          "green" => 255,
          "blue" => 255,
          "saturation" => 100,
          "lightness" => 100,
          "alpha" => 1
        ) do |name, max|
        val = kwargs.delete(name)
        next unless val
        assert_type val, :Number, name
        assert_unit val, '%', name
        Sass::Util.check_range("$#{name}: Amount", -100..100, val, '%')
        current = color.send(name)
        scale = val.value / 100.0
        diff = scale > 0 ? max - current : current
        [name.to_sym, current + diff * scale]
      end
      unless kwargs.empty?
        name, val = kwargs.to_a.first
        raise ArgumentError.new("Unknown argument $#{name} (#{val})")
      end
      color.with(with)
    end
    declare :scale_color, [:color], :var_kwargs => true
    def change_color(color, kwargs)
      assert_type color, :Color, :color
      with = Sass::Util.map_hash(
        'red' => ['Red value', 0..255],
        'green' => ['Green value', 0..255],
        'blue' => ['Blue value', 0..255],
        'hue' => [],
        'saturation' => ['Saturation', 0..100, '%'],
        'lightness' => ['Lightness', 0..100, '%'],
        'alpha' => ['Alpha channel', 0..1]
      ) do |name, (desc, range, unit)|
        val = kwargs.delete(name)
        next unless val
        assert_type val, :Number, name
        if range
          val = Sass::Util.check_range(desc, range, val, unit)
        else
          val = val.value
        end
        [name.to_sym, val]
      end
      unless kwargs.empty?
        name, val = kwargs.to_a.first
        raise ArgumentError.new("Unknown argument $#{name} (#{val})")
      end
      color.with(with)
    end
    declare :change_color, [:color], :var_kwargs => true
    def mix(color1, color2, weight = number(50))
      assert_type color1, :Color, :color1
      assert_type color2, :Color, :color2
      assert_type weight, :Number, :weight
      Sass::Util.check_range("Weight", 0..100, weight, '%')
      p = (weight.value / 100.0).to_f
      w = p * 2 - 1
      a = color1.alpha - color2.alpha
      w1 = ((w * a == -1 ? w : (w + a) / (1 + w * a)) + 1) / 2.0
      w2 = 1 - w1
      rgba = color1.rgb.zip(color2.rgb).map {|v1, v2| v1 * w1 + v2 * w2}
      rgba << color1.alpha * p + color2.alpha * (1 - p)
      rgb_color(*rgba)
    end
    declare :mix, [:color1, :color2]
    declare :mix, [:color1, :color2, :weight]
    def grayscale(color)
      if color.is_a?(Sass::Script::Value::Number)
        return identifier("grayscale(#{color})")
      end
      desaturate color, number(100)
    end
    declare :grayscale, [:color]
    def complement(color)
      adjust_hue color, number(180)
    end
    declare :complement, [:color]
    def invert(color)
      if color.is_a?(Sass::Script::Value::Number)
        return identifier("invert(#{color})")
      end
      assert_type color, :Color, :color
      color.with(
        :red => (255 - color.red),
        :green => (255 - color.green),
        :blue => (255 - color.blue))
    end
    declare :invert, [:color]
    def unquote(string)
      unless string.is_a?(Sass::Script::Value::String)
        Sass::Util.sass_warn(<<MESSAGE.strip)
DEPRECATION WARNING: Passing #{string.to_sass}, a non-string value, to unquote()
will be an error in future versions of Sass.
MESSAGE
        return string
      end
      return string if string.type == :identifier
      identifier(string.value)
    end
    declare :unquote, [:string]
    def quote(string)
      assert_type string, :String, :string
      if string.type != :string
        quoted_string(string.value)
      else
        string
      end
    end
    declare :quote, [:string]
    def str_length(string)
      assert_type string, :String, :string
      number(string.value.size)
    end
    declare :str_length, [:string]
    def str_insert(original, insert, index)
      assert_type original, :String, :string
      assert_type insert, :String, :insert
      assert_integer index, :index
      assert_unit index, nil, :index
      insertion_point = if index.to_i > 0
                          [index.to_i - 1, original.value.size].min
                        else
                          [index.to_i, -original.value.size - 1].max
                        end
      result = original.value.dup.insert(insertion_point, insert.value)
      Sass::Script::Value::String.new(result, original.type)
    end
    declare :str_insert, [:string, :insert, :index]
    def str_index(string, substring)
      assert_type string, :String, :string
      assert_type substring, :String, :substring
      index = string.value.index(substring.value)
      index ? number(index + 1) : null
    end
    declare :str_index, [:string, :substring]
    def str_slice(string, start_at, end_at = nil)
      assert_type string, :String, :string
      assert_unit start_at, nil, "start-at"
      end_at = number(-1) if end_at.nil?
      assert_unit end_at, nil, "end-at"
      return Sass::Script::Value::String.new("", string.type) if end_at.value == 0
      s = start_at.value > 0 ? start_at.value - 1 : start_at.value
      e = end_at.value > 0 ? end_at.value - 1 : end_at.value
      s = string.value.length + s if s < 0
      s = 0 if s < 0
      e = string.value.length + e if e < 0
      e = 0 if s < 0
      extracted = string.value.slice(s..e)
      Sass::Script::Value::String.new(extracted || "", string.type)
    end
    declare :str_slice, [:string, :start_at]
    declare :str_slice, [:string, :start_at, :end_at]
    def to_upper_case(string)
      assert_type string, :String, :string
      Sass::Script::Value::String.new(string.value.upcase, string.type)
    end
    declare :to_upper_case, [:string]
    def to_lower_case(string)
      assert_type string, :String, :string
      Sass::Script::Value::String.new(string.value.downcase, string.type)
    end
    declare :to_lower_case, [:string]
    def type_of(value)
      identifier(value.class.name.gsub(/Sass::Script::Value::/, '').downcase)
    end
    declare :type_of, [:value]
    def feature_exists(feature)
      assert_type feature, :String, :feature
      bool(Sass.has_feature?(feature.value))
    end
    declare :feature_exists, [:feature]
    def unit(number)
      assert_type number, :Number, :number
      quoted_string(number.unit_str)
    end
    declare :unit, [:number]
    def unitless(number)
      assert_type number, :Number, :number
      bool(number.unitless?)
    end
    declare :unitless, [:number]
    def comparable(number1, number2)
      assert_type number1, :Number, :number1
      assert_type number2, :Number, :number2
      bool(number1.comparable_to?(number2))
    end
    declare :comparable, [:number1, :number2]
    def percentage(number)
      unless number.is_a?(Sass::Script::Value::Number) && number.unitless?
        raise ArgumentError.new("$number: #{number.inspect} is not a unitless number")
      end
      number(number.value * 100, '%')
    end
    declare :percentage, [:number]
    def round(number)
      numeric_transformation(number) {|n| n.round}
    end
    declare :round, [:number]
    def ceil(number)
      numeric_transformation(number) {|n| n.ceil}
    end
    declare :ceil, [:number]
    def floor(number)
      numeric_transformation(number) {|n| n.floor}
    end
    declare :floor, [:number]
    def abs(number)
      numeric_transformation(number) {|n| n.abs}
    end
    declare :abs, [:number]
    def min(*numbers)
      numbers.each {|n| assert_type n, :Number}
      numbers.inject {|min, num| min.lt(num).to_bool ? min : num}
    end
    declare :min, [], :var_args => :true
    def max(*values)
      values.each {|v| assert_type v, :Number}
      values.inject {|max, val| max.gt(val).to_bool ? max : val}
    end
    declare :max, [], :var_args => :true
    def length(list)
      number(list.to_a.size)
    end
    declare :length, [:list]
    def set_nth(list, n, value)
      assert_type n, :Number, :n
      Sass::Script::Value::List.assert_valid_index(list, n)
      index = n.to_i > 0 ? n.to_i - 1 : n.to_i
      new_list = list.to_a.dup
      new_list[index] = value
      Sass::Script::Value::List.new(new_list, list.separator)
    end
    declare :set_nth, [:list, :n, :value]
    def nth(list, n)
      assert_type n, :Number, :n
      Sass::Script::Value::List.assert_valid_index(list, n)
      index = n.to_i > 0 ? n.to_i - 1 : n.to_i
      list.to_a[index]
    end
    declare :nth, [:list, :n]
    def join(list1, list2, separator = identifier("auto"))
      assert_type separator, :String, :separator
      unless %w[auto space comma].include?(separator.value)
        raise ArgumentError.new("Separator name must be space, comma, or auto")
      end
      sep = if separator.value == 'auto'
              list1.separator || list2.separator || :space
            else
              separator.value.to_sym
            end
      list(list1.to_a + list2.to_a, sep)
    end
    declare :join, [:list1, :list2]
    declare :join, [:list1, :list2, :separator]
    def append(list, val, separator = identifier("auto"))
      assert_type separator, :String, :separator
      unless %w[auto space comma].include?(separator.value)
        raise ArgumentError.new("Separator name must be space, comma, or auto")
      end
      sep = if separator.value == 'auto'
              list.separator || :space
            else
              separator.value.to_sym
            end
      list(list.to_a + [val], sep)
    end
    declare :append, [:list, :val]
    declare :append, [:list, :val, :separator]
    def zip(*lists)
      length = nil
      values = []
      lists.each do |list|
        array = list.to_a
        values << array.dup
        length = length.nil? ? array.length : [length, array.length].min
      end
      values.each do |value|
        value.slice!(length)
      end
      new_list_value = values.first.zip(*values[1..-1])
      list(new_list_value.map {|list| list(list, :space)}, :comma)
    end
    declare :zip, [], :var_args => true
    def index(list, value)
      index = list.to_a.index {|e| e.eq(value).to_bool}
      index ? number(index + 1) : null
    end
    declare :index, [:list, :value]
    def list_separator(list)
      identifier((list.separator || :space).to_s)
    end
    declare :separator, [:list]
    def map_get(map, key)
      assert_type map, :Map, :map
      map.to_h[key] || null
    end
    declare :map_get, [:map, :key]
    def map_merge(map1, map2)
      assert_type map1, :Map, :map1
      assert_type map2, :Map, :map2
      map(map1.to_h.merge(map2.to_h))
    end
    declare :map_merge, [:map1, :map2]
    def map_remove(map, *keys)
      assert_type map, :Map, :map
      hash = map.to_h.dup
      hash.delete_if {|key, _| keys.include?(key)}
      map(hash)
    end
    declare :map_remove, [:map, :key], :var_args => true
    def map_keys(map)
      assert_type map, :Map, :map
      list(map.to_h.keys, :comma)
    end
    declare :map_keys, [:map]
    def map_values(map)
      assert_type map, :Map, :map
      list(map.to_h.values, :comma)
    end
    declare :map_values, [:map]
    def map_has_key(map, key)
      assert_type map, :Map, :map
      bool(map.to_h.has_key?(key))
    end
    declare :map_has_key, [:map, :key]
    def keywords(args)
      assert_type args, :ArgList, :args
      map(Sass::Util.map_keys(args.keywords.as_stored) {|k| Sass::Script::Value::String.new(k)})
    end
    declare :keywords, [:args]
    def if(condition, if_true, if_false)
      if condition.to_bool
        perform(if_true)
      else
        perform(if_false)
      end
    end
    declare :if, [:condition, :"&if_true", :"&if_false"]
    def unique_id
      generator = Sass::Script::Functions.random_number_generator
      Thread.current[:sass_last_unique_id] ||= generator.rand(36**8)
      value = (Thread.current[:sass_last_unique_id] += (generator.rand(10) + 1))
      identifier("u" + value.to_s(36).rjust(8, '0'))
    end
    declare :unique_id, []
    def call(name, *args)
      assert_type name, :String, :name
      kwargs = args.last.is_a?(Hash) ? args.pop : {}
      funcall = Sass::Script::Tree::Funcall.new(
        name.value,
        args.map {|a| Sass::Script::Tree::Literal.new(a)},
        Sass::Util.map_vals(kwargs) {|v| Sass::Script::Tree::Literal.new(v)},
        nil,
        nil)
      funcall.options = options
      perform(funcall)
    end
    declare :call, [:name], :var_args => true, :var_kwargs => true
    def counter(*args)
      identifier("counter(#{args.map {|a| a.to_s(options)}.join(',')})")
    end
    declare :counter, [], :var_args => true
    def counters(*args)
      identifier("counters(#{args.map {|a| a.to_s(options)}.join(',')})")
    end
    declare :counters, [], :var_args => true
    def variable_exists(name)
      assert_type name, :String, :name
      bool(environment.caller.var(name.value))
    end
    declare :variable_exists, [:name]
    def global_variable_exists(name)
      assert_type name, :String, :name
      bool(environment.global_env.var(name.value))
    end
    declare :global_variable_exists, [:name]
    def function_exists(name)
      assert_type name, :String, :name
      exists = Sass::Script::Functions.callable?(name.value.tr("-", "_"))
      exists ||= environment.function(name.value)
      bool(exists)
    end
    declare :function_exists, [:name]
    def mixin_exists(name)
      assert_type name, :String, :name
      bool(environment.mixin(name.value))
    end
    declare :mixin_exists, [:name]
    def inspect(value)
      unquoted_string(value.to_sass)
    end
    declare :inspect, [:value]
    def random(limit = nil)
      generator = Sass::Script::Functions.random_number_generator
      if limit
        assert_integer limit, "limit"
        if limit.to_i < 1
          raise ArgumentError.new("$limit #{limit} must be greater than or equal to 1")
        end
        number(1 + generator.rand(limit.to_i))
      else
        number(generator.rand)
      end
    end
    declare :random, []
    declare :random, [:limit]
    def selector_parse(selector)
      parse_selector(selector, :selector).to_sass_script
    end
    declare :selector_parse, [:selector]
    def selector_nest(*selectors)
      if selectors.empty?
        raise ArgumentError.new("$selectors: At least one selector must be passed")
      end
      parsed = [parse_selector(selectors.first, :selectors)]
      parsed += selectors[1..-1].map {|sel| parse_selector(sel, :selectors, !!:parse_parent_ref)}
      parsed.inject {|result, child| child.resolve_parent_refs(result)}.to_sass_script
    end
    declare :selector_nest, [], :var_args => true
    def selector_append(*selectors)
      if selectors.empty?
        raise ArgumentError.new("$selectors: At least one selector must be passed")
      end
      selectors.map {|sel| parse_selector(sel, :selectors)}.inject do |parent, child|
        child.members.each do |seq|
          sseq = seq.members.first
          unless sseq.is_a?(Sass::Selector::SimpleSequence)
            raise ArgumentError.new("Can't append \"#{seq}\" to \"#{parent}\"")
          end
          base = sseq.base
          case base
          when Sass::Selector::Universal
            raise ArgumentError.new("Can't append \"#{seq}\" to \"#{parent}\"")
          when Sass::Selector::Element
            unless base.namespace.nil?
              raise ArgumentError.new("Can't append \"#{seq}\" to \"#{parent}\"")
            end
            sseq.members[0] = Sass::Selector::Parent.new(base.name)
          else
            sseq.members.unshift Sass::Selector::Parent.new
          end
        end
        child.resolve_parent_refs(parent)
      end.to_sass_script
    end
    declare :selector_append, [], :var_args => true
    def selector_extend(selector, extendee, extender)
      selector = parse_selector(selector, :selector)
      extendee = parse_selector(extendee, :extendee)
      extender = parse_selector(extender, :extender)
      extends = Sass::Util::SubsetMap.new
      begin
        extender.populate_extends(extends, extendee)
        selector.do_extend(extends).to_sass_script
      rescue Sass::SyntaxError => e
        raise ArgumentError.new(e.to_s)
      end
    end
    declare :selector_extend, [:selector, :extendee, :extender]
    def selector_replace(selector, original, replacement)
      selector = parse_selector(selector, :selector)
      original = parse_selector(original, :original)
      replacement = parse_selector(replacement, :replacement)
      extends = Sass::Util::SubsetMap.new
      begin
        replacement.populate_extends(extends, original)
        selector.do_extend(extends, [], !!:replace).to_sass_script
      rescue Sass::SyntaxError => e
        raise ArgumentError.new(e.to_s)
      end
    end
    declare :selector_replace, [:selector, :original, :replacement]
    def selector_unify(selector1, selector2)
      selector1 = parse_selector(selector1, :selector1)
      selector2 = parse_selector(selector2, :selector2)
      return null unless (unified = selector1.unify(selector2))
      unified.to_sass_script
    end
    declare :selector_unify, [:selector1, :selector2]
    def simple_selectors(selector)
      selector = parse_compound_selector(selector, :selector)
      list(selector.members.map {|simple| unquoted_string(simple.to_s)}, :comma)
    end
    declare :simple_selectors, [:selector]
    def is_superselector(sup, sub)
      sup = parse_selector(sup, :super)
      sub = parse_selector(sub, :sub)
      bool(sup.superselector?(sub))
    end
    declare :is_superselector, [:super, :sub]
    private
    def numeric_transformation(value)
      assert_type value, :Number, :value
      Sass::Script::Value::Number.new(
        yield(value.value), value.numerator_units, value.denominator_units)
    end
    def _adjust(color, amount, attr, range, op, units = "")
      assert_type color, :Color, :color
      assert_type amount, :Number, :amount
      Sass::Util.check_range('Amount', range, amount, units)
      color.with(attr => color.send(attr).send(op, amount.value))
    end
    def check_alpha_unit(alpha, function)
      return if alpha.unitless?
      if alpha.is_unit?("%")
        Sass::Util.sass_warn(<<WARNING)
DEPRECATION WARNING: Passing a percentage as the alpha value to #{function}() will be
interpreted differently in future versions of Sass. For now, use #{alpha.value} instead.
WARNING
      else
        Sass::Util.sass_warn(<<WARNING)
DEPRECATION WARNING: Passing a number with units as the alpha value to #{function}() is
deprecated and will be an error in future versions of Sass. Use #{alpha.value} instead.
WARNING
      end
    end
  end
end
module Sass
  module Script
    class Lexer
      include Sass::SCSS::RX
      Token = Struct.new(:type, :value, :source_range, :pos)
      def line
        return @line unless @tok
        @tok.source_range.start_pos.line
      end
      def offset
        return @offset unless @tok
        @tok.source_range.start_pos.offset
      end
      OPERATORS = {
        '+' => :plus,
        '-' => :minus,
        '*' => :times,
        '/' => :div,
        '%' => :mod,
        '=' => :single_eq,
        ':' => :colon,
        '(' => :lparen,
        ')' => :rparen,
        ',' => :comma,
        'and' => :and,
        'or' => :or,
        'not' => :not,
        '==' => :eq,
        '!=' => :neq,
        '>=' => :gte,
        '<=' => :lte,
        '>' => :gt,
        '<' => :lt,
        '#{' => :begin_interpolation,
        '}' => :end_interpolation,
        ';' => :semicolon,
        '{' => :lcurly,
        '...' => :splat,
      }
      OPERATORS_REVERSE = Sass::Util.map_hash(OPERATORS) {|k, v| [v, k]}
      TOKEN_NAMES = Sass::Util.map_hash(OPERATORS_REVERSE) {|k, v| [k, v.inspect]}.merge(
          :const => "variable (e.g. $foo)",
          :ident => "identifier (e.g. middle)")
      OP_NAMES = OPERATORS.keys.sort_by {|o| -o.size}
      IDENT_OP_NAMES = OP_NAMES.select {|k, v| k =~ /^\w+/}
      PARSEABLE_NUMBER = /(?:(\d*\.\d+)|(\d+))(?:[eE]([+-]?\d+))?(#{UNIT})?/
      REGULAR_EXPRESSIONS = {
        :whitespace => /\s+/,
        :comment => COMMENT,
        :single_line_comment => SINGLE_LINE_COMMENT,
        :variable => /(\$)(#{IDENT})/,
        :ident => /(#{IDENT})(\()?/,
        :number => PARSEABLE_NUMBER,
        :unary_minus_number => /-#{PARSEABLE_NUMBER}/,
        :color => HEXCOLOR,
        :id => /##{IDENT}/,
        :selector => /&/,
        :ident_op => /(#{Regexp.union(*IDENT_OP_NAMES.map do |s|
          Regexp.new(Regexp.escape(s) + "(?!#{NMCHAR}|\Z)")
        end)})/,
        :op => /(#{Regexp.union(*OP_NAMES)})/,
      }
      class << self
        private
        def string_re(open, close)
          /#{open}((?:\\.|\#(?!\{)|[^#{close}\\#])*)(#{close}|#\{)/m
        end
      end
      STRING_REGULAR_EXPRESSIONS = {
        :double => {
          false => string_re('"', '"'),
          true => string_re('', '"')
        },
        :single => {
          false => string_re("'", "'"),
          true => string_re('', "'")
        },
        :uri => {
          false => /url\(#{W}(#{URLCHAR}*?)(#{W}\)|#\{)/,
          true => /(#{URLCHAR}*?)(#{W}\)|#\{)/
        },
        :url_prefix => {
          false => /url-prefix\(#{W}(#{URLCHAR}*?)(#{W}\)|#\{)/,
          true => /(#{URLCHAR}*?)(#{W}\)|#\{)/
        },
        :domain => {
          false => /domain\(#{W}(#{URLCHAR}*?)(#{W}\)|#\{)/,
          true => /(#{URLCHAR}*?)(#{W}\)|#\{)/
        }
      }
      def initialize(str, line, offset, options)
        @scanner = str.is_a?(StringScanner) ? str : Sass::Util::MultibyteStringScanner.new(str)
        @line = line
        @offset = offset
        @options = options
        @interpolation_stack = []
        @prev = nil
      end
      def next
        @tok ||= read_token
        @tok, tok = nil, @tok
        @prev = tok
        tok
      end
      def whitespace?(tok = @tok)
        if tok
          @scanner.string[0...tok.pos] =~ /\s\Z/
        else
          @scanner.string[@scanner.pos, 1] =~ /^\s/ ||
            @scanner.string[@scanner.pos - 1, 1] =~ /\s\Z/
        end
      end
      def peek
        @tok ||= read_token
      end
      def unpeek!
        if @tok
          @scanner.pos = @tok.pos
          @line = @tok.source_range.start_pos.line
          @offset = @tok.source_range.start_pos.offset
        end
      end
      def done?
        return if @next_tok
        whitespace unless after_interpolation? && !@interpolation_stack.empty?
        @scanner.eos? && @tok.nil?
      end
      def after_interpolation?
        @prev && @prev.type == :end_interpolation
      end
      def expected!(name)
        unpeek!
        Sass::SCSS::Parser.expected(@scanner, name, @line)
      end
      def str
        old_pos = @tok ? @tok.pos : @scanner.pos
        yield
        new_pos = @tok ? @tok.pos : @scanner.pos
        @scanner.string[old_pos...new_pos]
      end
      private
      def read_token
        if (tok = @next_tok)
          @next_tok = nil
          return tok
        end
        return if done?
        start_pos = source_position
        value = token
        return unless value
        type, val = value
        Token.new(type, val, range(start_pos), @scanner.pos - @scanner.matched_size)
      end
      def whitespace
        nil while scan(REGULAR_EXPRESSIONS[:whitespace]) ||
          scan(REGULAR_EXPRESSIONS[:comment]) ||
          scan(REGULAR_EXPRESSIONS[:single_line_comment])
      end
      def token
        if after_interpolation? && (interp = @interpolation_stack.pop)
          interp_type, interp_value = interp
          if interp_type == :special_fun
            return special_fun_body(interp_value)
          else
            raise "[BUG]: Unknown interp_type #{interp_type}" unless interp_type == :string
            return string(interp_value, true)
          end
        end
        variable || string(:double, false) || string(:single, false) || number || id || color ||
          selector || string(:uri, false) || raw(UNICODERANGE) || special_fun || special_val ||
          ident_op || ident || op
      end
      def variable
        _variable(REGULAR_EXPRESSIONS[:variable])
      end
      def _variable(rx)
        return unless scan(rx)
        [:const, @scanner[2]]
      end
      def ident
        return unless scan(REGULAR_EXPRESSIONS[:ident])
        [@scanner[2] ? :funcall : :ident, @scanner[1]]
      end
      def string(re, open)
        line, offset = @line, @offset
        return unless scan(STRING_REGULAR_EXPRESSIONS[re][open])
        if @scanner[0] =~ /([^\\]|^)\n/
          filename = @options[:filename]
          Sass::Util.sass_warn <<MESSAGE
DEPRECATION WARNING on line #{line}, column #{offset}#{" of #{filename}" if filename}:
Unescaped multiline strings are deprecated and will be removed in a future version of Sass.
To include a newline in a string, use "\\a" or "\\a " as in CSS.
MESSAGE
        end
        if @scanner[2] == '#{' # '
          @interpolation_stack << [:string, re]
          start_pos = Sass::Source::Position.new(@line, @offset - 2)
          @next_tok = Token.new(:string_interpolation, range(start_pos), @scanner.pos - 2)
        end
        str =
          if re == :uri
            url = "#{'url(' unless open}#{@scanner[1]}#{')' unless @scanner[2] == '#{'}"
            Script::Value::String.new(url)
          else
            Script::Value::String.new(Sass::Script::Value::String.value(@scanner[1]), :string)
          end
        [:string, str]
      end
      def number
        if @scanner.peek(1) == '-'
          return if @scanner.pos == 0
          unary_minus_allowed =
            case @scanner.string[@scanner.pos - 1, 1]
            when /\s/; true
            when '/'; @scanner.pos != 1 && @scanner.string[@scanner.pos - 2, 1] == '*'
            else; false
            end
          return unless unary_minus_allowed
          return unless scan(REGULAR_EXPRESSIONS[:unary_minus_number])
          minus = true
        else
          return unless scan(REGULAR_EXPRESSIONS[:number])
          minus = false
        end
        value = (@scanner[1] ? @scanner[1].to_f : @scanner[2].to_i) * (minus ? -1 : 1)
        value *= 10**@scanner[3].to_i if @scanner[3]
        script_number = Script::Value::Number.new(value, Array(@scanner[4]))
        [:number, script_number]
      end
      def id
        return unless scan(REGULAR_EXPRESSIONS[:id])
        if @scanner[0] =~ /^\#[0-9a-fA-F]+$/ && (@scanner[0].length == 4 || @scanner[0].length == 7)
          return [:color, Script::Value::Color.from_hex(@scanner[0])]
        end
        [:ident, @scanner[0]]
      end
      def color
        return unless @scanner.match?(REGULAR_EXPRESSIONS[:color])
        return unless @scanner[0].length == 4 || @scanner[0].length == 7
        script_color = Script::Value::Color.from_hex(scan(REGULAR_EXPRESSIONS[:color]))
        [:color, script_color]
      end
      def selector
        start_pos = source_position
        return unless scan(REGULAR_EXPRESSIONS[:selector])
        script_selector = Script::Tree::Selector.new
        script_selector.source_range = range(start_pos)
        [:selector, script_selector]
      end
      def special_fun
        prefix = scan(/((-[\w-]+-)?(calc|element)|expression|progid:[a-z\.]*)\(/i)
        return unless prefix
        special_fun_body(1, prefix)
      end
      def special_fun_body(parens, prefix = nil)
        str = prefix || ''
        while (scanned = scan(/.*?([()]|\#\{)/m))
          str << scanned
          if scanned[-1] == ?(
            parens += 1
            next
          elsif scanned[-1] == ?)
            parens -= 1
            next unless parens == 0
          else
            raise "[BUG] Unreachable" unless @scanner[1] == '#{' # '
            str.slice!(-2..-1)
            @interpolation_stack << [:special_fun, parens]
            start_pos = Sass::Source::Position.new(@line, @offset - 2)
            @next_tok = Token.new(:string_interpolation, range(start_pos), @scanner.pos - 2)
          end
          return [:special_fun, Sass::Script::Value::String.new(str)]
        end
        scan(/.*/)
        expected!('")"')
      end
      def special_val
        return unless scan(/!important/i)
        [:string, Script::Value::String.new("!important")]
      end
      def ident_op
        op = scan(REGULAR_EXPRESSIONS[:ident_op])
        return unless op
        [OPERATORS[op]]
      end
      def op
        op = scan(REGULAR_EXPRESSIONS[:op])
        return unless op
        name = OPERATORS[op]
        @interpolation_stack << nil if name == :begin_interpolation
        [name]
      end
      def raw(rx)
        val = scan(rx)
        return unless val
        [:raw, val]
      end
      def scan(re)
        str = @scanner.scan(re)
        return unless str
        c = str.count("\n")
        @line += c
        @offset = (c == 0 ? @offset + str.size : str.size - str.rindex("\n"))
        str
      end
      def range(start_pos, end_pos = source_position)
        Sass::Source::Range.new(start_pos, end_pos, @options[:filename], @options[:importer])
      end
      def source_position
        Sass::Source::Position.new(@line, @offset)
      end
    end
  end
end
module Sass
  module Script
    class Parser
      def line
        @lexer.line
      end
      def offset
        @lexer.offset
      end
      def initialize(str, line, offset, options = {})
        @options = options
        @lexer = lexer_class.new(str, line, offset, options)
      end
      def parse_interpolated(warn_for_color = false)
        start_pos = Sass::Source::Position.new(line, offset - 2)
        expr = assert_expr :expr
        assert_tok :end_interpolation
        expr = Sass::Script::Tree::Interpolation.new(
          nil, expr, nil, !:wb, !:wa, !:originally_text, warn_for_color)
        expr.options = @options
        node(expr, start_pos)
      rescue Sass::SyntaxError => e
        e.modify_backtrace :line => @lexer.line, :filename => @options[:filename]
        raise e
      end
      def parse
        expr = assert_expr :expr
        assert_done
        expr.options = @options
        expr
      rescue Sass::SyntaxError => e
        e.modify_backtrace :line => @lexer.line, :filename => @options[:filename]
        raise e
      end
      def parse_until(tokens)
        @stop_at = tokens
        expr = assert_expr :expr
        assert_done
        expr.options = @options
        expr
      rescue Sass::SyntaxError => e
        e.modify_backtrace :line => @lexer.line, :filename => @options[:filename]
        raise e
      end
      def parse_mixin_include_arglist
        args, keywords = [], {}
        if try_tok(:lparen)
          args, keywords, splat, kwarg_splat = mixin_arglist
          assert_tok(:rparen)
        end
        assert_done
        args.each {|a| a.options = @options}
        keywords.each {|k, v| v.options = @options}
        splat.options = @options if splat
        kwarg_splat.options = @options if kwarg_splat
        return args, keywords, splat, kwarg_splat
      rescue Sass::SyntaxError => e
        e.modify_backtrace :line => @lexer.line, :filename => @options[:filename]
        raise e
      end
      def parse_mixin_definition_arglist
        args, splat = defn_arglist!(false)
        assert_done
        args.each do |k, v|
          k.options = @options
          v.options = @options if v
        end
        splat.options = @options if splat
        return args, splat
      rescue Sass::SyntaxError => e
        e.modify_backtrace :line => @lexer.line, :filename => @options[:filename]
        raise e
      end
      def parse_function_definition_arglist
        args, splat = defn_arglist!(true)
        assert_done
        args.each do |k, v|
          k.options = @options
          v.options = @options if v
        end
        splat.options = @options if splat
        return args, splat
      rescue Sass::SyntaxError => e
        e.modify_backtrace :line => @lexer.line, :filename => @options[:filename]
        raise e
      end
      def parse_string
        unless (peek = @lexer.peek) &&
            (peek.type == :string ||
            (peek.type == :funcall && peek.value.downcase == 'url'))
          lexer.expected!("string")
        end
        expr = assert_expr :funcall
        expr.options = @options
        @lexer.unpeek!
        expr
      rescue Sass::SyntaxError => e
        e.modify_backtrace :line => @lexer.line, :filename => @options[:filename]
        raise e
      end
      def self.parse(*args)
        new(*args).parse
      end
      PRECEDENCE = [
        :comma, :single_eq, :space, :or, :and,
        [:eq, :neq],
        [:gt, :gte, :lt, :lte],
        [:plus, :minus],
        [:times, :div, :mod],
      ]
      ASSOCIATIVE = [:plus, :times]
      class << self
        def precedence_of(op)
          PRECEDENCE.each_with_index do |e, i|
            return i if Array(e).include?(op)
          end
          raise "[BUG] Unknown operator #{op.inspect}"
        end
        def associative?(op)
          ASSOCIATIVE.include?(op)
        end
        private
        def production(name, sub, *ops)
          class_eval <<RUBY, __FILE__, __LINE__ + 1
            def #{name}
              interp = try_ops_after_interp(#{ops.inspect}, #{name.inspect})
              return interp if interp
              return unless e = #{sub}
              while tok = try_toks(#{ops.map {|o| o.inspect}.join(', ')})
                if interp = try_op_before_interp(tok, e)
                  other_interp = try_ops_after_interp(#{ops.inspect}, #{name.inspect}, interp)
                  return interp unless other_interp
                  return other_interp
                end
                e = node(Tree::Operation.new(e, assert_expr(#{sub.inspect}), tok.type),
                         e.source_range.start_pos)
              end
              e
            end
RUBY
        end
        def unary(op, sub)
          class_eval <<RUBY, __FILE__, __LINE__ + 1
            def unary_#{op}
              return #{sub} unless tok = try_tok(:#{op})
              interp = try_op_before_interp(tok)
              return interp if interp
              start_pos = source_position
              node(Tree::UnaryOperation.new(assert_expr(:unary_#{op}), :#{op}), start_pos)
            end
RUBY
        end
      end
      private
      def source_position
        Sass::Source::Position.new(line, offset)
      end
      def range(start_pos, end_pos = source_position)
        Sass::Source::Range.new(start_pos, end_pos, @options[:filename], @options[:importer])
      end
      def lexer_class; Lexer; end
      def map
        start_pos = source_position
        e = interpolation
        return unless e
        return list e, start_pos unless @lexer.peek && @lexer.peek.type == :colon
        pair = map_pair(e)
        map = node(Sass::Script::Tree::MapLiteral.new([pair]), start_pos)
        while try_tok(:comma)
          pair = map_pair
          return map unless pair
          map.pairs << pair
        end
        map
      end
      def map_pair(key = nil)
        return unless key ||= interpolation
        assert_tok :colon
        return key, assert_expr(:interpolation)
      end
      def expr
        start_pos = source_position
        e = interpolation
        return unless e
        list e, start_pos
      end
      def list(first, start_pos)
        return first unless @lexer.peek && @lexer.peek.type == :comma
        list = node(Sass::Script::Tree::ListLiteral.new([first], :comma), start_pos)
        while (tok = try_tok(:comma))
          element_before_interp = list.elements.length == 1 ? list.elements.first : list
          if (interp = try_op_before_interp(tok, element_before_interp))
            other_interp = try_ops_after_interp([:comma], :expr, interp)
            return interp unless other_interp
            return other_interp
          end
          return list unless (e = interpolation)
          list.elements << e
        end
        list
      end
      production :equals, :interpolation, :single_eq
      def try_op_before_interp(op, prev = nil)
        return unless @lexer.peek && @lexer.peek.type == :begin_interpolation
        wb = @lexer.whitespace?(op)
        str = literal_node(Script::Value::String.new(Lexer::OPERATORS_REVERSE[op.type]),
                           op.source_range)
        interp = node(
          Script::Tree::Interpolation.new(prev, str, nil, wb, !:wa, :originally_text),
          (prev || str).source_range.start_pos)
        interpolation(interp)
      end
      def try_ops_after_interp(ops, name, prev = nil)
        return unless @lexer.after_interpolation?
        op = try_toks(*ops)
        return unless op
        interp = try_op_before_interp(op, prev)
        return interp if interp
        wa = @lexer.whitespace?
        str = literal_node(Script::Value::String.new(Lexer::OPERATORS_REVERSE[op.type]),
                           op.source_range)
        str.line = @lexer.line
        interp = node(
          Script::Tree::Interpolation.new(prev, str, assert_expr(name), !:wb, wa, :originally_text),
          (prev || str).source_range.start_pos)
        interp
      end
      def interpolation(first = space)
        e = first
        while (interp = try_tok(:begin_interpolation))
          wb = @lexer.whitespace?(interp)
          mid = assert_expr :expr
          assert_tok :end_interpolation
          wa = @lexer.whitespace?
          e = node(
            Script::Tree::Interpolation.new(e, mid, space, wb, wa),
            (e || mid).source_range.start_pos)
        end
        e
      end
      def space
        start_pos = source_position
        e = or_expr
        return unless e
        arr = [e]
        while (e = or_expr)
          arr << e
        end
        if arr.size == 1
          arr.first
        else
          node(Sass::Script::Tree::ListLiteral.new(arr, :space), start_pos)
        end
      end
      production :or_expr, :and_expr, :or
      production :and_expr, :eq_or_neq, :and
      production :eq_or_neq, :relational, :eq, :neq
      production :relational, :plus_or_minus, :gt, :gte, :lt, :lte
      production :plus_or_minus, :times_div_or_mod, :plus, :minus
      production :times_div_or_mod, :unary_plus, :times, :div, :mod
      unary :plus, :unary_minus
      unary :minus, :unary_div
      unary :div, :unary_not # For strings, so /foo/bar works
      unary :not, :ident
      def ident
        return funcall unless @lexer.peek && @lexer.peek.type == :ident
        return if @stop_at && @stop_at.include?(@lexer.peek.value)
        name = @lexer.next
        if (color = Sass::Script::Value::Color::COLOR_NAMES[name.value.downcase])
          literal_node(Sass::Script::Value::Color.new(color, name.value), name.source_range)
        elsif name.value == "true"
          literal_node(Sass::Script::Value::Bool.new(true), name.source_range)
        elsif name.value == "false"
          literal_node(Sass::Script::Value::Bool.new(false), name.source_range)
        elsif name.value == "null"
          literal_node(Sass::Script::Value::Null.new, name.source_range)
        else
          literal_node(Sass::Script::Value::String.new(name.value, :identifier), name.source_range)
        end
      end
      def funcall
        tok = try_tok(:funcall)
        return raw unless tok
        args, keywords, splat, kwarg_splat = fn_arglist
        assert_tok(:rparen)
        node(Script::Tree::Funcall.new(tok.value, args, keywords, splat, kwarg_splat),
          tok.source_range.start_pos, source_position)
      end
      def defn_arglist!(must_have_parens)
        if must_have_parens
          assert_tok(:lparen)
        else
          return [], nil unless try_tok(:lparen)
        end
        return [], nil if try_tok(:rparen)
        res = []
        splat = nil
        must_have_default = false
        loop do
          c = assert_tok(:const)
          var = node(Script::Tree::Variable.new(c.value), c.source_range)
          if try_tok(:colon)
            val = assert_expr(:space)
            must_have_default = true
          elsif try_tok(:splat)
            splat = var
            break
          elsif must_have_default
            raise SyntaxError.new(
              "Required argument #{var.inspect} must come before any optional arguments.")
          end
          res << [var, val]
          break unless try_tok(:comma)
        end
        assert_tok(:rparen)
        return res, splat
      end
      def fn_arglist
        arglist(:equals, "function argument")
      end
      def mixin_arglist
        arglist(:interpolation, "mixin argument")
      end
      def arglist(subexpr, description)
        args = []
        keywords = Sass::Util::NormalizedMap.new
        e = send(subexpr)
        return [args, keywords] unless e
        splat = nil
        loop do
          if @lexer.peek && @lexer.peek.type == :colon
            name = e
            @lexer.expected!("comma") unless name.is_a?(Tree::Variable)
            assert_tok(:colon)
            value = assert_expr(subexpr, description)
            if keywords[name.name]
              raise SyntaxError.new("Keyword argument \"#{name.to_sass}\" passed more than once")
            end
            keywords[name.name] = value
          else
            if try_tok(:splat)
              return args, keywords, splat, e if splat
              splat, e = e, nil
            elsif splat
              raise SyntaxError.new("Only keyword arguments may follow variable arguments (...).")
            elsif !keywords.empty?
              raise SyntaxError.new("Positional arguments must come before keyword arguments.")
            end
            args << e if e
          end
          return args, keywords, splat unless try_tok(:comma)
          e = assert_expr(subexpr, description)
        end
      end
      def raw
        tok = try_tok(:raw)
        return special_fun unless tok
        literal_node(Script::Value::String.new(tok.value), tok.source_range)
      end
      def special_fun
        first = try_tok(:special_fun)
        return paren unless first
        str = literal_node(first.value, first.source_range)
        return str unless try_tok(:string_interpolation)
        mid = assert_expr :expr
        assert_tok :end_interpolation
        last = assert_expr(:special_fun)
        node(Tree::Interpolation.new(str, mid, last, false, false),
            first.source_range.start_pos)
      end
      def paren
        return variable unless try_tok(:lparen)
        was_in_parens = @in_parens
        @in_parens = true
        start_pos = source_position
        e = map
        end_pos = source_position
        assert_tok(:rparen)
        return e || node(Sass::Script::Tree::ListLiteral.new([], nil), start_pos, end_pos)
      ensure
        @in_parens = was_in_parens
      end
      def variable
        start_pos = source_position
        c = try_tok(:const)
        return string unless c
        node(Tree::Variable.new(*c.value), start_pos)
      end
      def string
        first = try_tok(:string)
        return number unless first
        str = literal_node(first.value, first.source_range)
        return str unless try_tok(:string_interpolation)
        mid = assert_expr :expr
        assert_tok :end_interpolation
        last = assert_expr(:string)
        node(Tree::StringInterpolation.new(str, mid, last), first.source_range.start_pos)
      end
      def number
        tok = try_tok(:number)
        return selector unless tok
        num = tok.value
        num.original = num.to_s unless @in_parens
        literal_node(num, tok.source_range.start_pos)
      end
      def selector
        tok = try_tok(:selector)
        return literal unless tok
        node(tok.value, tok.source_range.start_pos)
      end
      def literal
        t = try_tok(:color)
        return literal_node(t.value, t.source_range) if t
      end
      EXPR_NAMES = {
        :string => "string",
        :default => "expression (e.g. 1px, bold)",
        :mixin_arglist => "mixin argument",
        :fn_arglist => "function argument",
        :splat => "...",
        :special_fun => '")"',
      }
      def assert_expr(name, expected = nil)
        e = send(name)
        return e if e
        @lexer.expected!(expected || EXPR_NAMES[name] || EXPR_NAMES[:default])
      end
      def assert_tok(name)
        t = try_tok(name)
        return t if t
        @lexer.expected!(Lexer::TOKEN_NAMES[name] || name.to_s)
      end
      def assert_toks(*names)
        t = try_toks(*names)
        return t if t
        @lexer.expected!(names.map {|tok| Lexer::TOKEN_NAMES[tok] || tok}.join(" or "))
      end
      def try_tok(name)
        peeked = @lexer.peek
        peeked && name == peeked.type && @lexer.next
      end
      def try_toks(*names)
        peeked = @lexer.peek
        peeked && names.include?(peeked.type) && @lexer.next
      end
      def assert_done
        return if @lexer.done?
        @lexer.expected!(EXPR_NAMES[:default])
      end
      def literal_node(value, source_range_or_start_pos, end_pos = source_position)
        node(Sass::Script::Tree::Literal.new(value), source_range_or_start_pos, end_pos)
      end
      def node(node, source_range_or_start_pos, end_pos = source_position)
        source_range =
          if source_range_or_start_pos.is_a?(Sass::Source::Range)
            source_range_or_start_pos
          else
            range(source_range_or_start_pos, end_pos)
          end
        node.line = source_range.start_pos.line
        node.source_range = source_range
        node.filename = @options[:filename]
        node
      end
    end
  end
end
module Sass::Script::Tree
end
module Sass::Script::Tree
  class Node
    attr_reader :options
    attr_accessor :line
    attr_accessor :source_range
    attr_accessor :filename
    def options=(options)
      @options = options
      children.each do |c|
        if c.is_a? Hash
          c.values.each {|v| v.options = options}
        else
          c.options = options
        end
      end
    end
    def perform(environment)
      _perform(environment)
    rescue Sass::SyntaxError => e
      e.modify_backtrace(:line => line)
      raise e
    end
    def children
      Sass::Util.abstract(self)
    end
    def to_sass(opts = {})
      Sass::Util.abstract(self)
    end
    def deep_copy
      Sass::Util.abstract(self)
    end
    protected
    def dasherize(s, opts)
      if opts[:dasherize]
        s.gsub(/_/, '-')
      else
        s
      end
    end
    def _perform(environment)
      Sass::Util.abstract(self)
    end
    def opts(value)
      value.options = options
      value
    end
  end
end
module Sass::Script::Tree
  class Variable < Node
    attr_reader :name
    attr_reader :underscored_name
    def initialize(name)
      @name = name
      @underscored_name = name.gsub(/-/, "_")
      super()
    end
    def inspect(opts = {})
      "$#{dasherize(name, opts)}"
    end
    alias_method :to_sass, :inspect
    def children
      []
    end
    def deep_copy
      dup
    end
    protected
    def _perform(environment)
      val = environment.var(name)
      raise Sass::SyntaxError.new("Undefined variable: \"$#{name}\".") unless val
      if val.is_a?(Sass::Script::Value::Number) && val.original
        val = val.dup
        val.original = nil
      end
      val
    end
  end
end
module Sass::Script::Tree
  class Funcall < Node
    attr_reader :name
    attr_reader :args
    attr_reader :keywords
    attr_accessor :splat
    attr_accessor :kwarg_splat
    def initialize(name, args, keywords, splat, kwarg_splat)
      @name = name
      @args = args
      @keywords = keywords
      @splat = splat
      @kwarg_splat = kwarg_splat
      super()
    end
    def inspect
      args = @args.map {|a| a.inspect}.join(', ')
      keywords = Sass::Util.hash_to_a(@keywords.as_stored).
          map {|k, v| "$#{k}: #{v.inspect}"}.join(', ')
      if self.splat
        splat = args.empty? && keywords.empty? ? "" : ", "
        splat = "#{splat}#{self.splat.inspect}..."
        splat = "#{splat}, #{kwarg_splat.inspect}..." if kwarg_splat
      end
      "#{name}(#{args}#{', ' unless args.empty? || keywords.empty?}#{keywords}#{splat})"
    end
    def to_sass(opts = {})
      arg_to_sass = lambda do |arg|
        sass = arg.to_sass(opts)
        sass = "(#{sass})" if arg.is_a?(Sass::Script::Tree::ListLiteral) && arg.separator == :comma
        sass
      end
      args = @args.map(&arg_to_sass)
      keywords = Sass::Util.hash_to_a(@keywords.as_stored).
        map {|k, v| "$#{dasherize(k, opts)}: #{arg_to_sass[v]}"}
      if self.splat
        splat = "#{arg_to_sass[self.splat]}..."
        kwarg_splat = "#{arg_to_sass[self.kwarg_splat]}..." if self.kwarg_splat
      end
      arglist = [args, splat, keywords, kwarg_splat].flatten.compact.join(', ')
      "#{dasherize(name, opts)}(#{arglist})"
    end
    def children
      res = @args + @keywords.values
      res << @splat if @splat
      res << @kwarg_splat if @kwarg_splat
      res
    end
    def deep_copy
      node = dup
      node.instance_variable_set('@args', args.map {|a| a.deep_copy})
      copied_keywords = Sass::Util::NormalizedMap.new
      @keywords.as_stored.each {|k, v| copied_keywords[k] = v.deep_copy}
      node.instance_variable_set('@keywords', copied_keywords)
      node
    end
    protected
    def _perform(environment)
      args = Sass::Util.enum_with_index(@args).
        map {|a, i| perform_arg(a, environment, signature && signature.args[i])}
      keywords = Sass::Util.map_hash(@keywords) do |k, v|
        [k, perform_arg(v, environment, k.tr('-', '_'))]
      end
      splat = Sass::Tree::Visitors::Perform.perform_splat(
        @splat, keywords, @kwarg_splat, environment)
      if (fn = environment.function(@name))
        return without_original(perform_sass_fn(fn, args, splat, environment))
      end
      args = construct_ruby_args(ruby_name, args, splat, environment)
      if Sass::Script::Functions.callable?(ruby_name)
        local_environment = Sass::Environment.new(environment.global_env, environment.options)
        local_environment.caller = Sass::ReadOnlyEnvironment.new(environment, environment.options)
        result = opts(Sass::Script::Functions::EvaluationContext.new(
          local_environment).send(ruby_name, *args))
        without_original(result)
      else
        opts(to_literal(args))
      end
    rescue ArgumentError => e
      reformat_argument_error(e)
    end
    def to_literal(args)
      to_value(args)
    end
    def to_value(args)
      Sass::Script::Value::String.new("#{name}(#{args.join(', ')})")
    end
    private
    def ruby_name
      @ruby_name ||= @name.tr('-', '_')
    end
    def perform_arg(argument, environment, name)
      return argument if signature && signature.delayed_args.include?(name)
      argument.perform(environment)
    end
    def signature
      @signature ||= Sass::Script::Functions.signature(name.to_sym, @args.size, @keywords.size)
    end
    def without_original(value)
      return value unless value.is_a?(Sass::Script::Value::Number)
      value = value.dup
      value.original = nil
      value
    end
    def construct_ruby_args(name, args, splat, environment)
      args += splat.to_a if splat
      old_keywords_accessed = splat.keywords_accessed
      keywords = splat.keywords
      splat.keywords_accessed = old_keywords_accessed
      unless (signature = Sass::Script::Functions.signature(name.to_sym, args.size, keywords.size))
        return args if keywords.empty?
        raise Sass::SyntaxError.new("Function #{name} doesn't support keyword arguments")
      end
      if signature.var_kwargs && !signature.var_args && args.size > signature.args.size
        raise Sass::SyntaxError.new(
          "#{args[signature.args.size].inspect} is not a keyword argument for `#{name}'")
      elsif keywords.empty?
        return args
      end
      argnames = signature.args[args.size..-1] || []
      deprecated_argnames = (signature.deprecated && signature.deprecated[args.size..-1]) || []
      args = args + argnames.zip(deprecated_argnames).map do |(argname, deprecated_argname)|
        if keywords.has_key?(argname)
          keywords.delete(argname)
        elsif deprecated_argname && keywords.has_key?(deprecated_argname)
          deprecated_argname = keywords.denormalize(deprecated_argname)
          Sass::Util.sass_warn("DEPRECATION WARNING: The `$#{deprecated_argname}' argument for " +
            "`#{@name}()' has been renamed to `$#{argname}'.")
          keywords.delete(deprecated_argname)
        else
          raise Sass::SyntaxError.new("Function #{name} requires an argument named $#{argname}")
        end
      end
      if keywords.size > 0
        if signature.var_kwargs
          args << keywords.to_hash
        else
          argname = keywords.keys.sort.first
          if signature.args.include?(argname)
            raise Sass::SyntaxError.new(
              "Function #{name} was passed argument $#{argname} both by position and by name")
          else
            raise Sass::SyntaxError.new(
              "Function #{name} doesn't have an argument named $#{argname}")
          end
        end
      end
      args
    end
    def perform_sass_fn(function, args, splat, environment)
      Sass::Tree::Visitors::Perform.perform_arguments(function, args, splat, environment) do |env|
        env.caller = Sass::Environment.new(environment)
        val = catch :_sass_return do
          function.tree.each {|c| Sass::Tree::Visitors::Perform.visit(c, env)}
          raise Sass::SyntaxError.new("Function #{@name} finished without @return")
        end
        val
      end
    end
    def reformat_argument_error(e)
      message = e.message
      if Sass::Util.rbx?
        if e.message =~ /^method '([^']+)': given (\d+), expected (\d+)/
          error_name, given, expected = $1, $2, $3
          raise e if error_name != ruby_name || e.backtrace[0] !~ /:in `_perform'$/
          message = "wrong number of arguments (#{given} for #{expected})"
        end
      elsif Sass::Util.jruby?
        if Sass::Util.jruby1_6?
          should_maybe_raise = e.message =~ /^wrong number of arguments \((\d+) for (\d+)\)/ &&
            e.backtrace[0] !~ /:in `(block in )?#{ruby_name}'$/
        else
          should_maybe_raise =
            e.message =~ /^wrong number of arguments calling `[^`]+` \((\d+) for (\d+)\)/
          given, expected = $1, $2
        end
        if should_maybe_raise
          trace = e.backtrace.dup
          raise e if !Sass::Util.jruby1_6? && trace.shift !~ /:in `__send__'$/
          if !(trace[0] =~ /:in `send'$/ && trace[1] =~ /:in `_perform'$/)
            raise e
          elsif !Sass::Util.jruby1_6?
            message = "wrong number of arguments (#{given} for #{expected})"
          end
        end
      elsif e.message =~ /^wrong number of arguments \(\d+ for \d+\)/ &&
          e.backtrace[0] !~ /:in `(block in )?#{ruby_name}'$/
        raise e
      end
      raise Sass::SyntaxError.new("#{message} for `#{name}'")
    end
  end
end
module Sass::Script::Tree
  class Operation < Node
    attr_reader :operand1
    attr_reader :operand2
    attr_reader :operator
    def initialize(operand1, operand2, operator)
      @operand1 = operand1
      @operand2 = operand2
      @operator = operator
      super()
    end
    def inspect
      "(#{@operator.inspect} #{@operand1.inspect} #{@operand2.inspect})"
    end
    def to_sass(opts = {})
      o1 = operand_to_sass @operand1, :left, opts
      o2 = operand_to_sass @operand2, :right, opts
      sep =
        case @operator
        when :comma; ", "
        when :space; " "
        else; " #{Sass::Script::Lexer::OPERATORS_REVERSE[@operator]} "
        end
      "#{o1}#{sep}#{o2}"
    end
    def children
      [@operand1, @operand2]
    end
    def deep_copy
      node = dup
      node.instance_variable_set('@operand1', @operand1.deep_copy)
      node.instance_variable_set('@operand2', @operand2.deep_copy)
      node
    end
    protected
    def _perform(environment)
      value1 = @operand1.perform(environment)
      if @operator == :and
        return value1.to_bool ? @operand2.perform(environment) : value1
      elsif @operator == :or
        return value1.to_bool ? value1 : @operand2.perform(environment)
      end
      value2 = @operand2.perform(environment)
      if (value1.is_a?(Sass::Script::Value::Null) || value2.is_a?(Sass::Script::Value::Null)) &&
          @operator != :eq && @operator != :neq
        raise Sass::SyntaxError.new(
          "Invalid null operation: \"#{value1.inspect} #{@operator} #{value2.inspect}\".")
      end
      begin
        result = opts(value1.send(@operator, value2))
      rescue NoMethodError => e
        raise e unless e.name.to_s == @operator.to_s
        raise Sass::SyntaxError.new("Undefined operation: \"#{value1} #{@operator} #{value2}\".")
      end
      if @operator == :eq && value1.is_a?(Sass::Script::Value::Number) &&
          value2.is_a?(Sass::Script::Value::Number) && result == Sass::Script::Value::Bool::TRUE &&
          value1.unitless? != value2.unitless?
        Sass::Util.sass_warn <<WARNING
DEPRECATION WARNING on line #{line}#{" of #{filename}" if filename}:
The result of `#{value1} == #{value2}` will be `false` in future releases of Sass.
Unitless numbers will no longer be equal to the same numbers with units.
WARNING
      end
      result
    end
    private
    def operand_to_sass(op, side, opts)
      return "(#{op.to_sass(opts)})" if op.is_a?(Sass::Script::Tree::ListLiteral)
      return op.to_sass(opts) unless op.is_a?(Operation)
      pred = Sass::Script::Parser.precedence_of(@operator)
      sub_pred = Sass::Script::Parser.precedence_of(op.operator)
      assoc = Sass::Script::Parser.associative?(@operator)
      return "(#{op.to_sass(opts)})" if sub_pred < pred ||
        (side == :right && sub_pred == pred && !assoc)
      op.to_sass(opts)
    end
  end
end
module Sass::Script::Tree
  class UnaryOperation < Node
    attr_reader :operator
    attr_reader :operand
    def initialize(operand, operator)
      @operand = operand
      @operator = operator
      super()
    end
    def inspect
      "(#{@operator.inspect} #{@operand.inspect})"
    end
    def to_sass(opts = {})
      operand = @operand.to_sass(opts)
      if @operand.is_a?(Operation) ||
          (@operator == :minus &&
           (operand =~ Sass::SCSS::RX::IDENT) == 0)
        operand = "(#{@operand.to_sass(opts)})"
      end
      op = Sass::Script::Lexer::OPERATORS_REVERSE[@operator]
      op + (op =~ /[a-z]/ ? " " : "") + operand
    end
    def children
      [@operand]
    end
    def deep_copy
      node = dup
      node.instance_variable_set('@operand', @operand.deep_copy)
      node
    end
    protected
    def _perform(environment)
      operator = "unary_#{@operator}"
      value = @operand.perform(environment)
      value.send(operator)
    rescue NoMethodError => e
      raise e unless e.name.to_s == operator.to_s
      raise Sass::SyntaxError.new("Undefined unary operation: \"#{@operator} #{value}\".")
    end
  end
end
module Sass::Script::Tree
  class Interpolation < Node
    attr_reader :before
    attr_reader :mid
    attr_reader :after
    attr_reader :whitespace_before
    attr_reader :whitespace_after
    attr_reader :originally_text
    attr_reader :warn_for_color
    def initialize(before, mid, after, wb, wa, originally_text = false, warn_for_color = false)
      @before = before
      @mid = mid
      @after = after
      @whitespace_before = wb
      @whitespace_after = wa
      @originally_text = originally_text
      @warn_for_color = warn_for_color
    end
    def inspect
      "(interpolation #{@before.inspect} #{@mid.inspect} #{@after.inspect})"
    end
    def to_sass(opts = {})
      res = ""
      res << @before.to_sass(opts) if @before
      res << ' ' if @before && @whitespace_before
      res << '#{' unless @originally_text
      res << @mid.to_sass(opts)
      res << '}' unless @originally_text
      res << ' ' if @after && @whitespace_after
      res << @after.to_sass(opts) if @after
      res
    end
    def children
      [@before, @mid, @after].compact
    end
    def deep_copy
      node = dup
      node.instance_variable_set('@before', @before.deep_copy) if @before
      node.instance_variable_set('@mid', @mid.deep_copy)
      node.instance_variable_set('@after', @after.deep_copy) if @after
      node
    end
    protected
    def _perform(environment)
      res = ""
      res << @before.perform(environment).to_s if @before
      res << " " if @before && @whitespace_before
      val = @mid.perform(environment)
      if @warn_for_color && val.is_a?(Sass::Script::Value::Color) && val.name
        alternative = Operation.new(Sass::Script::Value::String.new("", :string), @mid, :plus)
        Sass::Util.sass_warn <<MESSAGE
WARNING on line #{line}, column #{source_range.start_pos.offset}#{" of #{filename}" if filename}:
You probably don't mean to use the color value `#{val}' in interpolation here.
It may end up represented as #{val.inspect}, which will likely produce invalid CSS.
Always quote color names when using them as strings (for example, "#{val}").
If you really want to use the color value here, use `#{alternative.to_sass}'.
MESSAGE
      end
      res << val.to_s(:quote => :none)
      res << " " if @after && @whitespace_after
      res << @after.perform(environment).to_s if @after
      opts(Sass::Script::Value::String.new(res))
    end
  end
end
module Sass::Script::Tree
  class StringInterpolation < Node
    def initialize(before, mid, after)
      @before = before
      @mid = mid
      @after = after
    end
    def inspect
      "(string_interpolation #{@before.inspect} #{@mid.inspect} #{@after.inspect})"
    end
    def to_sass(opts = {})
      before_unquote, before_quote_char, before_str = parse_str(@before.to_sass(opts))
      after_unquote, after_quote_char, after_str = parse_str(@after.to_sass(opts))
      unquote = before_unquote || after_unquote ||
        (before_quote_char && !after_quote_char && !after_str.empty?) ||
        (!before_quote_char && after_quote_char && !before_str.empty?)
      quote_char =
        if before_quote_char && after_quote_char && before_quote_char != after_quote_char
          before_str.gsub!("\\'", "'")
          before_str.gsub!('"', "\\\"")
          after_str.gsub!("\\'", "'")
          after_str.gsub!('"', "\\\"")
          '"'
        else
          before_quote_char || after_quote_char
        end
      res = ""
      res << 'unquote(' if unquote
      res << quote_char if quote_char
      res << before_str
      res << '#{' << @mid.to_sass(opts) << '}'
      res << after_str
      res << quote_char if quote_char
      res << ')' if unquote
      res
    end
    def children
      [@before, @mid, @after].compact
    end
    def deep_copy
      node = dup
      node.instance_variable_set('@before', @before.deep_copy) if @before
      node.instance_variable_set('@mid', @mid.deep_copy)
      node.instance_variable_set('@after', @after.deep_copy) if @after
      node
    end
    protected
    def _perform(environment)
      res = ""
      before = @before.perform(environment)
      res << before.value
      mid = @mid.perform(environment)
      res << (mid.is_a?(Sass::Script::Value::String) ? mid.value : mid.to_s(:quote => :none))
      res << @after.perform(environment).value
      opts(Sass::Script::Value::String.new(res, before.type))
    end
    private
    def parse_str(str)
      case str
      when /^unquote\((["'])(.*)\1\)$/
        return true, $1, $2
      when '""'
        return false, nil, ""
      when /^(["'])(.*)\1$/
        return false, $1, $2
      else
        return false, nil, str
      end
    end
  end
end
module Sass::Script::Tree
  class Literal < Node
    attr_reader :value
    def initialize(value)
      @value = value
    end
    def children; []; end
    def to_sass(opts = {}); value.to_sass(opts); end
    def deep_copy; dup; end
    def options=(options)
      value.options = options
    end
    def inspect
      value.inspect
    end
    protected
    def _perform(environment)
      value.source_range = source_range
      value
    end
  end
end
module Sass::Script::Tree
  class ListLiteral < Node
    attr_reader :elements
    attr_reader :separator
    def initialize(elements, separator)
      @elements = elements
      @separator = separator
    end
    def children; elements; end
    def to_sass(opts = {})
      return "()" if elements.empty?
      precedence = Sass::Script::Parser.precedence_of(separator)
      members = elements.map do |v|
        if v.is_a?(ListLiteral) && Sass::Script::Parser.precedence_of(v.separator) <= precedence ||
            separator == :space && v.is_a?(UnaryOperation) &&
              (v.operator == :minus || v.operator == :plus) ||
            separator == :space && v.is_a?(Operation)
          "(#{v.to_sass(opts)})"
        else
          v.to_sass(opts)
        end
      end
      return "(#{members.first},)" if separator == :comma && members.length == 1
      members.join(sep_str(nil))
    end
    def deep_copy
      node = dup
      node.instance_variable_set('@elements', elements.map {|e| e.deep_copy})
      node
    end
    def inspect
      "(#{elements.map {|e| e.inspect}.join(separator == :space ? ' ' : ', ')})"
    end
    protected
    def _perform(environment)
      list = Sass::Script::Value::List.new(
        elements.map {|e| e.perform(environment)},
        separator)
      list.source_range = source_range
      list.options = options
      list
    end
    private
    def sep_str(opts = options)
      return ' ' if separator == :space
      return ',' if opts && opts[:style] == :compressed
      ', '
    end
  end
end
module Sass::Script::Tree
  class MapLiteral < Node
    attr_reader :pairs
    def initialize(pairs)
      @pairs = pairs
    end
    def children
      @pairs.flatten
    end
    def to_sass(opts = {})
      return "()" if pairs.empty?
      to_sass = lambda do |value|
        if value.is_a?(ListLiteral) && value.separator == :comma
          "(#{value.to_sass(opts)})"
        else
          value.to_sass(opts)
        end
      end
      "(" + pairs.map {|(k, v)| "#{to_sass[k]}: #{to_sass[v]}"}.join(', ') + ")"
    end
    alias_method :inspect, :to_sass
    def deep_copy
      node = dup
      node.instance_variable_set('@pairs',
        pairs.map {|(k, v)| [k.deep_copy, v.deep_copy]})
      node
    end
    protected
    def _perform(environment)
      keys = Set.new
      map = Sass::Script::Value::Map.new(Sass::Util.to_hash(pairs.map do |(k, v)|
        k, v = k.perform(environment), v.perform(environment)
        if keys.include?(k)
          raise Sass::SyntaxError.new("Duplicate key #{k.inspect} in map #{to_sass}.")
        end
        keys << k
        [k, v]
      end))
      map.options = options
      map
    end
  end
end
module Sass::Script::Tree
  class Selector < Node
    def initialize; end
    def children
      []
    end
    def to_sass(opts = {})
      '&'
    end
    def deep_copy
      dup
    end
    protected
    def _perform(environment)
      selector = environment.selector
      return opts(Sass::Script::Value::Null.new) unless selector
      opts(selector.to_sass_script)
    end
  end
end
module Sass::Script::Value; end
module Sass::Script::Value
  class Base
    attr_reader :value
    attr_accessor :source_range
    def initialize(value = nil)
      value.freeze unless value.nil? || value == true || value == false
      @value = value
    end
    attr_writer :options
    def options
      return @options if @options
      raise Sass::SyntaxError.new(<<MSG)
The #options attribute is not set on this #{self.class}.
  This error is probably occurring because #to_s was called
  on this value within a custom Sass function without first
  setting the #options attribute.
MSG
    end
    def eq(other)
      Sass::Script::Value::Bool.new(self.class == other.class && value == other.value)
    end
    def neq(other)
      Sass::Script::Value::Bool.new(!eq(other).to_bool)
    end
    def unary_not
      Sass::Script::Value::Bool.new(!to_bool)
    end
    def single_eq(other)
      Sass::Script::Value::String.new("#{to_s}=#{other.to_s}")
    end
    def plus(other)
      type = other.is_a?(Sass::Script::Value::String) ? other.type : :identifier
      Sass::Script::Value::String.new(to_s(:quote => :none) + other.to_s(:quote => :none), type)
    end
    def minus(other)
      Sass::Script::Value::String.new("#{to_s}-#{other.to_s}")
    end
    def div(other)
      Sass::Script::Value::String.new("#{to_s}/#{other.to_s}")
    end
    def unary_plus
      Sass::Script::Value::String.new("+#{to_s}")
    end
    def unary_minus
      Sass::Script::Value::String.new("-#{to_s}")
    end
    def unary_div
      Sass::Script::Value::String.new("/#{to_s}")
    end
    def hash
      value.hash
    end
    def eql?(other)
      self == other
    end
    def inspect
      value.inspect
    end
    def to_bool
      true
    end
    def ==(other)
      eq(other).to_bool
    end
    def to_i
      raise Sass::SyntaxError.new("#{inspect} is not an integer.")
    end
    def assert_int!; to_i; end
    def separator; nil; end
    def to_a
      [self]
    end
    def to_h
      raise Sass::SyntaxError.new("#{inspect} is not a map.")
    end
    def to_s(opts = {})
      Sass::Util.abstract(self)
    end
    alias_method :to_sass, :to_s
    def null?
      false
    end
    protected
    def _perform(environment)
      self
    end
  end
end
module Sass::Script::Value
  class String < Base
    attr_reader :value
    attr_reader :type
    def self.value(contents)
      contents.gsub("\\\n", "") #BT+
    end
    def self.quote(contents, quote = nil)
      unless contents =~ /[\n\\"']/
        quote ||= '"'
        return "#{quote}#{contents}#{quote}"
      end
      if quote.nil?
        if contents.include?('"')
          if contents.include?("'")
            quote = '"'
          else
            quote = "'"
          end
        else
          quote = '"'
        end
      end
      contents = contents.gsub("\\", "\\\\") #BT+
      if quote == '"'
        contents = contents.gsub('"', "\\\"")
      else
        contents = contents.gsub("'", "\\'")
      end
      contents = contents.gsub(/\n(?![a-fA-F0-9\s])/, "\\a").gsub("\n", "\\a ")
      "#{quote}#{contents}#{quote}"
    end
    def initialize(value, type = :identifier)
      super(value)
      @type = type
    end
    def plus(other)
      other_value = if other.is_a?(Sass::Script::Value::String)
                      other.value
                    else
                      other.to_s(:quote => :none)
                    end
      Sass::Script::Value::String.new(value + other_value, type)
    end
    def to_s(opts = {})
      return @value.gsub(/\n\s*/, ' ') if opts[:quote] == :none || @type == :identifier
      Sass::Script::Value::String.quote(value, opts[:quote])
    end
    def to_sass(opts = {})
      to_s
    end
    def inspect
      String.quote(value)
    end
  end
end
module Sass::Script::Value
  class Number < Base
    attr_reader :value
    attr_reader :numerator_units
    attr_reader :denominator_units
    attr_accessor :original
    def self.precision
      @precision ||= 5
    end
    def self.precision=(digits)
      @precision = digits.round
      @precision_factor = 10.0**@precision
    end
    def self.precision_factor
      @precision_factor ||= 10.0**precision
    end
    NO_UNITS  = []
    def initialize(value, numerator_units = NO_UNITS, denominator_units = NO_UNITS)
      numerator_units = [numerator_units] if numerator_units.is_a?(::String)
      denominator_units = [denominator_units] if denominator_units.is_a?(::String)
      super(value)
      @numerator_units = numerator_units
      @denominator_units = denominator_units
      normalize!
    end
    def plus(other)
      if other.is_a? Number
        operate(other, :+)
      elsif other.is_a?(Color)
        other.plus(self)
      else
        super
      end
    end
    def minus(other)
      if other.is_a? Number
        operate(other, :-)
      else
        super
      end
    end
    def unary_plus
      self
    end
    def unary_minus
      Number.new(-value, @numerator_units, @denominator_units)
    end
    def times(other)
      if other.is_a? Number
        operate(other, :*)
      elsif other.is_a? Color
        other.times(self)
      else
        raise NoMethodError.new(nil, :times)
      end
    end
    def div(other)
      if other.is_a? Number
        res = operate(other, :/)
        if original && other.original
          res.original = "#{original}/#{other.original}"
        end
        res
      else
        super
      end
    end
    def mod(other)
      if other.is_a?(Number)
        operate(other, :%)
      else
        raise NoMethodError.new(nil, :mod)
      end
    end
    def eq(other)
      return Bool::FALSE unless other.is_a?(Sass::Script::Value::Number)
      this = self
      begin
        if unitless?
          this = this.coerce(other.numerator_units, other.denominator_units)
        else
          other = other.coerce(@numerator_units, @denominator_units)
        end
      rescue Sass::UnitConversionError
        return Bool::FALSE
      end
      Bool.new(this.value == other.value)
    end
    def hash
      [value, numerator_units, denominator_units].hash
    end
    def eql?(other)
      value == other.value && numerator_units == other.numerator_units &&
        denominator_units == other.denominator_units
    end
    def gt(other)
      raise NoMethodError.new(nil, :gt) unless other.is_a?(Number)
      operate(other, :>)
    end
    def gte(other)
      raise NoMethodError.new(nil, :gte) unless other.is_a?(Number)
      operate(other, :>=)
    end
    def lt(other)
      raise NoMethodError.new(nil, :lt) unless other.is_a?(Number)
      operate(other, :<)
    end
    def lte(other)
      raise NoMethodError.new(nil, :lte) unless other.is_a?(Number)
      operate(other, :<=)
    end
    def to_s(opts = {})
      return original if original
      raise Sass::SyntaxError.new("#{inspect} isn't a valid CSS value.") unless legal_units?
      inspect
    end
    def inspect(opts = {})
      return original if original
      value = self.class.round(self.value)
      str = value.to_s
      str = ("%0.#{self.class.precision}f" % value).gsub(/0*$/, '') if str.include?('e')
      unitless? ? str : "#{str}#{unit_str}"
    end
    alias_method :to_sass, :inspect
    def to_i
      super unless int?
      value.to_i
    end
    def int?
      value % 1 == 0.0
    end
    def unitless?
      @numerator_units.empty? && @denominator_units.empty?
    end
    def is_unit?(unit)
      if unit
        denominator_units.size == 0 && numerator_units.size == 1 && numerator_units.first == unit
      else
        unitless?
      end
    end
    def legal_units?
      (@numerator_units.empty? || @numerator_units.size == 1) && @denominator_units.empty?
    end
    def coerce(num_units, den_units)
      Number.new(if unitless?
                   value
                 else
                   value * coercion_factor(@numerator_units, num_units) /
                     coercion_factor(@denominator_units, den_units)
                 end, num_units, den_units)
    end
    def comparable_to?(other)
      operate(other, :+)
      true
    rescue Sass::UnitConversionError
      false
    end
    def unit_str
      rv = @numerator_units.sort.join("*")
      if @denominator_units.any?
        rv << "/"
        rv << @denominator_units.sort.join("*")
      end
      rv
    end
    private
    def self.round(num)
      if num.is_a?(Float) && (num.infinite? || num.nan?)
        num
      elsif num % 1 == 0.0
        num.to_i
      else
        ((num * precision_factor).round / precision_factor).to_f
      end
    end
    OPERATIONS = [:+, :-, :<=, :<, :>, :>=, :%]
    def operate(other, operation)
      this = self
      if OPERATIONS.include?(operation)
        if unitless?
          this = this.coerce(other.numerator_units, other.denominator_units)
        else
          other = other.coerce(@numerator_units, @denominator_units)
        end
      end
      value = :/ == operation ? this.value.to_f : this.value
      result = value.send(operation, other.value)
      if result.is_a?(Numeric)
        Number.new(result, *compute_units(this, other, operation))
      else # Boolean op
        Bool.new(result)
      end
    end
    def coercion_factor(from_units, to_units)
      from_units, to_units = sans_common_units(from_units, to_units)
      if from_units.size != to_units.size || !convertable?(from_units | to_units)
        raise Sass::UnitConversionError.new(
          "Incompatible units: '#{from_units.join('*')}' and '#{to_units.join('*')}'.")
      end
      from_units.zip(to_units).inject(1) {|m, p| m * conversion_factor(p[0], p[1])}
    end
    def compute_units(this, other, operation)
      case operation
      when :*
        [this.numerator_units + other.numerator_units,
         this.denominator_units + other.denominator_units]
      when :/
        [this.numerator_units + other.denominator_units,
         this.denominator_units + other.numerator_units]
      else
        [this.numerator_units, this.denominator_units]
      end
    end
    def normalize!
      return if unitless?
      @numerator_units, @denominator_units =
        sans_common_units(@numerator_units, @denominator_units)
      @denominator_units.each_with_index do |d, i|
        if convertable?(d) && (u = @numerator_units.find(&method(:convertable?)))
          @value /= conversion_factor(d, u)
          @denominator_units.delete_at(i)
          @numerator_units.delete_at(@numerator_units.index(u))
        end
      end
    end
    relative_sizes = [
      {
        'in' => Rational(1),
        'cm' => Rational(1, 2.54),
        'pc' => Rational(1, 6),
        'mm' => Rational(1, 25.4),
        'pt' => Rational(1, 72),
        'px' => Rational(1, 96)
      },
      {
        'deg'  => Rational(1, 360),
        'grad' => Rational(1, 400),
        'rad'  => Rational(1, 2 * Math::PI),
        'turn' => Rational(1)
      },
      {
        's'  => Rational(1),
        'ms' => Rational(1, 1000)
      },
      {
        'Hz'  => Rational(1),
        'kHz' => Rational(1000)
      },
      {
        'dpi'  => Rational(1),
        'dpcm' => Rational(1, 2.54),
        'dppx' => Rational(1, 96)
      }
    ]
    MUTUALLY_CONVERTIBLE = {}
    relative_sizes.map do |values|
      set = values.keys.to_set
      values.keys.each {|name| MUTUALLY_CONVERTIBLE[name] = set}
    end
    CONVERSION_TABLE = {}
    relative_sizes.each do |values|
      values.each do |(name1, value1)|
        CONVERSION_TABLE[name1] ||= {}
        values.each do |(name2, value2)|
          value = value1 / value2
          CONVERSION_TABLE[name1][name2] = value.denominator == 1 ? value.to_i : value.to_f
        end
      end
    end
    def conversion_factor(from_unit, to_unit)
      CONVERSION_TABLE[from_unit][to_unit]
    end
    def convertable?(units)
      units = Array(units).to_set
      return true if units.empty?
      return false unless (mutually_convertible = MUTUALLY_CONVERTIBLE[units.first])
      units.subset?(mutually_convertible)
    end
    def sans_common_units(units1, units2)
      units2 = units2.dup
      units1 = units1.map do |u|
        j = units2.index(u)
        next u unless j
        units2.delete_at(j)
        nil
      end
      units1.compact!
      return units1, units2
    end
  end
end
module Sass::Script::Value
  class Color < Base
    def self.int_to_rgba(color)
      rgba = (0..3).map {|n| color >> (n << 3) & 0xff}.reverse
      rgba[-1] = rgba[-1] / 255.0
      rgba
    end
    ALTERNATE_COLOR_NAMES = Sass::Util.map_vals({
        'aqua'                 => 0x00FFFFFF,
        'darkgrey'             => 0xA9A9A9FF,
        'darkslategrey'        => 0x2F4F4FFF,
        'dimgrey'              => 0x696969FF,
        'fuchsia'              => 0xFF00FFFF,
        'grey'                 => 0x808080FF,
        'lightgrey'            => 0xD3D3D3FF,
        'lightslategrey'       => 0x778899FF,
        'slategrey'            => 0x708090FF,
    }, &method(:int_to_rgba))
    COLOR_NAMES = Sass::Util.map_vals({
        'aliceblue'            => 0xF0F8FFFF,
        'antiquewhite'         => 0xFAEBD7FF,
        'aquamarine'           => 0x7FFFD4FF,
        'azure'                => 0xF0FFFFFF,
        'beige'                => 0xF5F5DCFF,
        'bisque'               => 0xFFE4C4FF,
        'black'                => 0x000000FF,
        'blanchedalmond'       => 0xFFEBCDFF,
        'blue'                 => 0x0000FFFF,
        'blueviolet'           => 0x8A2BE2FF,
        'brown'                => 0xA52A2AFF,
        'burlywood'            => 0xDEB887FF,
        'cadetblue'            => 0x5F9EA0FF,
        'chartreuse'           => 0x7FFF00FF,
        'chocolate'            => 0xD2691EFF,
        'coral'                => 0xFF7F50FF,
        'cornflowerblue'       => 0x6495EDFF,
        'cornsilk'             => 0xFFF8DCFF,
        'crimson'              => 0xDC143CFF,
        'cyan'                 => 0x00FFFFFF,
        'darkblue'             => 0x00008BFF,
        'darkcyan'             => 0x008B8BFF,
        'darkgoldenrod'        => 0xB8860BFF,
        'darkgray'             => 0xA9A9A9FF,
        'darkgreen'            => 0x006400FF,
        'darkkhaki'            => 0xBDB76BFF,
        'darkmagenta'          => 0x8B008BFF,
        'darkolivegreen'       => 0x556B2FFF,
        'darkorange'           => 0xFF8C00FF,
        'darkorchid'           => 0x9932CCFF,
        'darkred'              => 0x8B0000FF,
        'darksalmon'           => 0xE9967AFF,
        'darkseagreen'         => 0x8FBC8FFF,
        'darkslateblue'        => 0x483D8BFF,
        'darkslategray'        => 0x2F4F4FFF,
        'darkturquoise'        => 0x00CED1FF,
        'darkviolet'           => 0x9400D3FF,
        'deeppink'             => 0xFF1493FF,
        'deepskyblue'          => 0x00BFFFFF,
        'dimgray'              => 0x696969FF,
        'dodgerblue'           => 0x1E90FFFF,
        'firebrick'            => 0xB22222FF,
        'floralwhite'          => 0xFFFAF0FF,
        'forestgreen'          => 0x228B22FF,
        'gainsboro'            => 0xDCDCDCFF,
        'ghostwhite'           => 0xF8F8FFFF,
        'gold'                 => 0xFFD700FF,
        'goldenrod'            => 0xDAA520FF,
        'gray'                 => 0x808080FF,
        'green'                => 0x008000FF,
        'greenyellow'          => 0xADFF2FFF,
        'honeydew'             => 0xF0FFF0FF,
        'hotpink'              => 0xFF69B4FF,
        'indianred'            => 0xCD5C5CFF,
        'indigo'               => 0x4B0082FF,
        'ivory'                => 0xFFFFF0FF,
        'khaki'                => 0xF0E68CFF,
        'lavender'             => 0xE6E6FAFF,
        'lavenderblush'        => 0xFFF0F5FF,
        'lawngreen'            => 0x7CFC00FF,
        'lemonchiffon'         => 0xFFFACDFF,
        'lightblue'            => 0xADD8E6FF,
        'lightcoral'           => 0xF08080FF,
        'lightcyan'            => 0xE0FFFFFF,
        'lightgoldenrodyellow' => 0xFAFAD2FF,
        'lightgreen'           => 0x90EE90FF,
        'lightgray'            => 0xD3D3D3FF,
        'lightpink'            => 0xFFB6C1FF,
        'lightsalmon'          => 0xFFA07AFF,
        'lightseagreen'        => 0x20B2AAFF,
        'lightskyblue'         => 0x87CEFAFF,
        'lightslategray'       => 0x778899FF,
        'lightsteelblue'       => 0xB0C4DEFF,
        'lightyellow'          => 0xFFFFE0FF,
        'lime'                 => 0x00FF00FF,
        'limegreen'            => 0x32CD32FF,
        'linen'                => 0xFAF0E6FF,
        'magenta'              => 0xFF00FFFF,
        'maroon'               => 0x800000FF,
        'mediumaquamarine'     => 0x66CDAAFF,
        'mediumblue'           => 0x0000CDFF,
        'mediumorchid'         => 0xBA55D3FF,
        'mediumpurple'         => 0x9370DBFF,
        'mediumseagreen'       => 0x3CB371FF,
        'mediumslateblue'      => 0x7B68EEFF,
        'mediumspringgreen'    => 0x00FA9AFF,
        'mediumturquoise'      => 0x48D1CCFF,
        'mediumvioletred'      => 0xC71585FF,
        'midnightblue'         => 0x191970FF,
        'mintcream'            => 0xF5FFFAFF,
        'mistyrose'            => 0xFFE4E1FF,
        'moccasin'             => 0xFFE4B5FF,
        'navajowhite'          => 0xFFDEADFF,
        'navy'                 => 0x000080FF,
        'oldlace'              => 0xFDF5E6FF,
        'olive'                => 0x808000FF,
        'olivedrab'            => 0x6B8E23FF,
        'orange'               => 0xFFA500FF,
        'orangered'            => 0xFF4500FF,
        'orchid'               => 0xDA70D6FF,
        'palegoldenrod'        => 0xEEE8AAFF,
        'palegreen'            => 0x98FB98FF,
        'paleturquoise'        => 0xAFEEEEFF,
        'palevioletred'        => 0xDB7093FF,
        'papayawhip'           => 0xFFEFD5FF,
        'peachpuff'            => 0xFFDAB9FF,
        'peru'                 => 0xCD853FFF,
        'pink'                 => 0xFFC0CBFF,
        'plum'                 => 0xDDA0DDFF,
        'powderblue'           => 0xB0E0E6FF,
        'purple'               => 0x800080FF,
        'red'                  => 0xFF0000FF,
        'rebeccapurple'        => 0x663399FF,
        'rosybrown'            => 0xBC8F8FFF,
        'royalblue'            => 0x4169E1FF,
        'saddlebrown'          => 0x8B4513FF,
        'salmon'               => 0xFA8072FF,
        'sandybrown'           => 0xF4A460FF,
        'seagreen'             => 0x2E8B57FF,
        'seashell'             => 0xFFF5EEFF,
        'sienna'               => 0xA0522DFF,
        'silver'               => 0xC0C0C0FF,
        'skyblue'              => 0x87CEEBFF,
        'slateblue'            => 0x6A5ACDFF,
        'slategray'            => 0x708090FF,
        'snow'                 => 0xFFFAFAFF,
        'springgreen'          => 0x00FF7FFF,
        'steelblue'            => 0x4682B4FF,
        'tan'                  => 0xD2B48CFF,
        'teal'                 => 0x008080FF,
        'thistle'              => 0xD8BFD8FF,
        'tomato'               => 0xFF6347FF,
        'transparent'          => 0x00000000,
        'turquoise'            => 0x40E0D0FF,
        'violet'               => 0xEE82EEFF,
        'wheat'                => 0xF5DEB3FF,
        'white'                => 0xFFFFFFFF,
        'whitesmoke'           => 0xF5F5F5FF,
        'yellow'               => 0xFFFF00FF,
        'yellowgreen'          => 0x9ACD32FF
     }, &method(:int_to_rgba))
    COLOR_NAMES_REVERSE = COLOR_NAMES.invert.freeze
    COLOR_NAMES.update(ALTERNATE_COLOR_NAMES).freeze
    attr_reader :representation
    def initialize(attrs, representation = nil, allow_both_rgb_and_hsl = false)
      super(nil)
      if attrs.is_a?(Array)
        unless (3..4).include?(attrs.size)
          raise ArgumentError.new("Color.new(array) expects a three- or four-element array")
        end
        red, green, blue = attrs[0...3].map {|c| c.to_i}
        @attrs = {:red => red, :green => green, :blue => blue}
        @attrs[:alpha] = attrs[3] ? attrs[3].to_f : 1
        @representation = representation
      else
        attrs = attrs.reject {|k, v| v.nil?}
        hsl = [:hue, :saturation, :lightness] & attrs.keys
        rgb = [:red, :green, :blue] & attrs.keys
        if !allow_both_rgb_and_hsl && !hsl.empty? && !rgb.empty?
          raise ArgumentError.new("Color.new(hash) may not have both HSL and RGB keys specified")
        elsif hsl.empty? && rgb.empty?
          raise ArgumentError.new("Color.new(hash) must have either HSL or RGB keys specified")
        elsif !hsl.empty? && hsl.size != 3
          raise ArgumentError.new("Color.new(hash) must have all three HSL values specified")
        elsif !rgb.empty? && rgb.size != 3
          raise ArgumentError.new("Color.new(hash) must have all three RGB values specified")
        end
        @attrs = attrs
        @attrs[:hue] %= 360 if @attrs[:hue]
        @attrs[:alpha] ||= 1
        @representation = @attrs.delete(:representation)
      end
      [:red, :green, :blue].each do |k|
        next if @attrs[k].nil?
        @attrs[k] = Sass::Util.restrict(@attrs[k].to_i, 0..255)
      end
      [:saturation, :lightness].each do |k|
        next if @attrs[k].nil?
        @attrs[k] = Sass::Util.restrict(@attrs[k], 0..100)
      end
      @attrs[:alpha] = Sass::Util.restrict(@attrs[:alpha], 0..1)
    end
    def self.from_hex(hex_string, alpha = nil)
      unless hex_string =~ /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i ||
             hex_string =~ /^#?([0-9a-f])([0-9a-f])([0-9a-f])$/i
        raise ArgumentError.new("#{hex_string.inspect} is not a valid hex color.")
      end
      red   = $1.ljust(2, $1).to_i(16)
      green = $2.ljust(2, $2).to_i(16)
      blue  = $3.ljust(2, $3).to_i(16)
      hex_string = '##{hex_string}' unless hex_string[0] == ?#
      attrs = {:red => red, :green => green, :blue => blue, :representation => hex_string}
      attrs[:alpha] = alpha if alpha
      new(attrs)
    end
    def red
      hsl_to_rgb!
      @attrs[:red]
    end
    def green
      hsl_to_rgb!
      @attrs[:green]
    end
    def blue
      hsl_to_rgb!
      @attrs[:blue]
    end
    def hue
      rgb_to_hsl!
      @attrs[:hue]
    end
    def saturation
      rgb_to_hsl!
      @attrs[:saturation]
    end
    def lightness
      rgb_to_hsl!
      @attrs[:lightness]
    end
    def alpha
      @attrs[:alpha].to_f
    end
    def alpha?
      alpha < 1
    end
    def rgb
      [red, green, blue].freeze
    end
    def rgba
      [red, green, blue, alpha].freeze
    end
    def hsl
      [hue, saturation, lightness].freeze
    end
    def hsla
      [hue, saturation, lightness].freeze
    end
    def eq(other)
      Sass::Script::Value::Bool.new(
        other.is_a?(Color) && rgb == other.rgb && alpha == other.alpha)
    end
    def hash
      [rgb, alpha].hash
    end
    def with(attrs)
      attrs = attrs.reject {|k, v| v.nil?}
      hsl = !([:hue, :saturation, :lightness] & attrs.keys).empty?
      rgb = !([:red, :green, :blue] & attrs.keys).empty?
      if hsl && rgb
        raise ArgumentError.new("Cannot specify HSL and RGB values for a color at the same time")
      end
      if hsl
        [:hue, :saturation, :lightness].each {|k| attrs[k] ||= send(k)}
      elsif rgb
        [:red, :green, :blue].each {|k| attrs[k] ||= send(k)}
      else
        attrs = @attrs.merge(attrs)
      end
      attrs[:alpha] ||= alpha
      Color.new(attrs, nil, :allow_both_rgb_and_hsl)
    end
    def plus(other)
      if other.is_a?(Sass::Script::Value::Number) || other.is_a?(Sass::Script::Value::Color)
        piecewise(other, :+)
      else
        super
      end
    end
    def minus(other)
      if other.is_a?(Sass::Script::Value::Number) || other.is_a?(Sass::Script::Value::Color)
        piecewise(other, :-)
      else
        super
      end
    end
    def times(other)
      if other.is_a?(Sass::Script::Value::Number) || other.is_a?(Sass::Script::Value::Color)
        piecewise(other, :*)
      else
        raise NoMethodError.new(nil, :times)
      end
    end
    def div(other)
      if other.is_a?(Sass::Script::Value::Number) ||
          other.is_a?(Sass::Script::Value::Color)
        piecewise(other, :/)
      else
        super
      end
    end
    def mod(other)
      if other.is_a?(Sass::Script::Value::Number) ||
          other.is_a?(Sass::Script::Value::Color)
        piecewise(other, :%)
      else
        raise NoMethodError.new(nil, :mod)
      end
    end
    def to_s(opts = {})
      return smallest if options[:style] == :compressed
      return representation if representation
      return name if name
      alpha? ? rgba_str : hex_str
    end
    alias_method :to_sass, :to_s
    def inspect
      alpha? ? rgba_str : hex_str
    end
    def name
      COLOR_NAMES_REVERSE[rgba]
    end
    private
    def smallest
      small_explicit_str = alpha? ? rgba_str : hex_str.gsub(/^#(.)\1(.)\2(.)\3$/, '#\1\2\3')
      [representation, COLOR_NAMES_REVERSE[rgba], small_explicit_str].
          compact.min_by {|str| str.size}
    end
    def rgba_str
      split = options[:style] == :compressed ? ',' : ', '
      "rgba(#{rgb.join(split)}#{split}#{Number.round(alpha)})"
    end
    def hex_str
      red, green, blue = rgb.map {|num| num.to_s(16).rjust(2, '0')}
      "##{red}#{green}#{blue}"
    end
    def piecewise(other, operation)
      other_num = other.is_a? Number
      if other_num && !other.unitless?
        raise Sass::SyntaxError.new(
          "Cannot add a number with units (#{other}) to a color (#{self}).")
      end
      result = []
      (0...3).each do |i|
        res = rgb[i].send(operation, other_num ? other.value : other.rgb[i])
        result[i] = [[res, 255].min, 0].max
      end
      if !other_num && other.alpha != alpha
        raise Sass::SyntaxError.new("Alpha channels must be equal: #{self} #{operation} #{other}")
      end
      with(:red => result[0], :green => result[1], :blue => result[2])
    end
    def hsl_to_rgb!
      return if @attrs[:red] && @attrs[:blue] && @attrs[:green]
      h = @attrs[:hue] / 360.0
      s = @attrs[:saturation] / 100.0
      l = @attrs[:lightness] / 100.0
      m2 = l <= 0.5 ? l * (s + 1) : l + s - l * s
      m1 = l * 2 - m2
      @attrs[:red], @attrs[:green], @attrs[:blue] = [
        hue_to_rgb(m1, m2, h + 1.0 / 3),
        hue_to_rgb(m1, m2, h),
        hue_to_rgb(m1, m2, h - 1.0 / 3)
      ].map {|c| (c * 0xff).round}
    end
    def hue_to_rgb(m1, m2, h)
      h += 1 if h < 0
      h -= 1 if h > 1
      return m1 + (m2 - m1) * h * 6 if h * 6 < 1
      return m2 if h * 2 < 1
      return m1 + (m2 - m1) * (2.0 / 3 - h) * 6 if h * 3 < 2
      m1
    end
    def rgb_to_hsl!
      return if @attrs[:hue] && @attrs[:saturation] && @attrs[:lightness]
      r, g, b = [:red, :green, :blue].map {|k| @attrs[k] / 255.0}
      max = [r, g, b].max
      min = [r, g, b].min
      d = max - min
      h =
        case max
        when min; 0
        when r; 60 * (g - b) / d
        when g; 60 * (b - r) / d + 120
        when b; 60 * (r - g) / d + 240
        end
      l = (max + min) / 2.0
      s =
        if max == min
          0
        elsif l < 0.5
          d / (2 * l)
        else
          d / (2 - 2 * l)
        end
      @attrs[:hue] = h % 360
      @attrs[:saturation] = s * 100
      @attrs[:lightness] = l * 100
    end
  end
end
module Sass::Script::Value
  class Bool < Base
    TRUE  = new(true)
    FALSE = new(false)
    def self.new(value)
      value ? TRUE : FALSE
    end
    attr_reader :value
    alias_method :to_bool, :value
    def to_s(opts = {})
      @value.to_s
    end
    alias_method :to_sass, :to_s
  end
end
module Sass::Script::Value
  class Null < Base
    NULL = new(nil)
    def self.new
      NULL
    end
    def to_bool
      false
    end
    def null?
      true
    end
    def to_s(opts = {})
      ''
    end
    def to_sass(opts = {})
      'null'
    end
    def inspect
      'null'
    end
  end
end
module Sass::Script::Value
  class List < Base
    attr_reader :value
    alias_method :to_a, :value
    attr_reader :separator
    def initialize(value, separator)
      super(value)
      @separator = separator
    end
    def options=(options)
      super
      value.each {|v| v.options = options}
    end
    def eq(other)
      Sass::Script::Value::Bool.new(
        other.is_a?(List) && value == other.value &&
        separator == other.separator)
    end
    def hash
      @hash ||= [value, separator].hash
    end
    def to_s(opts = {})
      raise Sass::SyntaxError.new("() isn't a valid CSS value.") if value.empty?
      value.
        reject {|e| e.is_a?(Null) || e.is_a?(List) && e.value.empty?}.
        map {|e| e.to_s(opts)}.join(sep_str)
    end
    def to_sass(opts = {})
      return "()" if value.empty?
      members = value.map do |v|
        if element_needs_parens?(v)
          "(#{v.to_sass(opts)})"
        else
          v.to_sass(opts)
        end
      end
      return "(#{members.first},)" if members.length == 1 && separator == :comma
      members.join(sep_str(nil))
    end
    def to_h
      return Sass::Util.ordered_hash if value.empty?
      super
    end
    def inspect
      "(#{value.map {|e| e.inspect}.join(sep_str(nil))})"
    end
    def self.assert_valid_index(list, n)
      if !n.int? || n.to_i == 0
        raise ArgumentError.new("List index #{n} must be a non-zero integer")
      elsif list.to_a.size == 0
        raise ArgumentError.new("List index is #{n} but list has no items")
      elsif n.to_i.abs > (size = list.to_a.size)
        raise ArgumentError.new(
          "List index is #{n} but list is only #{size} item#{'s' if size != 1} long")
      end
    end
    private
    def element_needs_parens?(element)
      if element.is_a?(List)
        return false if element.value.empty?
        precedence = Sass::Script::Parser.precedence_of(separator)
        return Sass::Script::Parser.precedence_of(element.separator) <= precedence
      end
      return false unless separator == :space
      return false unless element.is_a?(Sass::Script::Tree::UnaryOperation)
      element.operator == :minus || element.operator == :plus
    end
    def sep_str(opts = options)
      return ' ' if separator == :space
      return ',' if opts && opts[:style] == :compressed
      ', '
    end
  end
end
module Sass::Script::Value
  class ArgList < List
    attr_accessor :keywords_accessed
    def initialize(value, keywords, separator)
      super(value, separator)
      if keywords.is_a?(Sass::Util::NormalizedMap)
        @keywords = keywords
      else
        @keywords = Sass::Util::NormalizedMap.new(keywords)
      end
    end
    def keywords
      @keywords_accessed = true
      @keywords
    end
  end
end
module Sass::Script::Value
  class Map < Base
    attr_reader :value
    alias_method :to_h, :value
    def initialize(hash)
      super(Sass::Util.ordered_hash(hash))
    end
    def options=(options)
      super
      value.each do |k, v|
        k.options = options
        v.options = options
      end
    end
    def separator
      :comma unless value.empty?
    end
    def to_a
      value.map do |k, v|
        list = List.new([k, v], :space)
        list.options = options
        list
      end
    end
    def eq(other)
      Bool.new(other.is_a?(Map) && value == other.value)
    end
    def hash
      @hash ||= value.hash
    end
    def to_s(opts = {})
      raise Sass::SyntaxError.new("#{inspect} isn't a valid CSS value.")
    end
    def to_sass(opts = {})
      return "()" if value.empty?
      to_sass = lambda do |value|
        if value.is_a?(List) && value.separator == :comma
          "(#{value.to_sass(opts)})"
        else
          value.to_sass(opts)
        end
      end
      "(#{value.map {|(k, v)| "#{to_sass[k]}: #{to_sass[v]}"}.join(', ')})"
    end
    alias_method :inspect, :to_sass
  end
end
module Sass
  module Script
    CONST_RENAMES = {
      :Literal => Sass::Script::Value::Base,
      :ArgList => Sass::Script::Value::ArgList,
      :Bool => Sass::Script::Value::Bool,
      :Color => Sass::Script::Value::Color,
      :List => Sass::Script::Value::List,
      :Null => Sass::Script::Value::Null,
      :Number => Sass::Script::Value::Number,
      :String => Sass::Script::Value::String,
      :Node => Sass::Script::Tree::Node,
      :Funcall => Sass::Script::Tree::Funcall,
      :Interpolation => Sass::Script::Tree::Interpolation,
      :Operation => Sass::Script::Tree::Operation,
      :StringInterpolation => Sass::Script::Tree::StringInterpolation,
      :UnaryOperation => Sass::Script::Tree::UnaryOperation,
      :Variable => Sass::Script::Tree::Variable,
    }
    def self.const_missing(name)
      klass = CONST_RENAMES[name]
      super unless klass
      CONST_RENAMES.each {|n, k| const_set(n, k)}
      klass
    end
  end
end
module Sass
  module SCSS
    module ScriptLexer
      private
      def variable
        return [:raw, "!important"] if scan(Sass::SCSS::RX::IMPORTANT)
        _variable(Sass::SCSS::RX::VARIABLE)
      end
    end
  end
end
module Sass
  module SCSS
    module ScriptParser
      private
      def lexer_class
        klass = Class.new(super)
        klass.send(:include, ScriptLexer)
        klass
      end
      def assert_done
        @lexer.unpeek!
      end
    end
  end
end
module Sass
  module SCSS
    class Parser
      attr_accessor :offset
      def initialize(str, filename, importer, line = 1, offset = 1)
        @template = str
        @filename = filename
        @importer = importer
        @line = line
        @offset = offset
        @strs = []
      end
      def parse
        init_scanner!
        root = stylesheet
        expected("selector or at-rule") unless root && @scanner.eos?
        root
      end
      def parse_interp_ident
        init_scanner!
        interp_ident
      end
      def parse_media_query_list
        init_scanner!
        ql = media_query_list
        expected("media query list") unless ql && @scanner.eos?
        ql
      end
      def parse_at_root_query
        init_scanner!
        query = at_root_query
        expected("@at-root query list") unless query && @scanner.eos?
        query
      end
      def parse_supports_condition
        init_scanner!
        condition = supports_condition
        expected("supports condition") unless condition && @scanner.eos?
        condition
      end
      private
      include Sass::SCSS::RX
      def source_position
        Sass::Source::Position.new(@line, @offset)
      end
      def range(start_pos, end_pos = source_position)
        Sass::Source::Range.new(start_pos, end_pos, @filename, @importer)
      end
      def init_scanner!
        @scanner =
          if @template.is_a?(StringScanner)
            @template
          else
            Sass::Util::MultibyteStringScanner.new(@template.gsub("\r", ""))
          end
      end
      def stylesheet
        node = node(Sass::Tree::RootNode.new(@scanner.string), source_position)
        block_contents(node, :stylesheet) {s(node)}
      end
      def s(node)
        while tok(S) || tok(CDC) || tok(CDO) || (c = tok(SINGLE_LINE_COMMENT)) || (c = tok(COMMENT))
          next unless c
          process_comment c, node
          c = nil
        end
        true
      end
      def ss
        nil while tok(S) || tok(SINGLE_LINE_COMMENT) || tok(COMMENT)
        true
      end
      def ss_comments(node)
        while tok(S) || (c = tok(SINGLE_LINE_COMMENT)) || (c = tok(COMMENT))
          next unless c
          process_comment c, node
          c = nil
        end
        true
      end
      def whitespace
        return unless tok(S) || tok(SINGLE_LINE_COMMENT) || tok(COMMENT)
        ss
      end
      def process_comment(text, node)
        silent = text =~ %r{\A//}
        loud = !silent && text =~ %r{\A/[/*]!}
        line = @line - text.count("\n")
        if silent
          value = [text.sub(%r{\A\s*//}, '/*').gsub(%r{^\s*//}, ' *') + ' */']
        else
          value = Sass::Engine.parse_interp(
            text, line, @scanner.pos - text.size, :filename => @filename)
          string_before_comment = @scanner.string[0...@scanner.pos - text.length]
          newline_before_comment = string_before_comment.rindex("\n")
          last_line_before_comment =
            if newline_before_comment
              string_before_comment[newline_before_comment + 1..-1]
            else
              string_before_comment
            end
          value.unshift(last_line_before_comment.gsub(/[^\s]/, ' '))
        end
        type = if silent
                 :silent
               elsif loud
                 :loud
               else
                 :normal
               end
        comment = Sass::Tree::CommentNode.new(value, type)
        comment.line = line
        node << comment
      end
      DIRECTIVES = Set[:mixin, :include, :function, :return, :debug, :warn, :for,
        :each, :while, :if, :else, :extend, :import, :media, :charset, :content,
        :_moz_document, :at_root, :error]
      PREFIXED_DIRECTIVES = Set[:supports]
      def directive
        start_pos = source_position
        return unless tok(/@/)
        name = tok!(IDENT)
        ss
        if (dir = special_directive(name, start_pos))
          return dir
        elsif (dir = prefixed_directive(name, start_pos))
          return dir
        end
        val = almost_any_value
        val = val ? ["@#{name} "] + Sass::Util.strip_string_array(val) : ["@#{name}"]
        directive_body(val, start_pos)
      end
      def directive_body(value, start_pos)
        node = Sass::Tree::DirectiveNode.new(value)
        if tok(/\{/)
          node.has_children = true
          block_contents(node, :directive)
          tok!(/\}/)
        end
        node(node, start_pos)
      end
      def special_directive(name, start_pos)
        sym = name.gsub('-', '_').to_sym
        DIRECTIVES.include?(sym) && send("#{sym}_directive", start_pos)
      end
      def prefixed_directive(name, start_pos)
        sym = deprefix(name).gsub('-', '_').to_sym
        PREFIXED_DIRECTIVES.include?(sym) && send("#{sym}_directive", name, start_pos)
      end
      def mixin_directive(start_pos)
        name = tok! IDENT
        args, splat = sass_script(:parse_mixin_definition_arglist)
        ss
        block(node(Sass::Tree::MixinDefNode.new(name, args, splat), start_pos), :directive)
      end
      def include_directive(start_pos)
        name = tok! IDENT
        args, keywords, splat, kwarg_splat = sass_script(:parse_mixin_include_arglist)
        ss
        include_node = node(
          Sass::Tree::MixinNode.new(name, args, keywords, splat, kwarg_splat), start_pos)
        if tok?(/\{/)
          include_node.has_children = true
          block(include_node, :directive)
        else
          include_node
        end
      end
      def content_directive(start_pos)
        ss
        node(Sass::Tree::ContentNode.new, start_pos)
      end
      def function_directive(start_pos)
        name = tok! IDENT
        args, splat = sass_script(:parse_function_definition_arglist)
        ss
        block(node(Sass::Tree::FunctionNode.new(name, args, splat), start_pos), :function)
      end
      def return_directive(start_pos)
        node(Sass::Tree::ReturnNode.new(sass_script(:parse)), start_pos)
      end
      def debug_directive(start_pos)
        node(Sass::Tree::DebugNode.new(sass_script(:parse)), start_pos)
      end
      def warn_directive(start_pos)
        node(Sass::Tree::WarnNode.new(sass_script(:parse)), start_pos)
      end
      def for_directive(start_pos)
        tok!(/\$/)
        var = tok! IDENT
        ss
        tok!(/from/)
        from = sass_script(:parse_until, Set["to", "through"])
        ss
        @expected = '"to" or "through"'
        exclusive = (tok(/to/) || tok!(/through/)) == 'to'
        to = sass_script(:parse)
        ss
        block(node(Sass::Tree::ForNode.new(var, from, to, exclusive), start_pos), :directive)
      end
      def each_directive(start_pos)
        tok!(/\$/)
        vars = [tok!(IDENT)]
        ss
        while tok(/,/)
          ss
          tok!(/\$/)
          vars << tok!(IDENT)
          ss
        end
        tok!(/in/)
        list = sass_script(:parse)
        ss
        block(node(Sass::Tree::EachNode.new(vars, list), start_pos), :directive)
      end
      def while_directive(start_pos)
        expr = sass_script(:parse)
        ss
        block(node(Sass::Tree::WhileNode.new(expr), start_pos), :directive)
      end
      def if_directive(start_pos)
        expr = sass_script(:parse)
        ss
        node = block(node(Sass::Tree::IfNode.new(expr), start_pos), :directive)
        pos = @scanner.pos
        line = @line
        ss
        else_block(node) ||
          begin
            @scanner.pos = pos
            @line = line
            node
          end
      end
      def else_block(node)
        start_pos = source_position
        return unless tok(/@else/)
        ss
        else_node = block(
          node(Sass::Tree::IfNode.new((sass_script(:parse) if tok(/if/))), start_pos),
          :directive)
        node.add_else(else_node)
        pos = @scanner.pos
        line = @line
        ss
        else_block(node) ||
          begin
            @scanner.pos = pos
            @line = line
            node
          end
      end
      def else_directive(start_pos)
        err("Invalid CSS: @else must come after @if")
      end
      def extend_directive(start_pos)
        selector_start_pos = source_position
        @expected = "selector"
        selector = Sass::Util.strip_string_array(expr!(:almost_any_value))
        optional = tok(OPTIONAL)
        ss
        node(Sass::Tree::ExtendNode.new(selector, !!optional, range(selector_start_pos)), start_pos)
      end
      def import_directive(start_pos)
        values = []
        loop do
          values << expr!(:import_arg)
          break if use_css_import?
          break unless tok(/,/)
          ss
        end
        values
      end
      def import_arg
        start_pos = source_position
        return unless (str = string) || (uri = tok?(/url\(/i))
        if uri
          str = sass_script(:parse_string)
          ss
          media = media_query_list
          ss
          return node(Tree::CssImportNode.new(str, media.to_a), start_pos)
        end
        ss
        media = media_query_list
        if str =~ %r{^(https?:)?//} || media || use_css_import?
          return node(Sass::Tree::CssImportNode.new(
              Sass::Script::Value::String.quote(str), media.to_a), start_pos)
        end
        node(Sass::Tree::ImportNode.new(str.strip), start_pos)
      end
      def use_css_import?; false; end
      def media_directive(start_pos)
        block(node(Sass::Tree::MediaNode.new(expr!(:media_query_list).to_a), start_pos), :directive)
      end
      def media_query_list
        query = media_query
        return unless query
        queries = [query]
        ss
        while tok(/,/)
          ss; queries << expr!(:media_query)
        end
        ss
        Sass::Media::QueryList.new(queries)
      end
      def media_query
        if (ident1 = interp_ident)
          ss
          ident2 = interp_ident
          ss
          if ident2 && ident2.length == 1 && ident2[0].is_a?(String) && ident2[0].downcase == 'and'
            query = Sass::Media::Query.new([], ident1, [])
          else
            if ident2
              query = Sass::Media::Query.new(ident1, ident2, [])
            else
              query = Sass::Media::Query.new([], ident1, [])
            end
            return query unless tok(/and/i)
            ss
          end
        end
        if query
          expr = expr!(:media_expr)
        else
          expr = media_expr
          return unless expr
        end
        query ||= Sass::Media::Query.new([], [], [])
        query.expressions << expr
        ss
        while tok(/and/i)
          ss; query.expressions << expr!(:media_expr)
        end
        query
      end
      def query_expr
        interp = interpolation
        return interp if interp
        return unless tok(/\(/)
        res = ['(']
        ss
        res << sass_script(:parse)
        if tok(/:/)
          res << ': '
          ss
          res << sass_script(:parse)
        end
        res << tok!(/\)/)
        ss
        res
      end
      alias_method :media_expr, :query_expr
      alias_method :at_root_query, :query_expr
      def charset_directive(start_pos)
        name = expr!(:string)
        ss
        node(Sass::Tree::CharsetNode.new(name), start_pos)
      end
      def _moz_document_directive(start_pos)
        res = ["@-moz-document "]
        loop do
          res << str {ss} << expr!(:moz_document_function)
          if (c = tok(/,/))
            res << c
          else
            break
          end
        end
        directive_body(res.flatten, start_pos)
      end
      def moz_document_function
        val = interp_uri || _interp_string(:url_prefix) ||
          _interp_string(:domain) || function(!:allow_var) || interpolation
        return unless val
        ss
        val
      end
      def at_root_directive(start_pos)
        if tok?(/\(/) && (expr = at_root_query)
          return block(node(Sass::Tree::AtRootNode.new(expr), start_pos), :directive)
        end
        at_root_node = node(Sass::Tree::AtRootNode.new, start_pos)
        rule_node = ruleset
        return block(at_root_node, :stylesheet) unless rule_node
        at_root_node << rule_node
        at_root_node
      end
      def at_root_directive_list
        return unless (first = tok(IDENT))
        arr = [first]
        ss
        while (e = tok(IDENT))
          arr << e
          ss
        end
        arr
      end
      def error_directive(start_pos)
        node(Sass::Tree::ErrorNode.new(sass_script(:parse)), start_pos)
      end
      def supports_directive(name, start_pos)
        condition = expr!(:supports_condition)
        node = Sass::Tree::SupportsNode.new(name, condition)
        tok!(/\{/)
        node.has_children = true
        block_contents(node, :directive)
        tok!(/\}/)
        node(node, start_pos)
      end
      def supports_condition
        supports_negation || supports_operator || supports_interpolation
      end
      def supports_negation
        return unless tok(/not/i)
        ss
        Sass::Supports::Negation.new(expr!(:supports_condition_in_parens))
      end
      def supports_operator
        cond = supports_condition_in_parens
        return unless cond
        while (op = tok(/and|or/i))
          ss
          cond = Sass::Supports::Operator.new(
            cond, expr!(:supports_condition_in_parens), op)
        end
        cond
      end
      def supports_condition_in_parens
        interp = supports_interpolation
        return interp if interp
        return unless tok(/\(/); ss
        if (cond = supports_condition)
          tok!(/\)/); ss
          cond
        else
          name = sass_script(:parse)
          tok!(/:/); ss
          value = sass_script(:parse)
          tok!(/\)/); ss
          Sass::Supports::Declaration.new(name, value)
        end
      end
      def supports_declaration_condition
        return unless tok(/\(/); ss
        supports_declaration_body
      end
      def supports_interpolation
        interp = interpolation
        return unless interp
        ss
        Sass::Supports::Interpolation.new(interp)
      end
      def variable
        return unless tok(/\$/)
        start_pos = source_position
        name = tok!(IDENT)
        ss; tok!(/:/); ss
        expr = sass_script(:parse)
        while tok(/!/)
          flag_name = tok!(IDENT)
          if flag_name == 'default'
            guarded ||= true
          elsif flag_name == 'global'
            global ||= true
          else
            raise Sass::SyntaxError.new("Invalid flag \"!#{flag_name}\".", :line => @line)
          end
          ss
        end
        result = Sass::Tree::VariableNode.new(name, expr, guarded, global)
        node(result, start_pos)
      end
      def operator
        str {ss if tok(/[\/,:.=]/)}
      end
      def ruleset
        start_pos = source_position
        return unless (rules = almost_any_value)
        block(node(
          Sass::Tree::RuleNode.new(rules, range(start_pos)), start_pos), :ruleset)
      end
      def block(node, context)
        node.has_children = true
        tok!(/\{/)
        block_contents(node, context)
        tok!(/\}/)
        node
      end
      def block_contents(node, context)
        block_given? ? yield : ss_comments(node)
        node << (child = block_child(context))
        while tok(/;/) || has_children?(child)
          block_given? ? yield : ss_comments(node)
          node << (child = block_child(context))
        end
        node
      end
      def block_child(context)
        return variable || directive if context == :function
        return variable || directive || ruleset if context == :stylesheet
        variable || directive || declaration_or_ruleset
      end
      def has_children?(child_or_array)
        return false unless child_or_array
        return child_or_array.last.has_children if child_or_array.is_a?(Array)
        child_or_array.has_children
      end
      def declaration_or_ruleset
        start_pos = source_position
        declaration = try_declaration
        if declaration.nil?
          return unless (selector = almost_any_value)
        elsif declaration.is_a?(Array)
          selector = declaration
        else
          return declaration
        end
        if (additional_selector = almost_any_value)
          selector << additional_selector
        end
        block(node(
          Sass::Tree::RuleNode.new(merge(selector), range(start_pos)), start_pos), :ruleset)
      end
      def try_declaration
        name_start_pos = source_position
        if (s = tok(/[:\*\.]|\#(?!\{)/))
          name = [s, str {ss}]
          return name unless (ident = interp_ident)
          name << ident
        else
          return unless (name = interp_ident)
          name = Array(name)
        end
        if (comment = tok(COMMENT))
          name << comment
        end
        name_end_pos = source_position
        mid = [str {ss}]
        return name + mid unless tok(/:/)
        mid << ':'
        return name + mid + [':'] if tok(/:/)
        mid << str {ss}
        post_colon_whitespace = !mid.last.empty?
        could_be_selector = !post_colon_whitespace && (tok?(IDENT_START) || tok?(INTERP_START))
        value_start_pos = source_position
        value = nil
        error = catch_error do
          value = value!
          if tok?(/\{/)
            tok!(/;/) if could_be_selector
          elsif !tok?(/[;{}]/)
            tok!(/[;{}]/)
          end
        end
        if error
          rethrow error unless could_be_selector
          additional_selector = almost_any_value
          rethrow error if tok?(/;/)
          return name + mid + (additional_selector || [])
        end
        value_end_pos = source_position
        ss
        require_block = tok?(/\{/)
        node = node(Sass::Tree::PropNode.new(name.flatten.compact, value, :new),
                    name_start_pos, value_end_pos)
        node.name_source_range = range(name_start_pos, name_end_pos)
        node.value_source_range = range(value_start_pos, value_end_pos)
        return node unless require_block
        nested_properties! node
      end
      def almost_any_value
        return unless (tok = almost_any_value_token)
        sel = [tok]
        while (tok = almost_any_value_token)
          sel << tok
        end
        merge(sel)
      end
      def almost_any_value_token
        tok(%r{
          (
            \\.
          |
            (?!url\()
            [^"'/\#!;\{\}] # "
          |
            /(?![/*])
          |
            \#(?!\{)
          |
            !(?![a-z]) # TODO: never consume "!" when issue 1126 is fixed.
          )+
        }xi) || tok(COMMENT) || tok(SINGLE_LINE_COMMENT) || interp_string || interp_uri ||
                interpolation(:warn_for_color)
      end
      def declaration
        name_start_pos = source_position
        if (s = tok(/[:\*\.]|\#(?!\{)/))
          name = [s, str {ss}, *expr!(:interp_ident)]
        else
          return unless (name = interp_ident)
          name = Array(name)
        end
        if (comment = tok(COMMENT))
          name << comment
        end
        name_end_pos = source_position
        ss
        tok!(/:/)
        ss
        value_start_pos = source_position
        value = value!
        value_end_pos = source_position
        ss
        require_block = tok?(/\{/)
        node = node(Sass::Tree::PropNode.new(name.flatten.compact, value, :new),
                    name_start_pos, value_end_pos)
        node.name_source_range = range(name_start_pos, name_end_pos)
        node.value_source_range = range(value_start_pos, value_end_pos)
        return node unless require_block
        nested_properties! node
      end
      def value!
        if tok?(/\{/)
          str = Sass::Script::Tree::Literal.new(Sass::Script::Value::String.new(""))
          str.line = source_position.line
          str.source_range = range(source_position)
          return str
        end
        start_pos = source_position
        if (val = tok(STATIC_VALUE, true))
          str = Sass::Script::Tree::Literal.new(Sass::Script::Value::String.new(val.strip))
          str.line = start_pos.line
          str.source_range = range(start_pos)
          return str
        end
        sass_script(:parse)
      end
      def nested_properties!(node)
        @expected = 'expression (e.g. 1px, bold) or "{"'
        block(node, :property)
      end
      def expr(allow_var = true)
        t = term(allow_var)
        return unless t
        res = [t, str {ss}]
        while (o = operator) && (t = term(allow_var))
          res << o << t << str {ss}
        end
        res.flatten
      end
      def term(allow_var)
        e = tok(NUMBER) ||
            interp_uri ||
            function(allow_var) ||
            interp_string ||
            tok(UNICODERANGE) ||
            interp_ident ||
            tok(HEXCOLOR) ||
            (allow_var && var_expr)
        return e if e
        op = tok(/[+-]/)
        return unless op
        @expected = "number or function"
        [op,
         tok(NUMBER) || function(allow_var) || (allow_var && var_expr) || expr!(:interpolation)]
      end
      def function(allow_var)
        name = tok(FUNCTION)
        return unless name
        if name == "expression(" || name == "calc("
          str, _ = Sass::Shared.balance(@scanner, ?(, ?), 1)
          [name, str]
        else
          [name, str {ss}, expr(allow_var), tok!(/\)/)]
        end
      end
      def var_expr
        return unless tok(/\$/)
        line = @line
        var = Sass::Script::Tree::Variable.new(tok!(IDENT))
        var.line = line
        var
      end
      def interpolation(warn_for_color = false)
        return unless tok(INTERP_START)
        sass_script(:parse_interpolated, warn_for_color)
      end
      def string
        return unless tok(STRING)
        Sass::Script::Value::String.value(@scanner[1] || @scanner[2])
      end
      def interp_string
        _interp_string(:double) || _interp_string(:single)
      end
      def interp_uri
        _interp_string(:uri)
      end
      def _interp_string(type)
        start = tok(Sass::Script::Lexer::STRING_REGULAR_EXPRESSIONS[type][false])
        return unless start
        res = [start]
        mid_re = Sass::Script::Lexer::STRING_REGULAR_EXPRESSIONS[type][true]
        while @scanner[2] == '#{'
          @scanner.pos -= 2 # Don't consume the #{
          res.last.slice!(-2..-1)
          res << expr!(:interpolation) << tok(mid_re)
        end
        res
      end
      def interp_ident(start = IDENT)
        val = tok(start) || interpolation(:warn_for_color) || tok(IDENT_HYPHEN_INTERP, true)
        return unless val
        res = [val]
        while (val = tok(NAME) || interpolation(:warn_for_color))
          res << val
        end
        res
      end
      def interp_ident_or_var
        id = interp_ident
        return id if id
        var = var_expr
        return [var] if var
      end
      def str
        @strs.push ""
        yield
        @strs.last
      ensure
        @strs.pop
      end
      def str?
        pos = @scanner.pos
        line = @line
        offset = @offset
        @strs.push ""
        throw_error {yield} && @strs.last
      rescue Sass::SyntaxError
        @scanner.pos = pos
        @line = line
        @offset = offset
        nil
      ensure
        @strs.pop
      end
      def node(node, start_pos, end_pos = source_position)
        node.line = start_pos.line
        node.source_range = range(start_pos, end_pos)
        node
      end
      @sass_script_parser = Class.new(Sass::Script::Parser)
      @sass_script_parser.send(:include, ScriptParser)
      class << self
        attr_accessor :sass_script_parser
      end
      def sass_script(*args)
        parser = self.class.sass_script_parser.new(@scanner, @line, @offset,
                                                   :filename => @filename, :importer => @importer)
        result = parser.send(*args)
        unless @strs.empty?
          src = result.to_sass
          @strs.each {|s| s << src}
        end
        @line = parser.line
        @offset = parser.offset
        result
      rescue Sass::SyntaxError => e
        throw(:_sass_parser_error, true) if @throw_error
        raise e
      end
      def merge(arr)
        arr && Sass::Util.merge_adjacent_strings([arr].flatten)
      end
      EXPR_NAMES = {
        :media_query => "media query (e.g. print, screen, print and screen)",
        :media_query_list => "media query (e.g. print, screen, print and screen)",
        :media_expr => "media expression (e.g. (min-device-width: 800px))",
        :at_root_query => "@at-root query (e.g. (without: media))",
        :at_root_directive_list => '* or identifier',
        :pseudo_args => "expression (e.g. fr, 2n+1)",
        :interp_ident => "identifier",
        :qualified_name => "identifier",
        :expr => "expression (e.g. 1px, bold)",
        :selector_comma_sequence => "selector",
        :string => "string",
        :import_arg => "file to import (string or url())",
        :moz_document_function => "matching function (e.g. url-prefix(), domain())",
        :supports_condition => "@supports condition (e.g. (display: flexbox))",
        :supports_condition_in_parens => "@supports condition (e.g. (display: flexbox))",
        :a_n_plus_b => "An+B expression",
        :keyframes_selector_component => "from, to, or a percentage",
        :keyframes_selector => "keyframes selector (e.g. 10%)"
      }
      TOK_NAMES = Sass::Util.to_hash(Sass::SCSS::RX.constants.map do |c|
        [Sass::SCSS::RX.const_get(c), c.downcase]
      end).merge(
        IDENT => "identifier",
        /[;{}]/ => '";"',
        /\b(without|with)\b/ => '"with" or "without"'
      )
      def tok?(rx)
        @scanner.match?(rx)
      end
      def expr!(name)
        e = send(name)
        return e if e
        expected(EXPR_NAMES[name] || name.to_s)
      end
      def tok!(rx)
        t = tok(rx)
        return t if t
        name = TOK_NAMES[rx]
        unless name
          source = rx.source.gsub(/\\\//, '/')
          string = rx.source.gsub(/\\(.)/, '\1')
          name = source == Regexp.escape(string) ? string.inspect : rx.inspect
        end
        expected(name)
      end
      def expected(name)
        throw(:_sass_parser_error, true) if @throw_error
        self.class.expected(@scanner, @expected || name, @line)
      end
      def err(msg)
        throw(:_sass_parser_error, true) if @throw_error
        raise Sass::SyntaxError.new(msg, :line => @line)
      end
      def throw_error
        old_throw_error, @throw_error = @throw_error, false
        yield
      ensure
        @throw_error = old_throw_error
      end
      def catch_error(&block)
        old_throw_error, @throw_error = @throw_error, true
        pos = @scanner.pos
        line = @line
        offset = @offset
        expected = @expected
        if catch(:_sass_parser_error) {yield; false}
          @scanner.pos = pos
          @line = line
          @offset = offset
          @expected = expected
          {:pos => pos, :line => line, :expected => @expected, :block => block}
        end
      ensure
        @throw_error = old_throw_error
      end
      def rethrow(err)
        if @throw_error
          throw :_sass_parser_error, err
        else
          @scanner = Sass::Util::MultibyteStringScanner.new(@scanner.string)
          @scanner.pos = err[:pos]
          @line = err[:line]
          @expected = err[:expected]
          err[:block].call
        end
      end
      def self.expected(scanner, expected, line)
        pos = scanner.pos
        after = scanner.string[0...pos]
        after.gsub!(/\s*\n\s*$/, '')
        after.gsub!(/.*\n/, '')
        after = "..." + after[-15..-1] if after.size > 18
        was = scanner.rest.dup
        was.gsub!(/^\s*\n\s*/, '')
        was.gsub!(/\n.*/, '')
        was = was[0...15] + "..." if was.size > 18
        raise Sass::SyntaxError.new(
          "Invalid CSS after \"#{after}\": expected #{expected}, was \"#{was}\"",
          :line => line)
      end
      NEWLINE = "\n"
      def tok(rx, last_group_lookahead = false)
        res = @scanner.scan(rx)
        if res
          if last_group_lookahead #BT+
			lastgroup = rx.match( @scanner.matched )[-1] #BT+
			if lastgroup #BT+
			  @scanner.pos -= lastgroup.length #BT+
			  res.slice!(-lastgroup.length..-1) #BT+
			end #BT+
          end
          newline_count = res.count(NEWLINE)
          if newline_count > 0
            @line += newline_count
            @offset = res[res.rindex(NEWLINE)..-1].size
          else
            @offset += res.size
          end
          @expected = nil
          if !@strs.empty? && rx != COMMENT && rx != SINGLE_LINE_COMMENT
            @strs.each {|s| s << res}
          end
          res
        end
      end
      def deprefix(str)
        str.gsub(/^-[a-zA-Z0-9]+-/, '')
      end
    end
  end
end
module Sass
  module Script
    class CssLexer < Lexer
      private
      def token
        important || super
      end
      def string(re, *args)
        if re == :uri
          uri = scan(URI)
          return unless uri
          return [:string, Script::Value::String.new(uri)]
        end
        return unless scan(STRING)
        string_value = Sass::Script::Value::String.value(@scanner[1] || @scanner[2])
        value = Script::Value::String.new(string_value, :string)
        [:string, value]
      end
      def important
        s = scan(IMPORTANT)
        return unless s
        [:raw, s]
      end
    end
  end
end
module Sass
  module Script
    class CssParser < Parser
      private
      def lexer_class; CssLexer; end
      production :div, :unary_plus, :div
      def string
        tok = try_tok(:string)
        return number unless tok
        unless @lexer.peek && @lexer.peek.type == :begin_interpolation
          return literal_node(tok.value, tok.source_range)
        end
      end
      alias_method :interpolation, :space
      alias_method :or_expr, :div
      alias_method :unary_div, :ident
      alias_method :paren, :string
    end
  end
end
module Sass
  module SCSS
    class StaticParser < Parser
      def parse_selector
        init_scanner!
        seq = expr!(:selector_comma_sequence)
        expected("selector") unless @scanner.eos?
        seq.line = @line
        seq.filename = @filename
        seq
      end
      def parse_static_at_root_query
        init_scanner!
        tok!(/\(/); ss
        type = tok!(/\b(without|with)\b/).to_sym; ss
        tok!(/:/); ss
        directives = expr!(:at_root_directive_list); ss
        tok!(/\)/)
        expected("@at-root query list") unless @scanner.eos?
        return type, directives
      end
      def parse_keyframes_selector
        init_scanner!
        sel = expr!(:keyframes_selector)
        expected("keyframes selector") unless @scanner.eos?
        sel
      end
      def initialize(str, filename, importer, line = 1, offset = 1, allow_parent_ref = true)
        super(str, filename, importer, line, offset)
        @allow_parent_ref = allow_parent_ref
      end
      private
      def moz_document_function
        val = tok(URI) || tok(URL_PREFIX) || tok(DOMAIN) || function(!:allow_var)
        return unless val
        ss
        [val]
      end
      def variable; nil; end
      def script_value; nil; end
      def interpolation(warn_for_color = false); nil; end
      def var_expr; nil; end
      def interp_string; (s = tok(STRING)) && [s]; end
      def interp_uri; (s = tok(URI)) && [s]; end
      def interp_ident(ident = IDENT); (s = tok(ident)) && [s]; end
      def use_css_import?; true; end
      def special_directive(name, start_pos)
        return unless %w[media import charset -moz-document].include?(name)
        super
      end
      def selector_comma_sequence
        sel = selector
        return unless sel
        selectors = [sel]
        ws = ''
        while tok(/,/)
          ws << str {ss}
          if (sel = selector)
            selectors << sel
            if ws.include?("\n")
              selectors[-1] = Selector::Sequence.new(["\n"] + selectors.last.members)
            end
            ws = ''
          end
        end
        Selector::CommaSequence.new(selectors)
      end
      def selector_string
        sel = selector
        return unless sel
        sel.to_s
      end
      def selector
        start_pos = source_position
        val = combinator || simple_selector_sequence
        return unless val
        nl = str {ss}.include?("\n")
        res = []
        res << val
        res << "\n" if nl
        while (val = combinator || simple_selector_sequence)
          res << val
          res << "\n" if str {ss}.include?("\n")
        end
        seq = Selector::Sequence.new(res.compact)
        if seq.members.any? {|sseq| sseq.is_a?(Selector::SimpleSequence) && sseq.subject?}
          location = " of #{@filename}" if @filename
          Sass::Util.sass_warn <<MESSAGE
DEPRECATION WARNING on line #{start_pos.line}, column #{start_pos.offset}#{location}:
The subject selector operator "!" is deprecated and will be removed in a future release.
This operator has been replaced by ":has()" in the CSS spec.
For example: #{seq.subjectless}
MESSAGE
        end
        seq
      end
      def combinator
        tok(PLUS) || tok(GREATER) || tok(TILDE) || reference_combinator
      end
      def reference_combinator
        return unless tok(/\//)
        res = '/'
        ns, name = expr!(:qualified_name)
        res << ns << '|' if ns
        res << name << tok!(/\//)
        res
      end
      def simple_selector_sequence
        start_pos = source_position
        e = element_name || id_selector || class_selector || placeholder_selector || attrib ||
            pseudo || parent_selector
        return unless e
        res = [e]
        while (v = id_selector || class_selector || placeholder_selector ||
                   attrib || pseudo || (tok(/\*/) && Selector::Universal.new(nil)))
          res << v
        end
        pos = @scanner.pos
        line = @line
        if (sel = str? {simple_selector_sequence})
          @scanner.pos = pos
          @line = line
          begin
            expected('"{"') if res.length == 1 && res[0].is_a?(Selector::Universal)
            throw_error {expected('"{"')}
          rescue Sass::SyntaxError => e
            e.message << "\n\n\"#{sel}\" may only be used at the beginning of a compound selector."
            raise e
          end
        end
        Selector::SimpleSequence.new(res, tok(/!/), range(start_pos))
      end
      def parent_selector
        return unless @allow_parent_ref && tok(/&/)
        Selector::Parent.new(tok(NAME))
      end
      def class_selector
        return unless tok(/\./)
        @expected = "class name"
        Selector::Class.new(tok!(IDENT))
      end
      def id_selector
        return unless tok(/#(?!\{)/)
        @expected = "id name"
        Selector::Id.new(tok!(NAME))
      end
      def placeholder_selector
        return unless tok(/%/)
        @expected = "placeholder name"
        Selector::Placeholder.new(tok!(IDENT))
      end
      def element_name
        ns, name = Sass::Util.destructure(qualified_name(:allow_star_name))
        return unless ns || name
        if name == '*'
          Selector::Universal.new(ns)
        else
          Selector::Element.new(name, ns)
        end
      end
      def qualified_name(allow_star_name = false)
        name = tok(IDENT) || tok(/\*/) || (tok?(/\|/) && "")
        return unless name
        return nil, name unless tok(/\|/)
        return name, tok!(IDENT) unless allow_star_name
        @expected = "identifier or *"
        return name, tok(IDENT) || tok!(/\*/)
      end
      def attrib
        return unless tok(/\[/)
        ss
        ns, name = attrib_name!
        ss
        op = tok(/=/) ||
             tok(INCLUDES) ||
             tok(DASHMATCH) ||
             tok(PREFIXMATCH) ||
             tok(SUFFIXMATCH) ||
             tok(SUBSTRINGMATCH)
        if op
          @expected = "identifier or string"
          ss
          val = tok(IDENT) || tok!(STRING)
          ss
        end
        flags = tok(IDENT) || tok(STRING)
        tok!(/\]/)
        Selector::Attribute.new(name, ns, op, val, flags)
      end
      def attrib_name!
        if (name_or_ns = tok(IDENT))
          if tok(/\|(?!=)/)
            ns = name_or_ns
            name = tok(IDENT)
          else
            name = name_or_ns
          end
        else
          ns = tok(/\*/) || ""
          tok!(/\|/)
          name = tok!(IDENT)
        end
        return ns, name
      end
      SELECTOR_PSEUDO_CLASSES = %w[not matches current any has host host-context].to_set
      PREFIXED_SELECTOR_PSEUDO_CLASSES = %w[nth-child nth-last-child].to_set
      def pseudo
        s = tok(/::?/)
        return unless s
        @expected = "pseudoclass or pseudoelement"
        name = tok!(IDENT)
        if tok(/\(/)
          ss
          deprefixed = deprefix(name)
          if s == ':' && SELECTOR_PSEUDO_CLASSES.include?(deprefixed)
            sel = selector_comma_sequence
          elsif s == ':' && PREFIXED_SELECTOR_PSEUDO_CLASSES.include?(deprefixed)
            arg, sel = prefixed_selector_pseudo
          else
            arg = expr!(:pseudo_args)
          end
          tok!(/\)/)
        end
        Selector::Pseudo.new(s == ':' ? :class : :element, name, arg, sel)
      end
      def pseudo_args
        arg = expr!(:pseudo_expr)
        while tok(/,/)
          arg << ',' << str {ss}
          arg.concat expr!(:pseudo_expr)
        end
        arg
      end
      def pseudo_expr
        res = pseudo_expr_token
        return unless res
        res << str {ss}
        while (e = pseudo_expr_token)
          res << e << str {ss}
        end
        res
      end
      def pseudo_expr_token
        tok(PLUS) || tok(/[-*]/) || tok(NUMBER) || tok(STRING) || tok(IDENT)
      end
      def prefixed_selector_pseudo
        prefix = str do
          expr = str {expr!(:a_n_plus_b)}
          ss
          return expr, nil unless tok(/of/)
          ss
        end
        return prefix, expr!(:selector_comma_sequence)
      end
      def a_n_plus_b
        if (parity = tok(/even|odd/i))
          return parity
        end
        if tok(/[+-]?[0-9]+/)
          ss
          return true unless tok(/n/)
        else
          return unless tok(/[+-]?n/i)
        end
        ss
        return true unless tok(/[+-]/)
        ss
        @expected = "number"
        tok!(/[0-9]+/)
        true
      end
      def keyframes_selector
        ss
        str do
          return unless keyframes_selector_component
          ss
          while tok(/,/)
            ss
            expr!(:keyframes_selector_component)
            ss
          end
        end
      end
      def keyframes_selector_component
        tok(IDENT) || tok(PERCENTAGE)
      end
      @sass_script_parser = Class.new(Sass::Script::CssParser)
      @sass_script_parser.send(:include, ScriptParser)
    end
  end
end
module Sass
  module SCSS
    class CssParser < StaticParser
      private
      def placeholder_selector; nil; end
      def parent_selector; nil; end
      def interpolation(warn_for_color = false); nil; end
      def use_css_import?; true; end
      def block_child(context)
        case context
        when :ruleset
          declaration
        when :stylesheet
          directive || ruleset
        when :directive
          directive || declaration_or_ruleset
        end
      end
      def nested_properties!(node)
        expected('expression (e.g. 1px, bold)')
      end
      def ruleset
        start_pos = source_position
        return unless (selector = selector_comma_sequence)
        block(node(Sass::Tree::RuleNode.new(selector, range(start_pos)), start_pos), :ruleset)
      end
      @sass_script_parser = Class.new(Sass::Script::CssParser)
      @sass_script_parser.send(:include, ScriptParser)
    end
  end
end
module Sass
  module SCSS; end
end
module Sass
  class Stack
    class Frame
      attr_reader :filename
      attr_reader :line
      attr_reader :type
      attr_reader :name
      def initialize(filename, line, type, name = nil)
        @filename = filename
        @line = line
        @type = type
        @name = name
      end
      def is_import?
        type == :import
      end
      def is_mixin?
        type == :mixin
      end
      def is_base?
        type == :base
      end
    end
    attr_reader :frames
    def initialize
      @frames = []
    end
    def with_base(filename, line)
      with_frame(filename, line, :base) {yield}
    end
    def with_import(filename, line)
      with_frame(filename, line, :import) {yield}
    end
    def with_mixin(filename, line, name)
      with_frame(filename, line, :mixin, name) {yield}
    end
    def to_s
      Sass::Util.enum_with_index(Sass::Util.enum_cons(frames.reverse + [nil], 2)).
          map do |(frame, caller), i|
        "#{i == 0 ? "on" : "from"} line #{frame.line}" +
          " of #{frame.filename || "an unknown file"}" +
          (caller && caller.name ? ", in `#{caller.name}'" : "")
      end.join("\n")
    end
    private
    def with_frame(filename, line, type, name = nil)
      @frames.pop if @frames.last && @frames.last.type == :base
      @frames.push(Frame.new(filename, line, type, name))
      yield
    ensure
      @frames.pop unless type == :base && @frames.last && @frames.last.type != :base
    end
  end
end
module Sass
  class SyntaxError < StandardError
    attr_accessor :sass_backtrace
    attr_accessor :sass_template
    def initialize(msg, attrs = {})
      @message = msg
      @sass_backtrace = []
      add_backtrace(attrs)
    end
    def sass_filename
      sass_backtrace.first[:filename]
    end
    def sass_mixin
      sass_backtrace.first[:mixin]
    end
    def sass_line
      sass_backtrace.first[:line]
    end
    def add_backtrace(attrs)
      sass_backtrace << attrs.reject {|k, v| v.nil?}
    end
    def modify_backtrace(attrs)
      attrs = attrs.reject {|k, v| v.nil?}
      (0...sass_backtrace.size).to_a.reverse.each do |i|
        entry = sass_backtrace[i]
        sass_backtrace[i] = attrs.merge(entry)
        attrs.reject! {|k, v| entry.include?(k)}
        break if attrs.empty?
      end
    end
    def to_s
      @message
    end
    def backtrace
      return nil if super.nil?
      return super if sass_backtrace.all? {|h| h.empty?}
      sass_backtrace.map do |h|
        "#{h[:filename] || "(sass)"}:#{h[:line]}" +
          (h[:mixin] ? ":in `#{h[:mixin]}'" : "")
      end + super
    end
    def sass_backtrace_str(default_filename = "an unknown file")
      lines = message.split("\n")
      msg = lines[0] + lines[1..-1].
        map {|l| "\n" + (" " * "Error: ".size) + l}.join
      "Error: #{msg}" +
        Sass::Util.enum_with_index(sass_backtrace).map do |entry, i|
          "\n        #{i == 0 ? "on" : "from"} line #{entry[:line]}" +
            " of #{entry[:filename] || default_filename}" +
            (entry[:mixin] ? ", in `#{entry[:mixin]}'" : "")
        end.join
    end
    class << self
      def exception_to_css(e, line_offset = 1)
        header = header_string(e, line_offset)
        <<END
/*
Backtrace:\n#{e.backtrace.join("\n").gsub("*/", "*\\/")}
*/
body:before {
  white-space: pre;
  font-family: monospace;
  content: "#{header.gsub('"', '\"').gsub("\n", '\\A ')}"; }
END
      end
      private
      def header_string(e, line_offset)
        unless e.is_a?(Sass::SyntaxError) && e.sass_line && e.sass_template
          return "#{e.class}: #{e.message}"
        end
        line_num = e.sass_line + 1 - line_offset
        min = [line_num - 6, 0].max
        section = e.sass_template.rstrip.split("\n")[min ... line_num + 5]
        return e.sass_backtrace_str if section.nil? || section.empty?
        e.sass_backtrace_str + "\n\n" + Sass::Util.enum_with_index(section).
          map {|line, i| "#{line_offset + min + i}: #{line}"}.join("\n")
      end
    end
  end
  class UnitConversionError < SyntaxError; end
end
module Sass
  module Importers
  end
end
module Sass
  module Importers
    class Base
      def find_relative(uri, base, options)
        Sass::Util.abstract(self)
      end
      def find(uri, options)
        Sass::Util.abstract(self)
      end
      def mtime(uri, options)
        Sass::Util.abstract(self)
      end
      def key(uri, options)
        Sass::Util.abstract(self)
      end
      def public_url(uri, sourcemap_directory)
        return if @public_url_warning_issued
        @public_url_warning_issued = true
        Sass::Util.sass_warn <<WARNING
WARNING: #{self.class.name} should define the #public_url method.
WARNING
        nil
      end
      def to_s
        Sass::Util.abstract(self)
      end
      def directories_to_watch
        []
      end
      def watched_file?(filename)
        false
      end
    end
  end
end
module Sass
  module Importers
    class Filesystem < Base
      attr_accessor :root
      def initialize(root)
        @root = File.expand_path(root)
        @real_root = Sass::Util.realpath(@root).to_s
        @same_name_warnings = Set.new
      end
      def find_relative(name, base, options)
        _find(File.dirname(base), name, options)
      end
      def find(name, options)
        _find(@root, name, options)
      end
      def mtime(name, options)
        file, _ = Sass::Util.destructure(find_real_file(@root, name, options))
        File.mtime(file) if file
      rescue Errno::ENOENT
        nil
      end
      def key(name, options)
        [self.class.name + ":" + File.dirname(File.expand_path(name)),
         File.basename(name)]
      end
      def to_s
        @root
      end
      def hash
        @root.hash
      end
      def eql?(other)
        !other.nil? && other.respond_to?(:root) && root.eql?(other.root)
      end
      def directories_to_watch
        [root]
      end
      def watched_file?(filename)
        filename =~ /\.s[ac]ss$/ && filename.start_with?(@real_root + File::SEPARATOR)
      end
      def public_url(name, sourcemap_directory)
        file_pathname = Sass::Util.cleanpath(Sass::Util.absolute_path(name, @root))
        return Sass::Util.file_uri_from_path(file_pathname) if sourcemap_directory.nil?
        sourcemap_pathname = Sass::Util.cleanpath(sourcemap_directory)
        begin
          Sass::Util.file_uri_from_path(
            Sass::Util.relative_path_from(file_pathname, sourcemap_pathname))
        rescue ArgumentError # when a relative path cannot be constructed
          Sass::Util.file_uri_from_path(file_pathname)
        end
      end
      protected
      def remove_root(name)
        if name.index(@root + "/") == 0
          name[(@root.length + 1)..-1]
        else
          name
        end
      end
      def extensions
        {'sass' => :sass, 'scss' => :scss}
      end
      def possible_files(name)
        name = escape_glob_characters(name)
        dirname, basename, extname = split(name)
        sorted_exts = extensions.sort
        syntax = extensions[extname]
        if syntax
          ret = [["#{dirname}/{_,}#{basename}.#{extensions.invert[syntax]}", syntax]]
        else
          ret = sorted_exts.map {|ext, syn| ["#{dirname}/{_,}#{basename}.#{ext}", syn]}
        end
        ret.map {|f, s| [f.sub(/^\.\//, ''), s]}
      end
      def escape_glob_characters(name)
        name.gsub(/[\*\[\]\{\}\?]/) do |char|
          "\\#{char}"
        end
      end
      REDUNDANT_DIRECTORY = /#{Regexp.escape(File::SEPARATOR)}\.#{Regexp.escape(File::SEPARATOR)}/
      def find_real_file(dir, name, options)
        dir = dir.gsub(File::ALT_SEPARATOR, File::SEPARATOR) unless File::ALT_SEPARATOR.nil?
        name = name.gsub(File::ALT_SEPARATOR, File::SEPARATOR) unless File::ALT_SEPARATOR.nil?
        found = possible_files(remove_root(name)).map do |f, s|
          path = (dir == "." || Sass::Util.pathname(f).absolute?) ? f :
            "#{escape_glob_characters(dir)}/#{f}"
          Dir[path].map do |full_path|
            full_path.gsub!(REDUNDANT_DIRECTORY, File::SEPARATOR)
            [Sass::Util.cleanpath(full_path).to_s, s]
          end
        end
        found = Sass::Util.flatten(found, 1)
        return if found.empty?
        if found.size > 1 && !@same_name_warnings.include?(found.first.first)
          found.each {|(f, _)| @same_name_warnings << f}
          relative_to = Sass::Util.pathname(dir)
          if options[:_from_import_node]
            candidates = found.map do |(f, _)|
              "  " + Sass::Util.pathname(f).relative_path_from(relative_to).to_s
            end.join("\n")
            raise Sass::SyntaxError.new(<<MESSAGE)
It's not clear which file to import for '@import "#{name}"'.
Candidates:
Please delete or rename all but one of these files.
MESSAGE
          else
            candidates = found.map {|(f, _)| "    " + File.basename(f)}.join("\n")
            Sass::Util.sass_warn <<WARNING
WARNING: In #{File.dirname(name)}:
  There are multiple files that match the name "#{File.basename(name)}":
WARNING
          end
        end
        found.first
      end
      def split(name)
        extension = nil
        dirname, basename = File.dirname(name), File.basename(name)
        if basename =~ /^(.*)\.(#{extensions.keys.map {|e| Regexp.escape(e)}.join('|')})$/
          basename = $1
          extension = $2
        end
        [dirname, basename, extension]
      end
      private
      def _find(dir, name, options)
        full_filename, syntax = Sass::Util.destructure(find_real_file(dir, name, options))
        full_filename = full_filename.tr("\\", "/") #BT+
        return unless full_filename
        full_filename = full_filename.tr("\\", "/") if Sass::Util.windows?
        options[:syntax] = syntax
        options[:filename] = full_filename
        options[:importer] = self
        Sass::Engine.new(File.read(full_filename), options)
      end
    end
  end
end
module Sass
  module Shared
    extend self
    def handle_interpolation(str)
      scan = Sass::Util::MultibyteStringScanner.new(str)
      yield scan while scan.scan(/(.*?)(\\*)\#\{/m)
      scan.rest
    end
    def balance(scanner, start, finish, count = 0)
      str = ''
      scanner = Sass::Util::MultibyteStringScanner.new(scanner) unless scanner.is_a? StringScanner
      regexp = Regexp.new("(.*?)[\\#{start.chr}\\#{finish.chr}]", Regexp::MULTILINE)
      while scanner.scan(regexp)
        str << scanner.matched
        count += 1 if scanner.matched[-1] == start
        count -= 1 if scanner.matched[-1] == finish
        return [str, scanner.rest] if count == 0
      end
    end
    def human_indentation(indentation, was = false)
      if !indentation.include?(?\t)
        noun = 'space'
      elsif !indentation.include?(?\s)
        noun = 'tab'
      else
        return indentation.inspect + (was ? ' was' : '')
      end
      singular = indentation.length == 1
      if was
        was = singular ? ' was' : ' were'
      else
        was = ''
      end
      "#{indentation.length} #{noun}#{'s' unless singular}#{was}"
    end
  end
end
module Sass::Media
  class QueryList
    attr_accessor :queries
    def initialize(queries)
      @queries = queries
    end
    def merge(other)
      new_queries = queries.map {|q1| other.queries.map {|q2| q1.merge(q2)}}.flatten.compact
      return if new_queries.empty?
      QueryList.new(new_queries)
    end
    def to_css
      queries.map {|q| q.to_css}.join(', ')
    end
    def to_src(options)
      queries.map {|q| q.to_src(options)}.join(', ')
    end
    def to_a
      Sass::Util.intersperse(queries.map {|q| q.to_a}, ', ').flatten
    end
    def deep_copy
      QueryList.new(queries.map {|q| q.deep_copy})
    end
  end
  class Query
    attr_accessor :modifier
    attr_accessor :type
    attr_accessor :expressions
    def initialize(modifier, type, expressions)
      @modifier = modifier
      @type = type
      @expressions = expressions
    end
    def resolved_modifier
      modifier.first || ''
    end
    def resolved_type
      type.first || ''
    end
    def merge(other)
      m1, t1 = resolved_modifier.downcase, resolved_type.downcase
      m2, t2 = other.resolved_modifier.downcase, other.resolved_type.downcase
      t1 = t2 if t1.empty?
      t2 = t1 if t2.empty?
      if (m1 == 'not') ^ (m2 == 'not')
        return if t1 == t2
        type = m1 == 'not' ? t2 : t1
        mod = m1 == 'not' ? m2 : m1
      elsif m1 == 'not' && m2 == 'not'
        return unless t1 == t2
        type = t1
        mod = 'not'
      elsif t1 != t2
        return
      else # t1 == t2, neither m1 nor m2 are "not"
        type = t1
        mod = m1.empty? ? m2 : m1
      end
      Query.new([mod], [type], other.expressions + expressions)
    end
    def to_css
      css = ''
      css << resolved_modifier
      css << ' ' unless resolved_modifier.empty?
      css << resolved_type
      css << ' and ' unless resolved_type.empty? || expressions.empty?
      css << expressions.map do |e|
        e.map {|c| c.is_a?(Sass::Script::Tree::Node) ? c.to_sass : c.to_s}.join
      end.join(' and ')
      css
    end
    def to_src(options)
      src = ''
      src << Sass::Media._interp_to_src(modifier, options)
      src << ' ' unless modifier.empty?
      src << Sass::Media._interp_to_src(type, options)
      src << ' and ' unless type.empty? || expressions.empty?
      src << expressions.map do |e|
        Sass::Media._interp_to_src(e, options)
      end.join(' and ')
      src
    end
    def to_a
      res = []
      res += modifier
      res << ' ' unless modifier.empty?
      res += type
      res << ' and ' unless type.empty? || expressions.empty?
      res += Sass::Util.intersperse(expressions, ' and ').flatten
      res
    end
    def deep_copy
      Query.new(
        modifier.map {|c| c.is_a?(Sass::Script::Tree::Node) ? c.deep_copy : c},
        type.map {|c| c.is_a?(Sass::Script::Tree::Node) ? c.deep_copy : c},
        expressions.map {|e| e.map {|c| c.is_a?(Sass::Script::Tree::Node) ? c.deep_copy : c}})
    end
  end
  def self._interp_to_src(interp, options)
    interp.map {|r| r.is_a?(String) ? r : r.to_sass(options)}.join
  end
end
module Sass::Supports
  class Condition
    def perform(environment); Sass::Util.abstract(self); end
    def to_css; Sass::Util.abstract(self); end
    def to_src(options); Sass::Util.abstract(self); end
    def deep_copy; Sass::Util.abstract(self); end
    def options=(options); Sass::Util.abstract(self); end
  end
  class Operator < Condition
    attr_accessor :left
    attr_accessor :right
    attr_accessor :op
    def initialize(left, right, op)
      @left = left
      @right = right
      @op = op
    end
    def perform(env)
      @left.perform(env)
      @right.perform(env)
    end
    def to_css
      "#{left_parens @left.to_css} #{op} #{right_parens @right.to_css}"
    end
    def to_src(options)
      "#{left_parens @left.to_src(options)} #{op} #{right_parens @right.to_src(options)}"
    end
    def deep_copy
      copy = dup
      copy.left = @left.deep_copy
      copy.right = @right.deep_copy
      copy
    end
    def options=(options)
      @left.options = options
      @right.options = options
    end
    private
    def left_parens(str)
      return "(#{str})" if @left.is_a?(Negation)
      str
    end
    def right_parens(str)
      return "(#{str})" if @right.is_a?(Negation) || @right.is_a?(Operator)
      str
    end
  end
  class Negation < Condition
    attr_accessor :condition
    def initialize(condition)
      @condition = condition
    end
    def perform(env)
      @condition.perform(env)
    end
    def to_css
      "not #{parens @condition.to_css}"
    end
    def to_src(options)
      "not #{parens @condition.to_src(options)}"
    end
    def deep_copy
      copy = dup
      copy.condition = condition.deep_copy
      copy
    end
    def options=(options)
      condition.options = options
    end
    private
    def parens(str)
      return "(#{str})" if @condition.is_a?(Negation) || @condition.is_a?(Operator)
      str
    end
  end
  class Declaration < Condition
    attr_accessor :name
    attr_accessor :resolved_name
    attr_accessor :value
    attr_accessor :resolved_value
    def initialize(name, value)
      @name = name
      @value = value
    end
    def perform(env)
      @resolved_name = name.perform(env)
      @resolved_value = value.perform(env)
    end
    def to_css
      "(#{@resolved_name}: #{@resolved_value})"
    end
    def to_src(options)
      "(#{@name.to_sass(options)}: #{@value.to_sass(options)})"
    end
    def deep_copy
      copy = dup
      copy.name = @name.deep_copy
      copy.value = @value.deep_copy
      copy
    end
    def options=(options)
      @name.options = options
      @value.options = options
    end
  end
  class Interpolation < Condition
    attr_accessor :value
    attr_accessor :resolved_value
    def initialize(value)
      @value = value
    end
    def perform(env)
      @resolved_value = value.perform(env).to_s(:quote => :none)
    end
    def to_css
      @resolved_value
    end
    def to_src(options)
      @value.to_sass(options)
    end
    def deep_copy
      copy = dup
      copy.value = @value.deep_copy
      copy
    end
    def options=(options)
      @value.options = options
    end
  end
end
module Sass
  Callable = Struct.new(:name, :args, :splat, :environment, :tree, :has_content, :type)
  class Engine
    class Line < Struct.new(:text, :tabs, :index, :offset, :filename, :children, :comment_tab_str)
      def comment?
        text[0] == COMMENT_CHAR && (text[1] == SASS_COMMENT_CHAR || text[1] == CSS_COMMENT_CHAR)
      end
    end
    PROPERTY_CHAR  = ?:
    COMMENT_CHAR = ?/
    SASS_COMMENT_CHAR = ?/
    SASS_LOUD_COMMENT_CHAR = ?!
    CSS_COMMENT_CHAR = ?*
    DIRECTIVE_CHAR = ?@
    ESCAPE_CHAR    = ?\\
    MIXIN_DEFINITION_CHAR = ?=
    MIXIN_INCLUDE_CHAR    = ?+
    PROPERTY_OLD = /^:([^\s=:"]+)\s*(?:\s+|$)(.*)/
    DEFAULT_OPTIONS = {
      :style => :nested,
      :load_paths => ['.'],
      :cache => true,
      :cache_location => './.sass-cache',
      :syntax => :sass,
      :filesystem_importer => Sass::Importers::Filesystem
    }.freeze
    def self.normalize_options(options)
      options = DEFAULT_OPTIONS.merge(options.reject {|k, v| v.nil?})
      options[:importer] ||= options[:filesystem_importer].new(".") if options[:filename]
      options[:original_filename] ||= options[:filename]
      options[:line_comments] ||= options[:line_numbers]
      options[:load_paths] = (options[:load_paths] + Sass.load_paths).map do |p|
        next p unless p.is_a?(String) || (defined?(Pathname) && p.is_a?(Pathname))
        options[:filesystem_importer].new(p.to_s)
      end
      options[:property_syntax] ||= options[:attribute_syntax]
      case options[:property_syntax]
      when :alternate; options[:property_syntax] = :new
      when :normal; options[:property_syntax] = :old
      end
      options[:sourcemap] = :auto if options[:sourcemap] == true
      options[:sourcemap] = :none if options[:sourcemap] == false
      options
    end
    def self.for_file(filename, options)
      had_syntax = options[:syntax]
      if had_syntax
      elsif filename =~ /\.scss$/
        options.merge!(:syntax => :scss)
      elsif filename =~ /\.sass$/
        options.merge!(:syntax => :sass)
      end
      Sass::Engine.new(File.read(filename), options.merge(:filename => filename))
    end
    attr_reader :options
    def initialize(template, options = {})
      @options = self.class.normalize_options(options)
      @template = template
    end
    def render
      return _to_tree.render unless @options[:quiet]
      Sass::Util.silence_sass_warnings {_to_tree.render}
    end
    def render_with_sourcemap(sourcemap_uri)
      return _render_with_sourcemap(sourcemap_uri) unless @options[:quiet]
      Sass::Util.silence_sass_warnings {_render_with_sourcemap(sourcemap_uri)}
    end
    alias_method :to_css, :render
    def to_tree
      @tree ||= if @options[:quiet]
                  Sass::Util.silence_sass_warnings {_to_tree}
                else
                  _to_tree
                end
    end
    def source_encoding
      check_encoding!
      @source_encoding
    end
    def dependencies
      _dependencies(Set.new, engines = Set.new)
      Sass::Util.array_minus(engines, [self])
    end
    def _dependencies(seen, engines)
      key = [@options[:filename], @options[:importer]]
      return if seen.include?(key)
      seen << key
      engines << self
      to_tree.grep(Tree::ImportNode) do |n|
        next if n.css_import?
        n.imported_file._dependencies(seen, engines)
      end
    end
    private
    def _render_with_sourcemap(sourcemap_uri)
      filename = @options[:filename]
      importer = @options[:importer]
      sourcemap_dir = @options[:sourcemap_filename] &&
        File.dirname(File.expand_path(@options[:sourcemap_filename]))
      if filename.nil?
        raise Sass::SyntaxError.new(<<ERR)
Error generating source map: couldn't determine public URL for the source stylesheet.
  No filename is available so there's nothing for the source map to link to.
ERR
      elsif importer.nil?
        raise Sass::SyntaxError.new(<<ERR)
Error generating source map: couldn't determine public URL for "#{filename}".
  Without a public URL, there's nothing for the source map to link to.
  An importer was not set for this file.
ERR
      elsif Sass::Util.silence_warnings do
              sourcemap_dir = nil if @options[:sourcemap] == :file
              importer.public_url(filename, sourcemap_dir).nil?
            end
        raise Sass::SyntaxError.new(<<ERR)
Error generating source map: couldn't determine public URL for "#{filename}".
  Without a public URL, there's nothing for the source map to link to.
  Custom importers should define the #public_url method.
ERR
      end
      rendered, sourcemap = _to_tree.render_with_sourcemap
      compressed = @options[:style] == :compressed
      rendered << "\n" if rendered[-1] != ?\n
      rendered << "\n" unless compressed
      rendered << "/*# sourceMappingURL="
      rendered << Sass::Util.escape_uri(sourcemap_uri)
      rendered << " */\n"
      return rendered, sourcemap
    end
    def _to_tree
      check_encoding!
      if (@options[:cache] || @options[:read_cache]) &&
          @options[:filename] && @options[:importer]
        key = sassc_key
        sha = Digest::SHA1.hexdigest(@template)
        if (root = @options[:cache_store].retrieve(key, sha))
          root.options = @options
          return root
        end
      end
      if @options[:syntax] == :scss
        root = Sass::SCSS::Parser.new(@template, @options[:filename], @options[:importer]).parse
      else
        root = Tree::RootNode.new(@template)
        append_children(root, tree(tabulate(@template)).first, true)
      end
      root.options = @options
      if @options[:cache] && key && sha
        begin
          old_options = root.options
          root.options = {}
          @options[:cache_store].store(key, sha, root)
        ensure
          root.options = old_options
        end
      end
      root
    rescue SyntaxError => e
      e.modify_backtrace(:filename => @options[:filename], :line => @line)
      e.sass_template = @template
      raise e
    end
    def sassc_key
      @options[:cache_store].key(*@options[:importer].key(@options[:filename], @options))
    end
    def check_encoding!
      return if @checked_encoding
      @checked_encoding = true
      @template, @source_encoding = Sass::Util.check_sass_encoding(@template)
    end
    def tabulate(string)
      tab_str = nil
      comment_tab_str = nil
      first = true
      lines = []
      string.scan(/^[^\n]*?$/).each_with_index do |line, index|
        index += (@options[:line] || 1)
        if line.strip.empty?
          lines.last.text << "\n" if lines.last && lines.last.comment?
          next
        end
        line_tab_str = line[/^\s*/]
        unless line_tab_str.empty?
          if tab_str.nil?
            comment_tab_str ||= line_tab_str
            next if try_comment(line, lines.last, "", comment_tab_str, index)
            comment_tab_str = nil
          end
          tab_str ||= line_tab_str
          raise SyntaxError.new("Indenting at the beginning of the document is illegal.",
            :line => index) if first
          raise SyntaxError.new("Indentation can't use both tabs and spaces.",
            :line => index) if tab_str.include?(?\s) && tab_str.include?(?\t)
        end
        first &&= !tab_str.nil?
        if tab_str.nil?
          lines << Line.new(line.strip, 0, index, 0, @options[:filename], [])
          next
        end
        comment_tab_str ||= line_tab_str
        if try_comment(line, lines.last, tab_str * lines.last.tabs, comment_tab_str, index)
          next
        else
          comment_tab_str = nil
        end
        line_tabs = line_tab_str.scan(tab_str).size
        if tab_str * line_tabs != line_tab_str
          message = <<END.strip.gsub("\n", ' ')
Inconsistent indentation: #{Sass::Shared.human_indentation line_tab_str, true} used for indentation,
but the rest of the document was indented using #{Sass::Shared.human_indentation tab_str}.
END
          raise SyntaxError.new(message, :line => index)
        end
        lines << Line.new(line.strip, line_tabs, index, line_tab_str.size, @options[:filename], [])
      end
      lines
    end
    def try_comment(line, last, tab_str, comment_tab_str, index)
      return unless last && last.comment?
      return unless line =~ /^#{tab_str}\s/
      unless line =~ /^(?:#{comment_tab_str})(.*)$/
        raise SyntaxError.new(<<MSG.strip.gsub("\n", " "), :line => index)
Inconsistent indentation:
previous line was indented by #{Sass::Shared.human_indentation comment_tab_str},
but this line was indented by #{Sass::Shared.human_indentation line[/^\s*/]}.
MSG
      end
      last.comment_tab_str ||= comment_tab_str
      last.text << "\n" << line
      true
    end
    def tree(arr, i = 0)
      return [], i if arr[i].nil?
      base = arr[i].tabs
      nodes = []
      while (line = arr[i]) && line.tabs >= base
        if line.tabs > base
          raise SyntaxError.new(
            "The line was indented #{line.tabs - base} levels deeper than the previous line.",
            :line => line.index) if line.tabs > base + 1
          nodes.last.children, i = tree(arr, i)
        else
          nodes << line
          i += 1
        end
      end
      return nodes, i
    end
    def build_tree(parent, line, root = false)
      @line = line.index
      @offset = line.offset
      node_or_nodes = parse_line(parent, line, root)
      Array(node_or_nodes).each do |node|
        next unless node.is_a? Tree::Node
        node.line = line.index
        node.filename = line.filename
        append_children(node, line.children, false)
      end
      node_or_nodes
    end
    def append_children(parent, children, root)
      continued_rule = nil
      continued_comment = nil
      children.each do |line|
        child = build_tree(parent, line, root)
        if child.is_a?(Tree::RuleNode)
          if child.continued? && child.children.empty?
            if continued_rule
              continued_rule.add_rules child
            else
              continued_rule = child
            end
            next
          elsif continued_rule
            continued_rule.add_rules child
            continued_rule.children = child.children
            continued_rule, child = nil, continued_rule
          end
        elsif continued_rule
          continued_rule = nil
        end
        if child.is_a?(Tree::CommentNode) && child.type == :silent
          if continued_comment &&
              child.line == continued_comment.line +
              continued_comment.lines + 1
            continued_comment.value.last.sub!(/ \*\/\Z/, '')
            child.value.first.gsub!(/\A\/\*/, ' *')
            continued_comment.value += ["\n"] + child.value
            next
          end
          continued_comment = child
        end
        check_for_no_children(child)
        validate_and_append_child(parent, child, line, root)
      end
      parent
    end
    def validate_and_append_child(parent, child, line, root)
      case child
      when Array
        child.each {|c| validate_and_append_child(parent, c, line, root)}
      when Tree::Node
        parent << child
      end
    end
    def check_for_no_children(node)
      return unless node.is_a?(Tree::RuleNode) && node.children.empty?
      Sass::Util.sass_warn(<<WARNING.strip)
WARNING on line #{node.line}#{" of #{node.filename}" if node.filename}:
This selector doesn't have any properties and will not be rendered.
WARNING
    end
    def parse_line(parent, line, root)
      case line.text[0]
      when PROPERTY_CHAR
        if line.text[1] == PROPERTY_CHAR ||
            (@options[:property_syntax] == :new &&
             line.text =~ PROPERTY_OLD && $2.empty?)
          Tree::RuleNode.new(parse_interp(line.text), full_line_range(line))
        else
          name_start_offset = line.offset + 1 # +1 for the leading ':'
          name, value = line.text.scan(PROPERTY_OLD)[0]
          raise SyntaxError.new("Invalid property: \"#{line.text}\".",
            :line => @line) if name.nil? || value.nil?
          value_start_offset = name_end_offset = name_start_offset + name.length
          unless value.empty?
            value_start_offset = name_start_offset + line.text.index(value, name.length + 1) - 1
          end
          property = parse_property(name, parse_interp(name), value, :old, line, value_start_offset)
          property.name_source_range = Sass::Source::Range.new(
            Sass::Source::Position.new(@line, to_parser_offset(name_start_offset)),
            Sass::Source::Position.new(@line, to_parser_offset(name_end_offset)),
            @options[:filename], @options[:importer])
          property
        end
      when ?$
        parse_variable(line)
      when COMMENT_CHAR
        parse_comment(line)
      when DIRECTIVE_CHAR
        parse_directive(parent, line, root)
      when ESCAPE_CHAR
        Tree::RuleNode.new(parse_interp(line.text[1..-1]), full_line_range(line))
      when MIXIN_DEFINITION_CHAR
        parse_mixin_definition(line)
      when MIXIN_INCLUDE_CHAR
        if line.text[1].nil? || line.text[1] == ?\s
          Tree::RuleNode.new(parse_interp(line.text), full_line_range(line))
        else
          parse_mixin_include(line, root)
        end
      else
        parse_property_or_rule(line)
      end
    end
    def parse_property_or_rule(line)
      scanner = Sass::Util::MultibyteStringScanner.new(line.text)
      hack_char = scanner.scan(/[:\*\.]|\#(?!\{)/)
      offset = line.offset
      offset += hack_char.length if hack_char
      parser = Sass::SCSS::Parser.new(scanner,
        @options[:filename], @options[:importer],
        @line, to_parser_offset(offset))
      unless (res = parser.parse_interp_ident)
        parsed = parse_interp(line.text, line.offset)
        return Tree::RuleNode.new(parsed, full_line_range(line))
      end
      ident_range = Sass::Source::Range.new(
        Sass::Source::Position.new(@line, to_parser_offset(line.offset)),
        Sass::Source::Position.new(@line, parser.offset),
        @options[:filename], @options[:importer])
      offset = parser.offset - 1
      res.unshift(hack_char) if hack_char
      if (comment = scanner.scan(Sass::SCSS::RX::COMMENT))
        res << comment
        offset += comment.length
      end
      name = line.text[0...scanner.pos]
      if (scanned = scanner.scan(/\s*:(?:\s+|$)/)) # test for a property
        offset += scanned.length
        property = parse_property(name, res, scanner.rest, :new, line, offset)
        property.name_source_range = ident_range
        property
      else
        res.pop if comment
        if (trailing = (scanner.scan(/\s*#{Sass::SCSS::RX::COMMENT}/) ||
                        scanner.scan(/\s*#{Sass::SCSS::RX::SINGLE_LINE_COMMENT}/)))
          trailing.strip!
        end
        interp_parsed = parse_interp(scanner.rest)
        selector_range = Sass::Source::Range.new(
          ident_range.start_pos,
          Sass::Source::Position.new(@line, to_parser_offset(line.offset) + line.text.length),
          @options[:filename], @options[:importer])
        rule = Tree::RuleNode.new(res + interp_parsed, selector_range)
        rule << Tree::CommentNode.new([trailing], :silent) if trailing
        rule
      end
    end
    def parse_property(name, parsed_name, value, prop, line, start_offset)
      if value.strip.empty?
        expr = Sass::Script::Tree::Literal.new(Sass::Script::Value::String.new(""))
        end_offset = start_offset
      else
        expr = parse_script(value, :offset => to_parser_offset(start_offset))
        end_offset = expr.source_range.end_pos.offset - 1
      end
      node = Tree::PropNode.new(parse_interp(name), expr, prop)
      node.value_source_range = Sass::Source::Range.new(
        Sass::Source::Position.new(line.index, to_parser_offset(start_offset)),
        Sass::Source::Position.new(line.index, to_parser_offset(end_offset)),
        @options[:filename], @options[:importer])
      if value.strip.empty? && line.children.empty?
        raise SyntaxError.new(
          "Invalid property: \"#{node.declaration}\" (no value)." +
          node.pseudo_class_selector_message)
      end
      node
    end
    def parse_variable(line)
      name, value, flags = line.text.scan(Script::MATCH)[0]
      raise SyntaxError.new("Illegal nesting: Nothing may be nested beneath variable declarations.",
        :line => @line + 1) unless line.children.empty?
      raise SyntaxError.new("Invalid variable: \"#{line.text}\".",
        :line => @line) unless name && value
      flags = flags ? flags.split(/\s+/) : []
      if (invalid_flag = flags.find {|f| f != '!default' && f != '!global'})
        raise SyntaxError.new("Invalid flag \"#{invalid_flag}\".", :line => @line)
      end
      var_lhs_length = 1 + name.length # 1 stands for '$'
      index = line.text.index(value, line.offset + var_lhs_length) || 0
      expr = parse_script(value, :offset => to_parser_offset(line.offset + index))
      Tree::VariableNode.new(name, expr, flags.include?('!default'), flags.include?('!global'))
    end
    def parse_comment(line)
      if line.text[1] == CSS_COMMENT_CHAR || line.text[1] == SASS_COMMENT_CHAR
        silent = line.text[1] == SASS_COMMENT_CHAR
        loud = !silent && line.text[2] == SASS_LOUD_COMMENT_CHAR
        if silent
          value = [line.text]
        else
          value = self.class.parse_interp(
            line.text, line.index, to_parser_offset(line.offset), :filename => @filename)
        end
        value = Sass::Util.with_extracted_values(value) do |str|
          str = str.gsub(/^#{line.comment_tab_str}/m, '')[2..-1] # get rid of // or /*
          format_comment_text(str, silent)
        end
        type = if silent
                 :silent
               elsif loud
                 :loud
               else
                 :normal
               end
        Tree::CommentNode.new(value, type)
      else
        Tree::RuleNode.new(parse_interp(line.text), full_line_range(line))
      end
    end
    DIRECTIVES = Set[:mixin, :include, :function, :return, :debug, :warn, :for,
      :each, :while, :if, :else, :extend, :import, :media, :charset, :content,
      :at_root, :error]
    def parse_directive(parent, line, root)
      directive, whitespace, value = line.text[1..-1].split(/(\s+)/, 2)
      raise SyntaxError.new("Invalid directive: '@'.") unless directive
      offset = directive.size + whitespace.size + 1 if whitespace
      directive_name = directive.gsub('-', '_').to_sym
      if DIRECTIVES.include?(directive_name)
        return send("parse_#{directive_name}_directive", parent, line, root, value, offset)
      end
      unprefixed_directive = directive.gsub(/^-[a-z0-9]+-/i, '')
      if unprefixed_directive == 'supports'
        parser = Sass::SCSS::Parser.new(value, @options[:filename], @line)
        return Tree::SupportsNode.new(directive, parser.parse_supports_condition)
      end
      Tree::DirectiveNode.new(
        value.nil? ? ["@#{directive}"] : ["@#{directive} "] + parse_interp(value, offset))
    end
    def parse_while_directive(parent, line, root, value, offset)
      raise SyntaxError.new("Invalid while directive '@while': expected expression.") unless value
      Tree::WhileNode.new(parse_script(value, :offset => offset))
    end
    def parse_if_directive(parent, line, root, value, offset)
      raise SyntaxError.new("Invalid if directive '@if': expected expression.") unless value
      Tree::IfNode.new(parse_script(value, :offset => offset))
    end
    def parse_debug_directive(parent, line, root, value, offset)
      raise SyntaxError.new("Invalid debug directive '@debug': expected expression.") unless value
      raise SyntaxError.new("Illegal nesting: Nothing may be nested beneath debug directives.",
        :line => @line + 1) unless line.children.empty?
      offset = line.offset + line.text.index(value).to_i
      Tree::DebugNode.new(parse_script(value, :offset => offset))
    end
    def parse_error_directive(parent, line, root, value, offset)
      raise SyntaxError.new("Invalid error directive '@error': expected expression.") unless value
      raise SyntaxError.new("Illegal nesting: Nothing may be nested beneath error directives.",
        :line => @line + 1) unless line.children.empty?
      offset = line.offset + line.text.index(value).to_i
      Tree::ErrorNode.new(parse_script(value, :offset => offset))
    end
    def parse_extend_directive(parent, line, root, value, offset)
      raise SyntaxError.new("Invalid extend directive '@extend': expected expression.") unless value
      raise SyntaxError.new("Illegal nesting: Nothing may be nested beneath extend directives.",
        :line => @line + 1) unless line.children.empty?
      optional = !!value.gsub!(/\s+#{Sass::SCSS::RX::OPTIONAL}$/, '')
      offset = line.offset + line.text.index(value).to_i
      interp_parsed = parse_interp(value, offset)
      selector_range = Sass::Source::Range.new(
        Sass::Source::Position.new(@line, to_parser_offset(offset)),
        Sass::Source::Position.new(@line, to_parser_offset(line.offset) + line.text.length),
        @options[:filename], @options[:importer]
      )
      Tree::ExtendNode.new(interp_parsed, optional, selector_range)
    end
    def parse_warn_directive(parent, line, root, value, offset)
      raise SyntaxError.new("Invalid warn directive '@warn': expected expression.") unless value
      raise SyntaxError.new("Illegal nesting: Nothing may be nested beneath warn directives.",
        :line => @line + 1) unless line.children.empty?
      offset = line.offset + line.text.index(value).to_i
      Tree::WarnNode.new(parse_script(value, :offset => offset))
    end
    def parse_return_directive(parent, line, root, value, offset)
      raise SyntaxError.new("Invalid @return: expected expression.") unless value
      raise SyntaxError.new("Illegal nesting: Nothing may be nested beneath return directives.",
        :line => @line + 1) unless line.children.empty?
      offset = line.offset + line.text.index(value).to_i
      Tree::ReturnNode.new(parse_script(value, :offset => offset))
    end
    def parse_charset_directive(parent, line, root, value, offset)
      name = value && value[/\A(["'])(.*)\1\Z/, 2] # "
      raise SyntaxError.new("Invalid charset directive '@charset': expected string.") unless name
      raise SyntaxError.new("Illegal nesting: Nothing may be nested beneath charset directives.",
        :line => @line + 1) unless line.children.empty?
      Tree::CharsetNode.new(name)
    end
    def parse_media_directive(parent, line, root, value, offset)
      parser = Sass::SCSS::Parser.new(value,
        @options[:filename], @options[:importer],
        @line, to_parser_offset(@offset))
      offset = line.offset + line.text.index('media').to_i - 1
      parsed_media_query_list = parser.parse_media_query_list.to_a
      node = Tree::MediaNode.new(parsed_media_query_list)
      node.source_range = Sass::Source::Range.new(
        Sass::Source::Position.new(@line, to_parser_offset(offset)),
        Sass::Source::Position.new(@line, to_parser_offset(line.offset) + line.text.length),
        @options[:filename], @options[:importer])
      node
    end
    def parse_at_root_directive(parent, line, root, value, offset)
      return Sass::Tree::AtRootNode.new unless value
      if value.start_with?('(')
        parser = Sass::SCSS::Parser.new(value,
          @options[:filename], @options[:importer],
          @line, to_parser_offset(@offset))
        offset = line.offset + line.text.index('at-root').to_i - 1
        return Tree::AtRootNode.new(parser.parse_at_root_query)
      end
      at_root_node = Tree::AtRootNode.new
      parsed = parse_interp(value, offset)
      rule_node = Tree::RuleNode.new(parsed, full_line_range(line))
      append_children(rule_node, line.children, false)
      at_root_node << rule_node
      parent << at_root_node
      nil
    end
    def parse_for_directive(parent, line, root, value, offset)
      var, from_expr, to_name, to_expr =
        value.scan(/^([^\s]+)\s+from\s+(.+)\s+(to|through)\s+(.+)$/).first
      if var.nil? # scan failed, try to figure out why for error message
        if value !~ /^[^\s]+/
          expected = "variable name"
        elsif value !~ /^[^\s]+\s+from\s+.+/
          expected = "'from <expr>'"
        else
          expected = "'to <expr>' or 'through <expr>'"
        end
        raise SyntaxError.new("Invalid for directive '@for #{value}': expected #{expected}.")
      end
      raise SyntaxError.new("Invalid variable \"#{var}\".") unless var =~ Script::VALIDATE
      var = var[1..-1]
      parsed_from = parse_script(from_expr, :offset => line.offset + line.text.index(from_expr))
      parsed_to = parse_script(to_expr, :offset => line.offset + line.text.index(to_expr))
      Tree::ForNode.new(var, parsed_from, parsed_to, to_name == 'to')
    end
    def parse_each_directive(parent, line, root, value, offset)
      vars, list_expr = value.scan(/^([^\s]+(?:\s*,\s*[^\s]+)*)\s+in\s+(.+)$/).first
      if vars.nil? # scan failed, try to figure out why for error message
        if value !~ /^[^\s]+/
          expected = "variable name"
        elsif value !~ /^[^\s]+(?:\s*,\s*[^\s]+)*[^\s]+\s+from\s+.+/
          expected = "'in <expr>'"
        end
        raise SyntaxError.new("Invalid each directive '@each #{value}': expected #{expected}.")
      end
      vars = vars.split(',').map do |var|
        var.strip!
        raise SyntaxError.new("Invalid variable \"#{var}\".") unless var =~ Script::VALIDATE
        var[1..-1]
      end
      parsed_list = parse_script(list_expr, :offset => line.offset + line.text.index(list_expr))
      Tree::EachNode.new(vars, parsed_list)
    end
    def parse_else_directive(parent, line, root, value, offset)
      previous = parent.children.last
      raise SyntaxError.new("@else must come after @if.") unless previous.is_a?(Tree::IfNode)
      if value
        if value !~ /^if\s+(.+)/
          raise SyntaxError.new("Invalid else directive '@else #{value}': expected 'if <expr>'.")
        end
        expr = parse_script($1, :offset => line.offset + line.text.index($1))
      end
      node = Tree::IfNode.new(expr)
      append_children(node, line.children, false)
      previous.add_else node
      nil
    end
    def parse_import_directive(parent, line, root, value, offset)
      raise SyntaxError.new("Illegal nesting: Nothing may be nested beneath import directives.",
        :line => @line + 1) unless line.children.empty?
      scanner = Sass::Util::MultibyteStringScanner.new(value)
      values = []
      loop do
        unless (node = parse_import_arg(scanner, offset + scanner.pos))
          raise SyntaxError.new(
            "Invalid @import: expected file to import, was #{scanner.rest.inspect}",
            :line => @line)
        end
        values << node
        break unless scanner.scan(/,\s*/)
      end
      if scanner.scan(/;/)
        raise SyntaxError.new("Invalid @import: expected end of line, was \";\".",
          :line => @line)
      end
      values
    end
    def parse_import_arg(scanner, offset)
      return if scanner.eos?
      if scanner.match?(/url\(/i)
        script_parser = Sass::Script::Parser.new(scanner, @line, to_parser_offset(offset), @options)
        str = script_parser.parse_string
        if scanner.eos?
          end_pos = str.source_range.end_pos
          node = Tree::CssImportNode.new(str)
        else
          media_parser = Sass::SCSS::Parser.new(scanner,
            @options[:filename], @options[:importer],
            @line, str.source_range.end_pos.offset)
          media = media_parser.parse_media_query_list
          end_pos = Sass::Source::Position.new(@line, media_parser.offset + 1)
          node = Tree::CssImportNode.new(str, media.to_a)
        end
        node.source_range = Sass::Source::Range.new(
          str.source_range.start_pos, end_pos,
          @options[:filename], @options[:importer])
        return node
      end
      unless (quoted_val = scanner.scan(Sass::SCSS::RX::STRING))
        scanned = scanner.scan(/[^,;]+/)
        node = Tree::ImportNode.new(scanned)
        start_parser_offset = to_parser_offset(offset)
        node.source_range = Sass::Source::Range.new(
          Sass::Source::Position.new(@line, start_parser_offset),
          Sass::Source::Position.new(@line, start_parser_offset + scanned.length),
          @options[:filename], @options[:importer])
        return node
      end
      start_offset = offset
      offset += scanner.matched.length
      val = Sass::Script::Value::String.value(scanner[1] || scanner[2])
      scanned = scanner.scan(/\s*/)
      if !scanner.match?(/[,;]|$/)
        offset += scanned.length if scanned
        media_parser = Sass::SCSS::Parser.new(scanner,
          @options[:filename], @options[:importer], @line, offset)
        media = media_parser.parse_media_query_list
        node = Tree::CssImportNode.new(quoted_val, media.to_a)
        node.source_range = Sass::Source::Range.new(
          Sass::Source::Position.new(@line, to_parser_offset(start_offset)),
          Sass::Source::Position.new(@line, media_parser.offset),
          @options[:filename], @options[:importer])
      elsif val =~ %r{^(https?:)?//}
        node = Tree::CssImportNode.new(quoted_val)
        node.source_range = Sass::Source::Range.new(
          Sass::Source::Position.new(@line, to_parser_offset(start_offset)),
          Sass::Source::Position.new(@line, to_parser_offset(offset)),
          @options[:filename], @options[:importer])
      else
        node = Tree::ImportNode.new(val)
        node.source_range = Sass::Source::Range.new(
          Sass::Source::Position.new(@line, to_parser_offset(start_offset)),
          Sass::Source::Position.new(@line, to_parser_offset(offset)),
          @options[:filename], @options[:importer])
      end
      node
    end
    def parse_mixin_directive(parent, line, root, value, offset)
      parse_mixin_definition(line)
    end
    MIXIN_DEF_RE = /^(?:=|@mixin)\s*(#{Sass::SCSS::RX::IDENT})(.*)$/
    def parse_mixin_definition(line)
      name, arg_string = line.text.scan(MIXIN_DEF_RE).first
      raise SyntaxError.new("Invalid mixin \"#{line.text[1..-1]}\".") if name.nil?
      offset = line.offset + line.text.size - arg_string.size
      args, splat = Script::Parser.new(arg_string.strip, @line, to_parser_offset(offset), @options).
        parse_mixin_definition_arglist
      Tree::MixinDefNode.new(name, args, splat)
    end
    CONTENT_RE = /^@content\s*(.+)?$/
    def parse_content_directive(parent, line, root, value, offset)
      trailing = line.text.scan(CONTENT_RE).first.first
      unless trailing.nil?
        raise SyntaxError.new(
          "Invalid content directive. Trailing characters found: \"#{trailing}\".")
      end
      raise SyntaxError.new("Illegal nesting: Nothing may be nested beneath @content directives.",
        :line => line.index + 1) unless line.children.empty?
      Tree::ContentNode.new
    end
    def parse_include_directive(parent, line, root, value, offset)
      parse_mixin_include(line, root)
    end
    MIXIN_INCLUDE_RE = /^(?:\+|@include)\s*(#{Sass::SCSS::RX::IDENT})(.*)$/
    def parse_mixin_include(line, root)
      name, arg_string = line.text.scan(MIXIN_INCLUDE_RE).first
      raise SyntaxError.new("Invalid mixin include \"#{line.text}\".") if name.nil?
      offset = line.offset + line.text.size - arg_string.size
      args, keywords, splat, kwarg_splat =
        Script::Parser.new(arg_string.strip, @line, to_parser_offset(offset), @options).
          parse_mixin_include_arglist
      Tree::MixinNode.new(name, args, keywords, splat, kwarg_splat)
    end
    FUNCTION_RE = /^@function\s*(#{Sass::SCSS::RX::IDENT})(.*)$/
    def parse_function_directive(parent, line, root, value, offset)
      name, arg_string = line.text.scan(FUNCTION_RE).first
      raise SyntaxError.new("Invalid function definition \"#{line.text}\".") if name.nil?
      offset = line.offset + line.text.size - arg_string.size
      args, splat = Script::Parser.new(arg_string.strip, @line, to_parser_offset(offset), @options).
        parse_function_definition_arglist
      Tree::FunctionNode.new(name, args, splat)
    end
    def parse_script(script, options = {})
      line = options[:line] || @line
      offset = options[:offset] || @offset + 1
      Script.parse(script, line, offset, @options)
    end
    def format_comment_text(text, silent)
      content = text.split("\n")
      if content.first && content.first.strip.empty?
        removed_first = true
        content.shift
      end
      return "/* */" if content.empty?
      content.last.gsub!(/ ?\*\/ *$/, '')
      first = content.shift unless removed_first
      content.map! {|l| l.gsub!(/^\*( ?)/, '\1') || (l.empty? ? "" : " ") + l}
      content.unshift first unless removed_first
      if silent
        "/*" + content.join("\n *") + " */"
      else
        "/*" + content.join("\n *").gsub(/ \*\Z/, '') + " */"
      end
    end
    def parse_interp(text, offset = 0)
      self.class.parse_interp(text, @line, offset, :filename => @filename)
    end
    def to_parser_offset(offset)
      offset + 1
    end
    def full_line_range(line)
      Sass::Source::Range.new(
        Sass::Source::Position.new(@line, to_parser_offset(line.offset)),
        Sass::Source::Position.new(@line, to_parser_offset(line.offset) + line.text.length),
        @options[:filename], @options[:importer])
    end
    def self.parse_interp(text, line, offset, options)
      res = []
      rest = Sass::Shared.handle_interpolation text do |scan|
        escapes = scan[2].size
        res << scan.matched[0...-2 - escapes]
        if escapes.odd?
          res << "\\" * (escapes - 1) << '#{'
        else
          res << "\\" * [0, escapes - 1].max
          res << Script::Parser.new(
            scan, line, offset + scan.pos - scan.matched_size + 1, options).
            parse_interpolated
        end
      end
      res << rest
    end
  end
end