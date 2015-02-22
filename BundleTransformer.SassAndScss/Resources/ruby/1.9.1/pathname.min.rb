#
# = pathname.rb
#
# Object-Oriented Pathname Class
#
# Author:: Tanaka Akira <akr@m17n.org>
# Documentation:: Author and Gavin Sinclair
#
# For documentation, see class Pathname.
#
# <tt>pathname.rb</tt> is distributed with Ruby since 1.8.0.
#
class Pathname
  if RUBY_VERSION < "1.9"
    TO_PATH = :to_str
  else
    TO_PATH = :to_path
  end
  SAME_PATHS = if File::FNM_SYSCASE.nonzero?
    proc {|a, b| a.casecmp(b).zero?}
  else
    proc {|a, b| a == b}
  end
  def initialize(path)
    path = path.__send__(TO_PATH) if path.respond_to? TO_PATH
    @path = path.dup
    if /\0/ =~ @path
      raise ArgumentError, "pathname contains \\0: #{@path.inspect}"
    end
    self.taint if @path.tainted?
  end
  def freeze() super; @path.freeze; self end
  def taint() super; @path.taint; self end
  def untaint() super; @path.untaint; self end
  def ==(other)
    return false unless Pathname === other
    other.to_s == @path
  end
  alias === ==
  alias eql? ==
  def <=>(other)
    return nil unless Pathname === other
    @path.tr('/', "\0") <=> other.to_s.tr('/', "\0")
  end
  def hash # :nodoc:
    @path.hash
  end
  def to_s
    @path.dup
  end
  alias_method TO_PATH, :to_s
  def inspect # :nodoc:
    "#<#{self.class}:#{@path}>"
  end
  def sub(pattern, *rest, &block)
    if block
      path = @path.sub(pattern, *rest) {|*args|
        begin
          old = Thread.current[:pathname_sub_matchdata]
          Thread.current[:pathname_sub_matchdata] = $~
          eval("$~ = Thread.current[:pathname_sub_matchdata]", block.binding)
        ensure
          Thread.current[:pathname_sub_matchdata] = old
        end
        yield(*args)
      }
    else
      path = @path.sub(pattern, *rest)
    end
    self.class.new(path)
  end
  if File::ALT_SEPARATOR
    SEPARATOR_LIST = "#{Regexp.quote File::ALT_SEPARATOR}#{Regexp.quote File::SEPARATOR}"
    SEPARATOR_PAT = /[#{SEPARATOR_LIST}]/
  else
    SEPARATOR_LIST = "#{Regexp.quote File::SEPARATOR}"
    SEPARATOR_PAT = /#{Regexp.quote File::SEPARATOR}/
  end
  def sub_ext(repl)
    ext = File.extname(@path)
    self.class.new(@path.chomp(ext) + repl)
  end
  def chop_basename(path)
    base = File.basename(path)
    if /\A#{SEPARATOR_PAT}?\z/o =~ base
      return nil
    else
      return path[0, path.rindex(base)], base
    end
  end
  private :chop_basename
  def split_names(path)
    names = []
    while r = chop_basename(path)
      path, basename = r
      names.unshift basename
    end
    return path, names
  end
  private :split_names
  def prepend_prefix(prefix, relpath)
    if relpath.empty?
      File.dirname(prefix)
    elsif /#{SEPARATOR_PAT}/o =~ prefix
      prefix = File.dirname(prefix)
      prefix = File.join(prefix, "") if File.basename(prefix + 'a') != 'a'
      prefix + relpath
    else
      prefix + relpath
    end
  end
  private :prepend_prefix
  def cleanpath(consider_symlink=false)
    if consider_symlink
      cleanpath_conservative
    else
      cleanpath_aggressive
    end
  end
  def cleanpath_aggressive
    path = @path
    names = []
    pre = path
    while r = chop_basename(pre)
      pre, base = r
      case base
      when '.'
      when '..'
        names.unshift base
      else
        if names[0] == '..'
          names.shift
        else
          names.unshift base
        end
      end
    end
    if /#{SEPARATOR_PAT}/o =~ File.basename(pre)
      names.shift while names[0] == '..'
    end
    self.class.new(prepend_prefix(pre, File.join(*names)))
  end
  private :cleanpath_aggressive
  def has_trailing_separator?(path)
    if r = chop_basename(path)
      pre, basename = r
      pre.length + basename.length < path.length
    else
      false
    end
  end
  private :has_trailing_separator?
  def add_trailing_separator(path)
    if File.basename(path + 'a') == 'a'
      path
    else
      File.join(path, "") # xxx: Is File.join is appropriate to add separator?
    end
  end
  private :add_trailing_separator
  def del_trailing_separator(path)
    if r = chop_basename(path)
      pre, basename = r
      pre + basename
    elsif /#{SEPARATOR_PAT}+\z/o =~ path
      $` + File.dirname(path)[/#{SEPARATOR_PAT}*\z/o]
    else
      path
    end
  end
  private :del_trailing_separator
  def cleanpath_conservative
    path = @path
    names = []
    pre = path
    while r = chop_basename(pre)
      pre, base = r
      names.unshift base if base != '.'
    end
    if /#{SEPARATOR_PAT}/o =~ File.basename(pre)
      names.shift while names[0] == '..'
    end
    if names.empty?
      self.class.new(File.dirname(pre))
    else
      if names.last != '..' && File.basename(path) == '.'
        names << '.'
      end
      result = prepend_prefix(pre, File.join(*names))
      if /\A(?:\.|\.\.)\z/ !~ names.last && has_trailing_separator?(path)
        self.class.new(add_trailing_separator(result))
      else
        self.class.new(result)
      end
    end
  end
  private :cleanpath_conservative
  def realpath(basedir=nil)
    self.class.new(File.realpath(@path, basedir))
  end
  def realdirpath(basedir=nil)
    self.class.new(File.realdirpath(@path, basedir))
  end
  def parent
    self + '..'
  end
  def mountpoint?
    begin
      stat1 = self.lstat
      stat2 = self.parent.lstat
      stat1.dev == stat2.dev && stat1.ino == stat2.ino ||
        stat1.dev != stat2.dev
    rescue Errno::ENOENT
      false
    end
  end
  def root?
    !!(chop_basename(@path) == nil && /#{SEPARATOR_PAT}/o =~ @path)
  end
  def absolute?
    !relative?
  end
  def relative?
    path = @path
    while r = chop_basename(path)
      path, basename = r
    end
    path == ''
  end
  def each_filename # :yield: filename
    return to_enum(__method__) unless block_given?
    prefix, names = split_names(@path)
    names.each {|filename| yield filename }
    nil
  end
  def descend
    vs = []
    ascend {|v| vs << v }
    vs.reverse_each {|v| yield v }
    nil
  end
  def ascend
    path = @path
    yield self
    while r = chop_basename(path)
      path, name = r
      break if path.empty?
      yield self.class.new(del_trailing_separator(path))
    end
  end
  def +(other)
    other = Pathname.new(other) unless Pathname === other
    Pathname.new(plus(@path, other.to_s))
  end
  def plus(path1, path2) # -> path
    prefix2 = path2
    index_list2 = []
    basename_list2 = []
    while r2 = chop_basename(prefix2)
      prefix2, basename2 = r2
      index_list2.unshift prefix2.length
      basename_list2.unshift basename2
    end
    return path2 if prefix2 != ''
    prefix1 = path1
    while true
      while !basename_list2.empty? && basename_list2.first == '.'
        index_list2.shift
        basename_list2.shift
      end
      break unless r1 = chop_basename(prefix1)
      prefix1, basename1 = r1
      next if basename1 == '.'
      if basename1 == '..' || basename_list2.empty? || basename_list2.first != '..'
        prefix1 = prefix1 + basename1
        break
      end
      index_list2.shift
      basename_list2.shift
    end
    r1 = chop_basename(prefix1)
    if !r1 && /#{SEPARATOR_PAT}/o =~ File.basename(prefix1)
      while !basename_list2.empty? && basename_list2.first == '..'
        index_list2.shift
        basename_list2.shift
      end
    end
    if !basename_list2.empty?
      suffix2 = path2[index_list2.first..-1]
      r1 ? File.join(prefix1, suffix2) : prefix1 + suffix2
    else
      r1 ? prefix1 : File.dirname(prefix1)
    end
  end
  private :plus
  def join(*args)
    args.unshift self
    result = args.pop
    result = Pathname.new(result) unless Pathname === result
    return result if result.absolute?
    args.reverse_each {|arg|
      arg = Pathname.new(arg) unless Pathname === arg
      result = arg + result
      return result if result.absolute?
    }
    result
  end
  def children(with_directory=true)
    with_directory = false if @path == '.'
    result = []
    Dir.foreach(@path) {|e|
      next if e == '.' || e == '..'
      if with_directory
        result << self.class.new(File.join(@path, e))
      else
        result << self.class.new(e)
      end
    }
    result
  end
  def each_child(with_directory=true, &b)
    children(with_directory).each(&b)
  end
  def relative_path_from(base_directory)
    dest_directory = self.cleanpath.to_s
    base_directory = base_directory.cleanpath.to_s
    dest_prefix = dest_directory
    dest_names = []
    while r = chop_basename(dest_prefix)
      dest_prefix, basename = r
      dest_names.unshift basename if basename != '.'
    end
    base_prefix = base_directory
    base_names = []
    while r = chop_basename(base_prefix)
      base_prefix, basename = r
      base_names.unshift basename if basename != '.'
    end
    unless SAME_PATHS[dest_prefix, base_prefix]
      raise ArgumentError, "different prefix: #{dest_prefix.inspect} and #{base_directory.inspect}"
    end
    while !dest_names.empty? &&
          !base_names.empty? &&
          SAME_PATHS[dest_names.first, base_names.first]
      dest_names.shift
      base_names.shift
    end
    if base_names.include? '..'
      raise ArgumentError, "base_directory has ..: #{base_directory.inspect}"
    end
    base_names.fill('..')
    relpath_names = base_names + dest_names
    if relpath_names.empty?
      Pathname.new('.')
    else
      Pathname.new(File.join(*relpath_names))
    end
  end
end
class Pathname    # * IO *
  def each_line(*args, &block) # :yield: line
    IO.foreach(@path, *args, &block)
  end
  def read(*args) IO.read(@path, *args) end
  def binread(*args) IO.binread(@path, *args) end
  def readlines(*args) IO.readlines(@path, *args) end
  def sysopen(*args) IO.sysopen(@path, *args) end
end
class Pathname    # * File *
  def atime() File.atime(@path) end
  def ctime() File.ctime(@path) end
  def mtime() File.mtime(@path) end
  def chmod(mode) File.chmod(mode, @path) end
  def lchmod(mode) File.lchmod(mode, @path) end
  def chown(owner, group) File.chown(owner, group, @path) end
  def lchown(owner, group) File.lchown(owner, group, @path) end
  def fnmatch(pattern, *args) File.fnmatch(pattern, @path, *args) end
  def fnmatch?(pattern, *args) File.fnmatch?(pattern, @path, *args) end
  def ftype() File.ftype(@path) end
  def make_link(old) File.link(old, @path) end
  def open(*args, &block) # :yield: file
    File.open(@path, *args, &block)
  end
  def readlink() self.class.new(File.readlink(@path)) end
  def rename(to) File.rename(@path, to) end
  def stat() File.stat(@path) end
  def lstat() File.lstat(@path) end
  def make_symlink(old) File.symlink(old, @path) end
  def truncate(length) File.truncate(@path, length) end
  def utime(atime, mtime) File.utime(atime, mtime, @path) end
  def basename(*args) self.class.new(File.basename(@path, *args)) end
  def dirname() self.class.new(File.dirname(@path)) end
  def extname() File.extname(@path) end
  def expand_path(*args) self.class.new(File.expand_path(@path, *args)) end
  def split() File.split(@path).map {|f| self.class.new(f) } end
end
class Pathname    # * FileTest *
  def blockdev?() FileTest.blockdev?(@path) end
  def chardev?() FileTest.chardev?(@path) end
  def executable?() FileTest.executable?(@path) end
  def executable_real?() FileTest.executable_real?(@path) end
  def exist?() FileTest.exist?(@path) end
  def grpowned?() FileTest.grpowned?(@path) end
  def directory?() FileTest.directory?(@path) end
  def file?() FileTest.file?(@path) end
  def pipe?() FileTest.pipe?(@path) end
  def socket?() FileTest.socket?(@path) end
  def owned?() FileTest.owned?(@path) end
  def readable?() FileTest.readable?(@path) end
  def world_readable?() FileTest.world_readable?(@path) end
  def readable_real?() FileTest.readable_real?(@path) end
  def setuid?() FileTest.setuid?(@path) end
  def setgid?() FileTest.setgid?(@path) end
  def size() FileTest.size(@path) end
  def size?() FileTest.size?(@path) end
  def sticky?() FileTest.sticky?(@path) end
  def symlink?() FileTest.symlink?(@path) end
  def writable?() FileTest.writable?(@path) end
  def world_writable?() FileTest.world_writable?(@path) end
  def writable_real?() FileTest.writable_real?(@path) end
  def zero?() FileTest.zero?(@path) end
end
class Pathname    # * Dir *
  def Pathname.glob(*args) # :yield: pathname
    if block_given?
      Dir.glob(*args) {|f| yield self.new(f) }
    else
      Dir.glob(*args).map {|f| self.new(f) }
    end
  end
  def Pathname.getwd() self.new(Dir.getwd) end
  class << self; alias pwd getwd end
  def entries() Dir.entries(@path).map {|f| self.class.new(f) } end
  def each_entry(&block) # :yield: pathname
    Dir.foreach(@path) {|f| yield self.class.new(f) }
  end
  def mkdir(*args) Dir.mkdir(@path, *args) end
  def rmdir() Dir.rmdir(@path) end
  def opendir(&block) # :yield: dir
    Dir.open(@path, &block)
  end
end
class Pathname    # * Find *
  def find(&block) # :yield: pathname
    require 'find.min.rb'
    if @path == '.'
      Find.find(@path) {|f| yield self.class.new(f.sub(%r{\A\./}, '')) }
    else
      Find.find(@path) {|f| yield self.class.new(f) }
    end
  end
end
class Pathname    # * mixed *
  def unlink()
    begin
      Dir.unlink @path
    rescue Errno::ENOTDIR
      File.unlink @path
    end
  end
  alias delete unlink
end
class Pathname
  undef =~
end
module Kernel
  def Pathname(path) # :doc:
    Pathname.new(path)
  end
  private :Pathname
end