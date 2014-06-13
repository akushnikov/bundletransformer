#
# find.rb: the Find module for processing all files under a given directory.
#
module Find
  def find(*paths) # :yield: path
    block_given? or return enum_for(__method__, *paths)
    paths.collect!{|d| raise Errno::ENOENT unless File.exist?(d); d.dup}
    while file = paths.shift
      catch(:prune) do
	yield file.dup.taint
        begin
          s = File.lstat(file)
        rescue Errno::ENOENT, Errno::EACCES, Errno::ENOTDIR, Errno::ELOOP, Errno::ENAMETOOLONG
          next
        end
        if s.directory? then
          begin
            fs = Dir.entries(file)
          rescue Errno::ENOENT, Errno::EACCES, Errno::ENOTDIR, Errno::ELOOP, Errno::ENAMETOOLONG
            next
          end
          fs.sort!
          fs.reverse_each {|f|
            next if f == "." or f == ".."
            f = File.join(file, f)
            paths.unshift f.untaint
          }
        end
      end
    end
  end
  def prune
    throw :prune
  end
  module_function :find, :prune
end