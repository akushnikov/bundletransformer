#!/usr/bin/env ruby
#--
# set.rb - defines the Set class
#++
# Copyright (c) 2002-2008 Akinori MUSHA <knu@iDaemons.org>
#
# Documentation by Akinori MUSHA and Gavin Sinclair.
#
# All rights reserved.  You can redistribute and/or modify it under the same
# terms as Ruby.
#
#   $Id: set.rb 28095 2010-05-30 13:15:17Z marcandre $
#
# == Overview
#
# This library provides the Set class, which deals with a collection
# of unordered values with no duplicates.  It is a hybrid of Array's
# intuitive inter-operation facilities and Hash's fast lookup.  If you
# need to keep values ordered, use the SortedSet class.
#
# The method +to_set+ is added to Enumerable for convenience.
#
# See the Set and SortedSet documentation for examples of usage.
class Set
  include Enumerable
  def self.[](*ary)
    new(ary)
  end
  def initialize(enum = nil, &block) # :yields: o
    @hash ||= Hash.new
    enum.nil? and return
    if block
      do_with_enum(enum) { |o| add(block[o]) }
    else
      merge(enum)
    end
  end
  def do_with_enum(enum, &block)
    if enum.respond_to?(:each_entry)
      enum.each_entry(&block)
    elsif enum.respond_to?(:each)
      enum.each(&block)
    else
      raise ArgumentError, "value must be enumerable"
    end
  end
  private :do_with_enum
  def initialize_copy(orig)
    @hash = orig.instance_eval{@hash}.dup
  end
  def freeze	# :nodoc:
    super
    @hash.freeze
    self
  end
  def taint	# :nodoc:
    super
    @hash.taint
    self
  end
  def untaint	# :nodoc:
    super
    @hash.untaint
    self
  end
  def size
    @hash.size
  end
  alias length size
  def empty?
    @hash.empty?
  end
  def clear
    @hash.clear
    self
  end
  def replace(enum)
    if enum.class == self.class
      @hash.replace(enum.instance_eval { @hash })
    else
      clear
      merge(enum)
    end
    self
  end
  def to_a
    @hash.keys
  end
  def flatten_merge(set, seen = Set.new)
    set.each { |e|
      if e.is_a?(Set)
	if seen.include?(e_id = e.object_id)
	  raise ArgumentError, "tried to flatten recursive Set"
	end
	seen.add(e_id)
	flatten_merge(e, seen)
	seen.delete(e_id)
      else
	add(e)
      end
    }
    self
  end
  protected :flatten_merge
  def flatten
    self.class.new.flatten_merge(self)
  end
  def flatten!
    if detect { |e| e.is_a?(Set) }
      replace(flatten())
    else
      nil
    end
  end
  def include?(o)
    @hash.include?(o)
  end
  alias member? include?
  def superset?(set)
    set.is_a?(Set) or raise ArgumentError, "value must be a set"
    return false if size < set.size
    set.all? { |o| include?(o) }
  end
  def proper_superset?(set)
    set.is_a?(Set) or raise ArgumentError, "value must be a set"
    return false if size <= set.size
    set.all? { |o| include?(o) }
  end
  def subset?(set)
    set.is_a?(Set) or raise ArgumentError, "value must be a set"
    return false if set.size < size
    all? { |o| set.include?(o) }
  end
  def proper_subset?(set)
    set.is_a?(Set) or raise ArgumentError, "value must be a set"
    return false if set.size <= size
    all? { |o| set.include?(o) }
  end
  def each
    block_given? or return enum_for(__method__)
    @hash.each_key { |o| yield(o) }
    self
  end
  def add(o)
    @hash[o] = true
    self
  end
  alias << add
  def add?(o)
    if include?(o)
      nil
    else
      add(o)
    end
  end
  def delete(o)
    @hash.delete(o)
    self
  end
  def delete?(o)
    if include?(o)
      delete(o)
    else
      nil
    end
  end
  def delete_if
    block_given? or return enum_for(__method__)
    to_a.each { |o| @hash.delete(o) if yield(o) }
    self
  end
  def keep_if
    block_given? or return enum_for(__method__)
    to_a.each { |o| @hash.delete(o) unless yield(o) }
    self
  end
  def collect!
    block_given? or return enum_for(__method__)
    set = self.class.new
    each { |o| set << yield(o) }
    replace(set)
  end
  alias map! collect!
  def reject!
    block_given? or return enum_for(__method__)
    n = size
    delete_if { |o| yield(o) }
    size == n ? nil : self
  end
  def select!
    block_given? or return enum_for(__method__)
    n = size
    keep_if { |o| yield(o) }
    size == n ? nil : self
  end
  def merge(enum)
    if enum.instance_of?(self.class)
      @hash.update(enum.instance_variable_get(:@hash))
    else
      do_with_enum(enum) { |o| add(o) }
    end
    self
  end
  def subtract(enum)
    do_with_enum(enum) { |o| delete(o) }
    self
  end
  def |(enum)
    dup.merge(enum)
  end
  alias + |		##
  alias union |		##
  def -(enum)
    dup.subtract(enum)
  end
  alias difference -	##
  def &(enum)
    n = self.class.new
    do_with_enum(enum) { |o| n.add(o) if include?(o) }
    n
  end
  alias intersection &	##
  def ^(enum)
    n = Set.new(enum)
    each { |o| if n.include?(o) then n.delete(o) else n.add(o) end }
    n
  end
  def ==(other)
    if self.equal?(other)
      true
    elsif other.instance_of?(self.class)
      @hash == other.instance_variable_get(:@hash)
    elsif other.is_a?(Set) && self.size == other.size
      other.all? { |o| @hash.include?(o) }
    else
      false
    end
  end
  def hash	# :nodoc:
    @hash.hash
  end
  def eql?(o)	# :nodoc:
    return false unless o.is_a?(Set)
    @hash.eql?(o.instance_eval{@hash})
  end
  def classify # :yields: o
    block_given? or return enum_for(__method__)
    h = {}
    each { |i|
      x = yield(i)
      (h[x] ||= self.class.new).add(i)
    }
    h
  end
  def divide(&func)
    func or return enum_for(__method__)
    if func.arity == 2
      require 'tsort.min.rb'
      class << dig = {}		# :nodoc:
	include TSort
	alias tsort_each_node each_key
	def tsort_each_child(node, &block)
	  fetch(node).each(&block)
	end
      end
      each { |u|
	dig[u] = a = []
	each{ |v| func.call(u, v) and a << v }
      }
      set = Set.new()
      dig.each_strongly_connected_component { |css|
	set.add(self.class.new(css))
      }
      set
    else
      Set.new(classify(&func).values)
    end
  end
  InspectKey = :__inspect_key__         # :nodoc:
  def inspect
    ids = (Thread.current[InspectKey] ||= [])
    if ids.include?(object_id)
      return sprintf('#<%s: {...}>', self.class.name)
    end
    begin
      ids << object_id
      return sprintf('#<%s: {%s}>', self.class, to_a.inspect[1..-2])
    ensure
      ids.pop
    end
  end
  def pretty_print(pp)	# :nodoc:
    pp.text sprintf('#<%s: {', self.class.name)
    pp.nest(1) {
      pp.seplist(self) { |o|
	pp.pp o
      }
    }
    pp.text "}>"
  end
  def pretty_print_cycle(pp)	# :nodoc:
    pp.text sprintf('#<%s: {%s}>', self.class.name, empty? ? '' : '...')
  end
end
module Enumerable
  def to_set(klass = Set, *args, &block)
    klass.new(self, *args, &block)
  end
end
if $0 == __FILE__
  eval DATA.read, nil, $0, __LINE__+4
end
__END__