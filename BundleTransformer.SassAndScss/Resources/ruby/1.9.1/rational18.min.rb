#
#   rational18.rb -
#       $Release Version: 0.5 $
#       $Revision: 1.8 $
#       $Date: 2015/02/21 18:31:34 $
#       by Andrey Taritsyn
#
# Documentation by Kevin Jackson and Gavin Sinclair.
#
# When you <tt>require 'rational'</tt>, all interactions between numbers
# potentially return a rational result.  For example:
#
#   1.quo(2)              # -> 0.5
#   require 'rational'
#   1.quo(2)              # -> Rational(1,2)
#
# See Rational for full documentation.
#
module Kernel
  def Rational(a, b = 1)
    if a.kind_of?(Rational) && b == 1
      a
    else
      Rational.reduce(a, b)
    end
  end
end
class Rational < Numeric
  @RCS_ID='-$Id: rational.rb,v 1.7 1999/08/24 12:49:28 keiju Exp keiju $-'
  def Rational.reduce(num, den)
    if den.nil?
      den = 1
	end
    raise ZeroDivisionError, "denominator is zero" if den == 0
    if den < 0
      num = -num
      den = -den
    end
	if num.kind_of?(Integer) && den.kind_of?(Integer)
		gcd = num.gcd(den)
		num = num.div(gcd)
		den = den.div(gcd)
	end
    if den == 1 && defined?(Unify)
      num
    else
      new!(num, den)
    end
  end
  def Rational.new!(num, den)
    if den.nil?
      den = 1
	end
    new(num, den)
  end
  private_class_method :new
  def initialize(num, den)
    if den < 0
      num = -num
      den = -den
    end
    @numerator = num
    @denominator = den
  end
  def + (a)
    if a.kind_of?(Rational)
      num = @numerator * a.denominator
      num_a = a.numerator * @denominator
      Rational(num + num_a, @denominator * a.denominator)
    elsif a.kind_of?(Integer)
      self + Rational.new!(a, 1)
    elsif a.kind_of?(Float)
      Float(self) + a
    else
      x, y = a.coerce(self)
      x + y
    end
  end
  def - (a)
    if a.kind_of?(Rational)
      num = @numerator * a.denominator
      num_a = a.numerator * @denominator
      Rational(num - num_a, @denominator * a.denominator)
    elsif a.kind_of?(Integer)
      self - Rational.new!(a, 1)
    elsif a.kind_of?(Float)
      Float(self) - a
    else
      x, y = a.coerce(self)
      x - y
    end
  end
  def * (a)
    if a.kind_of?(Rational)
      num = @numerator * a.numerator
      den = @denominator * a.denominator
      Rational(num, den)
    elsif a.kind_of?(Integer)
      self * Rational.new!(a, 1)
    elsif a.kind_of?(Float)
      Float(self) * a
    else
      x, y = a.coerce(self)
      x * y
    end
  end
  def / (a)
    if a.kind_of?(Rational)
      num = @numerator * a.denominator
      den = @denominator * a.numerator
      Rational(num, den)
    elsif a.kind_of?(Integer)
      raise ZeroDivisionError, "division by zero" if a == 0
      self / Rational.new!(a, 1)
    elsif a.kind_of?(Float)
      Float(self) / a
    else
      x, y = a.coerce(self)
      x / y
    end
  end
  def ** (other)
    if other.kind_of?(Rational)
      Float(self) ** other
    elsif other.kind_of?(Integer)
      if other > 0
	    num = @numerator ** other
	    den = @denominator ** other
      elsif other < 0
	    num = @denominator ** -other
	    den = @numerator ** -other
      elsif other == 0
	    num = 1
	    den = 1
      end
      Rational.new!(num, den)
    elsif other.kind_of?(Float)
      Float(self) ** other
    else
      x, y = other.coerce(self)
      x ** y
    end
  end
  def % (other)
    value = (self / other).to_i
    return self - other * value
  end
  def divmod(other)
    value = (self / other).to_i
    return value, self - other * value
  end
  def abs
    if @numerator > 0
      Rational.new!(@numerator, @denominator)
    else
      Rational.new!(-@numerator, @denominator)
    end
  end
  def == (other)
    if other.kind_of?(Rational)
      @numerator == other.numerator && @denominator == other.denominator
    elsif other.kind_of?(Integer)
      self == Rational.new!(other, 1)
    elsif other.kind_of?(Float)
      Float(self) == other
    elsif defined?(BigDecimal) && other.kind_of?(BigDecimal)
      Float(self) == other
    elsif
      self == other
    end
  end
  def <=> (other)
    if other.kind_of?(Rational)
      num = @numerator * other.denominator
      num_a = other.numerator * @denominator
      v = num - num_a
      if v > 0
	    return 1
      elsif v < 0
	    return  -1
      else
	    return 0
      end
    elsif other.kind_of?(Integer)
      return self <=> Rational.new!(other, 1)
    elsif other.kind_of?(Float)
      return Float(self) <=> other
    elsif defined? other.coerce
      x, y = other.coerce(self)
      return x <=> y
    else
      return nil
    end
  end
  def coerce(other)
    if other.kind_of?(Float)
      return other, self.to_f
    elsif other.kind_of?(Integer)
      return Rational.new!(other, 1), self
    else
      super
    end
  end
  def to_i
    Integer(@numerator.div(@denominator))
  end
  def to_f
    @numerator.to_f / @denominator.to_f
  end
  def to_s
    if @denominator == 1
      @numerator.to_s
    else
      @numerator.to_s + " / " + @denominator.to_s
    end
  end
  def to_r
    self
  end
  def inspect
    sprintf("Rational(%s, %s)", @numerator.inspect, @denominator.inspect)
  end
  def hash
    @numerator.hash ^ @denominator.hash
  end
  attr :numerator
  attr :denominator
  private :initialize
end
class Fixnum
  undef quo
  def quo(other)
    Rational.new!(self, 1) / other
  end
  alias rdiv quo
  def rpower (other)
    if other >= 0
      self.power!(other)
    else
      Rational.new!(self, 1) ** other
    end
  end
  unless defined? 1.power!
    alias power! **
    alias ** rpower
  end
end
class Bignum
  unless defined? Complex
    alias power! **
  end
  undef quo
  def quo(other)
    Rational.new!(self, 1) / other
  end
  alias rdiv quo
  def rpower (other)
    if other >= 0
      self.power!(other)
    else
      Rational.new!(self, 1) ** other
    end
  end
  unless defined? Complex
    alias ** rpower
  end
end