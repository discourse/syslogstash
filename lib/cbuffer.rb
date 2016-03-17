class CBuffer

  def initialize(capacity)
    @capacity = capacity
    @f = @b = @fc = 0
    @buffer = Array.new(capacity)
  end

  def get
    return if empty?
    element = @buffer[@b]
    @buffer[@b] = nil
    @b = (@b + 1) % @capacity
    @fc = @fc - 1
    element
  end

  def unget(element)
    old_idx = (@b -1) % @capacity
    if @buffer[old_idx] == nil
      @buffer[old_idx] = element
      @b = old_idx
      @fc = @fc + 1
    end #else old element would have been discarded anyways
  end

  def put(element)
    @b = @b +1 if full?
    @buffer[@f] = element
    @f = (@f + 1) % @capacity
    @fc = @fc + 1
    full?
  end

  def full?
    @f == @b && @fc != 0
  end

  def empty?
    @f == @b && @fc == 0
  end

  def size
    @capacity
  end

  def clear
    @buffer = Array.new(@capacity)
    @f = @b = @fc = 0
  end

  def to_s
    "<#{self.class} @size=#{@capacity} @buffer=#{@buffer}>"
  end

end
