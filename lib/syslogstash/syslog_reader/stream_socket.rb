# frozen_string_literal: true
class Syslogstash::SyslogReader::StreamSocket
  include ServiceSkeleton::LoggingHelpers

  def initialize(fd, logger)
    @buffer = ''
    @fd = fd
    @finished = false
    @logger = logger
    # we don't have access to the remote peer information
    # after the socket is closed, so let's note this down for later
    @cached_remote_address = @fd.remote_address

    @remote_address = begin
      if @fd.local_address.afamily == Socket::AF_UNIX
        Socket.unpack_sockaddr_un(fd.getpeername).to_s
      else
        port, remote_address = Socket.unpack_sockaddr_in(fd.getpeername)
        "#{remote_address}:#{port}"
      end
    end
    # we're not ever going to write to it
    fd.close_write
  end

  attr_accessor :cached_remote_address

  def finished?
    @finished
  end

  def to_io
    @fd
  end

  def to_s
    af = @fd.local_address.afamily == Socket::AF_UNIX ? "UNIX" : "TCP"
    "#{af} fd #{@fd.fileno} from #{@remote_address}"
  end

  # called when we have incoming data on the socket
  # extracted messages are yielded to the caller
  def read_messages(final: false)
    begin
      loop do
        @buffer += @fd.read_nonblock 2048 # "a large chunk"
        extract_messages { |msg| yield msg }
      end
    rescue EOFError, SocketError => e
      @logger.debug(logloc) { "#{self} received #{e.message} (#{e.class})" }
      final = true
    rescue IO::EAGAINWaitReadable
      # no more data to read for now
      extract_messages(donereading: true) { |msg| yield msg }
    end
    if final
      extract_messages(final: true) { |msg| yield msg }
      @finished = true
    end
  end

  def close
    @logger.debug(logloc) { "closed connection on #{self}" }
    @fd.close
  end

  private

  # this function processes @buffer which may contain multiple messages,
  # then leaves the @buffer containing the unprocessed leftovers
  # messages are yielded to the caller
  #
  # parameters:
  #   donereading: we have no other immediate messages coming in so
  #                consider a message ending in "\r\n" as final
  #   final: there will never be other messages arriving, send off what we have
  #
  # buffering and blocking messages is hard because of multiline messages:
  # * we might get a multiline message at any point so we have to look for a <#>
  #   to KNOW there's a new message
  # * but when reading a single message we might just get "<#>message\r\n"
  # so we need to know when we're in either situation and behave slightly
  # differently
  def extract_messages(donereading: false, final: false)
    return if @buffer.nil? || @buffer.empty?

    # split messages at the point between "\r\n" and "<NUM>"
    messages = @buffer.split(/(?!\r?\n)(?=<\d+>)/)
    yield messages.shift until messages.length == 1

    # we're left with a complete "<#>message\r\n", or a partial message
    @buffer = messages.first
    if final || (donereading && @buffer.match(/\r?\n$/))
      yield @buffer
      @buffer = ''
    end
  end
end
