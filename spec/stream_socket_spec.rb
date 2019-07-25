require 'syslogstash'

describe Syslogstash::SyslogReader::StreamSocket do
  # we are cheating and avoiding actual TCP sockets because what matters
  # is it's a stream socket and not dgram
  let(:sockets) { Socket.pair(:UNIX, :STREAM) }
  let(:logger) { Logger.new("/dev/null") }
  let(:tcp_socket) { Syslogstash::SyslogReader::StreamSocket.new(sockets.first, logger) }
  let(:writer) { sockets[1] }

  it "extracts a single message" do
    writer.write(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!\r\n"
    )
    expect { |b| tcp_socket.read_messages(&b) }.to yield_with_args(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!\r\n"
    )
  end

  it "extracts a multiline message" do
    writer.write(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!\r\nThe boat's name is Tim.\r\n"
    )
    expect { |b| tcp_socket.read_messages(&b) }.to yield_with_args(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!\r\nThe boat's name is Tim.\r\n"
    )
  end

  it "extracts multiple messages" do
    writer.write(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!\r\n" +
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm in the water!\r\n"
    )
    expect { |b| tcp_socket.read_messages(&b) }.to yield_successive_args(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!\r\n",
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm in the water!\r\n"
    )
  end

  it "properly combines fragments of messages" do
    ["<7", "4>Jan  2 03:04", ":05 myho", "st myprog", "ram[12345]: I'm on", " a boat!"].each do |frag|
      writer.write(frag)
      writer.flush
      expect { |b| tcp_socket.read_messages(&b) }.not_to yield_control
    end
    writer.write(
      "\r\n<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm in the water!\r\n"
    )
    writer.flush
    expect { |b| tcp_socket.read_messages(&b) }.to yield_successive_args(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!\r\n",
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm in the water!\r\n"
    )
  end

  it "does not send an incomplete message" do
    writer.write(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on"
    )
    expect { |b| tcp_socket.read_messages(&b) }.not_to yield_with_args
  end

  it "sends on an incomplete message after socket closed" do
    writer.write(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on"
    )
    writer.close
    expect { |b| tcp_socket.read_messages(&b) }.to yield_with_args(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on",
    )
  end

  it "sends on an incomplete message on a final call" do
    writer.write(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on"
    )
    expect { |b| tcp_socket.read_messages(final: true, &b) }.to yield_with_args(
      "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on",
    )
  end
end
