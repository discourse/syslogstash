# frozen_string_literal: true

# A single socket reader.
#

require 'deep_merge'

TIMESTAMP_FORMAT = '%FT%T.%3NZ'

class Syslogstash::SyslogReader
  include ServiceSkeleton::LoggingHelpers

  class UnparseableMessage < StandardError; end

  def initialize(config, logstash, metrics)
    @config   = config
    @logstash = logstash
    @metrics  = metrics

    @logger   = config.logger

    @shutdown_reader, @shutdown_writer = IO.pipe

    @tcp_socket = nil
    @udp_socket = nil
    @unix_socket = nil

    @logger.debug(logloc) { "initialized" }
  end

  # Start reading from the socket, parsing entries, and flinging
  # them at logstash.
  def run
    logger.debug(logloc) { "off we go!" }

    begin
      slen = config.syslog_socket.length
      if config.syslog_socket.start_with? 'tcp+udp/'
        port = config.syslog_socket.slice(8..slen).to_i # lop off tcp+udp/
        start_tcp(port)
        start_udp(port)
      elsif config.syslog_socket.start_with? 'tcp/'
        port = config.syslog_socket.slice(4..slen).to_i # lop off tcp/
        start_tcp(port)
      elsif config.syslog_socket.start_with? 'udp/'
        port = config.syslog_socket.slice(4..slen).to_i # lop off udp/
        start_udp(port)
      elsif config.syslog_socket.start_with? '/' # treat as a filename
        start_unix(config.syslog_socket)
      else
        raise ArgumentError, "invalid syslog specification: #{config.syslog_socket}"
      end
    rescue ArgumentError
      raise
    rescue StandardError => ex
      raise ex.class, "Error while trying to bind to #{config.syslog_socket}: #{ex.message}", ex.backtrace
    end

    interesting_sockets = [@shutdown_reader, @unix_socket, @udp_socket, @tcp_socket].compact
    # list of connected clients
    tcp_connected_fds = []

    begin
      while !@shutdown_reader.closed? do
        IO.select(interesting_sockets + tcp_connected_fds, nil, nil).first.each do |fd|
          if fd == @udp_socket || fd == @unix_socket
            begin
              msg = fd.recvmsg_nonblock
            rescue IO::WaitWritable
              logger.debug(logloc) { "select said a message was waiting, but it wasn't.  o.O" }
            else
              logger.debug(logloc) { "Message received: #{msg.inspect}" }
              message, remote = msg
              process_message message, remote: remote
            end
          elsif fd == @tcp_socket
            # a new connection has arrived
            client = StreamSocket.new(fd.accept, logger)
            tcp_connected_fds << client
            logger.debug(logloc) { "accepted connection on #{client}" }
          elsif tcp_connected_fds.include? fd
            # data incoming from existing tcp socket
            fd.read_messages do |message|
              logger.debug(logloc) { "Message received: #{message.inspect}" }
              process_message message, remote: fd.cached_remote_address
            end
            if fd.finished?
              fd.close
              tcp_connected_fds.delete fd
            end
          elsif fd == @shutdown_reader
            @shutdown_reader.close
            logger.debug(logloc) { "Tripped over shutdown reader" }
          end
        end
      end
    ensure
      # close all of our sockets
      if !@tcp_socket.nil?
        @tcp_socket.close
        logger.debug(logloc) { "closed stream socket #{config.syslog_socket}" }
      end
      if !@udp_socket.nil?
        @udp_socket.close
        logger.debug(logloc) { "closed datagram socket #{config.syslog_socket}" }
      end
      if !@unix_socket.nil?
        @unix_socket.close
        logger.debug(logloc) { "removing socket file #{config.syslog_socket}" }
        File.unlink(config.syslog_socket) rescue nil
      end

      # close all our TCP connections, if any
      tcp_connected_fds.each do |fd|
        fd.read_messages(final: true) do |message|
          logger.debug(logloc) { "Message received: #{message.inspect}" }
          process_message message, remote: fd.cached_remote_address
        end
        logger.debug(logloc) { "(shutting down) closing connection #{fd}" }
        fd.close
      end
      logger.debug(logloc) { "shutdown complete" }
    end
  end

  def shutdown
    @shutdown_writer.close
  end

  def parse_timestamp(t)
    return Time.now.utc if t.nil?

    begin
      if t.start_with? '*'
        # unsynced timestamp from IOS, is useless
        Time.now.utc
      else
        # DateTime does a fairly sensible job of this
        DateTime.parse(t)
      end
    rescue
      # as good a fallback as any
      Time.now.utc
    end
  end

  private

  attr_reader :config, :logger

  def start_tcp(port)
    begin
      @tcp_socket&.close
      @tcp_socket = TCPServer.new('::', port)
      logger.info(logloc) { "started TCP server on port #{port}" }
    rescue Errno::EADDRINUSE
      logger.info(logloc) { "tcp socket for #{config.syslog_socket} already in use" }
      sleep 1
      retry
    end
  end

  def start_udp(port)
    begin
      @udp_socket&.close
      @udp_socket = Socket.new(Socket::AF_INET6, Socket::SOCK_DGRAM, 0)
      @udp_socket.bind(Socket.pack_sockaddr_in(port, '::' ))
      logger.info(logloc) { "started UDP server on port #{port}" }
    rescue Errno::EADDRINUSE
      logger.info(logloc) { "udp socket for #{config.syslog_socket} already in use" }
      sleep 1
      retry
    end
  end

  def start_unix(path)
    begin
      @unix_socket&.close
      @unix_socket = Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0)
      @unix_socket.bind(Socket.pack_sockaddr_un(path))
      logger.info(logloc) { "started UNIX listener on #{config.syslog_socket}" }
      File.chmod(0666, path)
    rescue Errno::EEXIST, Errno::EADDRINUSE
      logger.info(logloc) { "socket #{config.syslog_socket} already exists; deleting" }
      File.unlink(config.syslog_socket) rescue nil
      retry
    end
  end

  def process_message(msg, remote: nil)
    @metrics.messages_received_total.increment(labels: { socket_path: config.syslog_socket })
    relay_message msg
    logstash_message msg, remote
  end

  def extract_log_entry_from_message(msg, remote: nil)
    if msg =~ /\A<(\d+)>(\w{3} [ 0-9]{2} [0-9:]{8}) (.*)\z/m
      # most everything except our special snowflake: Cisco
      flags     = $1.to_i
      timestamp = $2
      content   = $3

      # Lo! the many ways that syslog messages can be formatted
      hostname, program, pid, message =
        case content
        # the gold standard: hostname, program name with optional PID
        when /\A([a-zA-Z0-9._-]*[^:]) (\S+?)(\[(\d+)\])?: (.*)\z/m
          [$1, $2, $4, $5]
        # hostname, no program name
        when /\A([a-zA-Z0-9._-]+) (\S+[^:] .*)\z/m
          [$1, nil, nil, $2]
        # program name, no hostname (yeah, you heard me, non-RFC compliant!)
        when /\A(\S+?)(\[(\d+)\])?: (.*)\z/m
          [nil, $1, $3, $4]
        else
          # I have NFI
          [nil, nil, nil, content]
        end

      log = {
        '@timestamp': parse_timestamp(timestamp).strftime(TIMESTAMP_FORMAT),
        log: {
          original: msg,
          syslog: {
            severity: {
              code: flags % 8,
            },
            facility: {
              code: flags / 8,
            },
          },
        },
        message: message,
      }
      log.deep_merge({ host: { hostname: hostname } }) unless hostname.nil?
      log.deep_merge({ process: { pid: pid.to_i } }) unless pid.nil?
      log.deep_merge({ process: { name: program } }) unless program.nil?
      log_entry(log)
    elsif msg =~ /\A<(\d+)>(\d+): (?:([^ :]+): )?(\*?\w{3} [ 0-9]{2} [0-9:]{8}\.[0-9]{3}): (.*)\z/m
      # aforementioned special snowflake: Cisco IOS
      # e.g.: <157>6223: switch01.sjc3: Sep 16 18:35:06.954: %PARSER-5-CFGLOG_LOGGEDCMD: command
      flags     = $1.to_i
      seq_num   = $2
      hostname  = $3 # optional
      timestamp = $4
      content   = $5

      program, message =
        case content
        # IOS: %ID: details
        when /\A%([^:]+): (.*)\z/m
          [$1, $2]
        else
          # I have NFI
          [nil, content]
        end

      log = {
        '@timestamp': parse_timestamp(timestamp).strftime(TIMESTAMP_FORMAT),
        event: {
          sequence: seq_num.to_i,
        },
        log: {
          original: msg,
          syslog: {
            severity: {
              code: flags % 8,
            },
            facility: {
              code: flags / 8,
            },
          },
        },
        message: message,
      }
      log.deep_merge({ host: { hostname: hostname } }) unless hostname.nil?
      log.deep_merge({ process: { name: program } }) unless program.nil?
      log_entry(log)

    elsif msg =~ /\A<(\d+)>(\S+)\[(\d+)\]: (.*)\z/m
      # ANOTHER SNOWFLAKE: Mellanox Onyx doesn't send a timestamp OR a hostname
      # try and make this regex as specific as possible to avoid snaring other things
      # example lines:
      # <189>snmpd[26572]: [snmpd.NOTICE]: Got SNMP request from ip 172.16.1.100
      # <189>cli[962]: [cli.NOTICE]: user admin: Entering configuration mode
      # <141>metad[2466]: TID 139915579090752: [metad.NOTICE]: Sending final query response for msg_id '117065370' (no error, has resp)
      flags     = $1.to_i
      hostname  = case remote.afamily
                  when Socket::AF_INET
                    remote.getnameinfo.first
                  when Socket::AF_INET6
                    remote.getnameinfo.first
                  when Socket::AF_UNIX
                    remote.getnameinfo.first
                  else
                    'unknownhost'
                  end
      timestamp = Time.now.utc.strftime('%b %e %H:%M:%S')
      program   = $2
      pid       = $3.to_i
      message   = $4

      log_entry(
        '@timestamp': parse_timestamp(timestamp).strftime(TIMESTAMP_FORMAT),
        log: {
          original: msg,
          syslog: {
            facility: {
              code: flags / 8,
            },
            severity: {
              code: flags % 8,
            },
          },
        },
        host: {
          hostname: hostname,
        },
        message: message,
        process: {
          name: program,
          pid: pid,
        }
      )

    else
      raise UnparseableMessage
    end
  end

  def logstash_message(msg, remote)
    msg = msg.chomp.encode("UTF-8", invalid: :replace, undef: :replace)
    begin
      log_entry = extract_log_entry_from_message(msg, remote: remote)
      if config.drop_regex && log_entry[:message].match?(config.drop_regex)
        @metrics.dropped_total.increment({})
        logger.debug(logloc) { "dropping message #{msg}" }
        return
      end
      # `unsafe_instance` is Ultravisor's way of telling us to be careful
      # In this case, we know that `send_event` is designed to be threadsafe
      @logstash.unsafe_instance.send_event(log_entry) 
    rescue UnparseableMessage
      logger.warn(logloc) { "Unparseable message: #{msg.inspect}" }
    end
  end

  def log_entry(h)
    {}.tap do |e|
      e.deep_merge({
        ecs: {
          version: '1.8'
        },
        event: {
          created: Time.now.utc.strftime(TIMESTAMP_FORMAT)
        },
        log: {
          logger: 'Syslogstash',
          syslog: {
            facility: {
              name: FACILITIES[h[:log][:syslog][:facility][:code]],
            },
            severity: {
              name: SEVERITIES[h[:log][:syslog][:severity][:code]],
            },
          },
        },
      })
      e.deep_merge!(h)
      e.deep_merge!(config.add_fields)
      logger.debug(logloc) { "Complete log entry is: #{e.inspect}" }
    end
  end

  def relay_message(msg)
    @currently_failed ||= {}

    if config.relay_to_stdout
      # This one's easy
      puts msg.sub(/\A<\d+>/, '')
      $stdout.flush
    end

    config.relay_sockets.each do |f|
      relay_to_socket(f)
    end
  end

  def relay_to_socket(f)
    begin
      s = Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0)
      begin
        s.connect(Socket.pack_sockaddr_un(f))
      rescue Errno::ENOENT
        # Socket doesn't exist; we don't care enough about this to bother
        # reporting it.  People will figure it out themselves soon enough.
      rescue StandardError => ex
        unless @currently_failed[f]
          logger.warn(logloc) { "Error while connecting to relay socket #{f}: #{ex.message} (#{ex.class})" }
          @currently_failed[f] = true
        end
        return
      end

      begin
        # We really, *really* don't want to block the world just because
        # whoever's on the other end of the relay socket can't process
        # messages quick enough.
        s.sendmsg_nonblock(msg)
        if @currently_failed[f]
          logger.info(logloc) { "Error on socket #{f} has cleared; messages are being delivered again" }
          @currently_failed[f] = false
        end
      rescue Errno::ENOTCONN
        unless @currently_failed[f]
          logger.debug(logloc) { "Nothing is listening on socket #{f}" }
          @currently_failed[f] = true
        end
      rescue IO::EAGAINWaitWritable
        unless @currently_failed[f]
          logger.warn(logloc) { "Socket #{f} is currently backlogged; messages to this socket are now being discarded undelivered" }
          @currently_failed[f] = true
        end
      rescue StandardError => ex
        logger.warn(logloc) { (["Failed to relay message to socket #{f} from #{config.syslog_socket}: #{ex.message} (#{ex.class})"] + ex.backtrace).join("\n  ") }
      end
    ensure
      s.close
    end
  end

  # There is a gap between 12-15 inclusive
  # We need to define them to ensure the local0-7 facilities line up correctly
  FACILITIES = %w{
    kern
    user
    mail
    daemon
    auth
    syslog
    lpr
    news
    uucp
    cron
    authpriv
    ftp
    facility12
    facility13
    facility14
    facility15
    local0 local1 local2 local3 local4 local5 local6 local7
  }

  SEVERITIES = %w{
    emerg
    alert
    crit
    err
    warning
    notice
    info
    debug
  }
end

require_relative 'syslog_reader/stream_socket'
