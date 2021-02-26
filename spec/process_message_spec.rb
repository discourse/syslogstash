# frozen_string_literal: true

require_relative './spec_helper'

require 'syslogstash'

ECS_VERSION = '1.8'

class MockConfig
  attr_accessor :drop_regex
  attr_reader :logger

  def initialize(logger)
    @logger = logger
  end

  def syslog_socket
    '/somewhere/funny'
  end

  def relay_to_stdout
    false
  end

  def relay_sockets
    []
  end

  def add_fields
    @add_fields ||= {}
  end
end

class MockMetrics
  def dropped_total
    @dropped_total ||=
      Prometheus::Client::Counter.new(
        :dropped_total,
        docstring: 'Number of log entries that were not forwarded due to matching the drop regex',
      )
  end

  def messages_received_total
    @messages_received_total ||=
      Prometheus::Client::Counter.new(
        :messages_received_total,
        docstring: 'The number of syslog message received from the log socket',
      )
  end
end

describe Syslogstash::SyslogReader do
  let(:mock_writer) { instance_double(LogstashWriter) }
  let(:logger) { Logger.new('/dev/null') }
  let(:mock_config) { MockConfig.new(logger) }
  let(:mock_metrics) { MockMetrics.new }
  let(:reader) { Syslogstash::SyslogReader.new(mock_config, mock_writer, mock_metrics) }

  it "parses an all-features-on message" do
    msg = "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!"
    expect(mock_writer)
      .to receive(:send_event)
      .with(
        '@timestamp': "#{Time.now.year}-01-02T03:04:05.000Z",
        ecs: {
          version: ECS_VERSION,
        },
        event: {
          created: match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
        },
        log: {
          logger: 'Syslogstash',
          original: msg,
          syslog: {
            facility: {
              code: 9,
              name: 'cron',
            },
            severity: {
              code: 2,
              name: 'crit',
            },
          },
        },
        host: {
          hostname: 'myhost',
        },
        message: "I'm on a boat!",
        process: {
          name: 'myprogram',
          pid: 12345,
        },
      )
    reader.send(:process_message, msg)
  end

  it "parses a no-PID message" do
    msg = "<74>Jan  2 03:04:05 myhost myprogram: I'm on a boat!"
    expect(mock_writer)
      .to receive(:send_event)
      .with(
        '@timestamp': "#{Time.now.year}-01-02T03:04:05.000Z",
        ecs: {
          version: ECS_VERSION,
        },
        event: {
          created: match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
        },
        log: {
          logger: 'Syslogstash',
          original: msg,
          syslog: {
            facility: {
              code: 9,
              name: 'cron',
            },
            severity: {
              code: 2,
              name: 'crit',
            },
          },
        },
        host: {
          hostname: 'myhost',
        },
        message: "I'm on a boat!",
        process: {
          name: 'myprogram',
        },
      )
    reader.send(:process_message, msg)
  end

  it "parses a no-program message" do
    msg = "<74>Jan  2 03:04:05 myhost I'm on a boat!"
    expect(mock_writer)
      .to receive(:send_event)
      .with(
        '@timestamp': "#{Time.now.year}-01-02T03:04:05.000Z",
        ecs: {
          version: ECS_VERSION,
        },
        event: {
          created: match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
        },
        log: {
          logger: 'Syslogstash',
          original: msg,
          syslog: {
            facility: {
              code: 9,
              name: 'cron',
            },
            severity: {
              code: 2,
              name: 'crit',
            },
          },
        },
        host: {
          hostname: 'myhost',
        },
        message: "I'm on a boat!",
      )
    reader.send(:process_message, msg)
  end

  it "parses a (non-standard) no-hostname message" do
    msg = "<74>Jan  2 03:04:05 myprogram[12345]: I'm on a boat!"
    expect(mock_writer)
      .to receive(:send_event)
      .with(
        '@timestamp': "#{Time.now.year}-01-02T03:04:05.000Z",
        ecs: {
          version: ECS_VERSION,
        },
        event: {
          created: match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
        },
        log: {
          logger: 'Syslogstash',
          original: msg,
          syslog: {
            facility: {
              code: 9,
              name: 'cron',
            },
            severity: {
              code: 2,
              name: 'crit',
            },
          },
        },
        process: {
          name: 'myprogram',
          pid: 12345,
        },
        message: "I'm on a boat!",
      )
    reader.send(:process_message, msg)
  end

  it "parses an IOS message with hostname" do
    msg = "<157>6214: switch01.sjc3: Sep 16 18:17:23.009: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin]"
    expect(mock_writer)
      .to receive(:send_event)
      .with(
        '@timestamp': "#{Time.now.year}-09-16T18:17:23.009Z",

        ecs: {
          version: ECS_VERSION,
        },
        event: {
          created: match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
          sequence: 6214,
        },
        log: {
          logger: 'Syslogstash',
          original: msg,
          syslog: {
            facility: {
              code: 19,
              name: 'local3',
            },
            severity: {
              code: 5,
              name: 'notice',
            },
          },
        },
        host: {
          hostname: 'switch01.sjc3',
        },
        process: {
          name: 'SEC_LOGIN-5-LOGIN_SUCCESS',
        },
        message: 'Login Success [user: admin]',
      )

    reader.send(:process_message, msg)
  end

  it "parses an IOS message without hostname" do
    msg = "<157>6214: Sep 16 18:17:23.009: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin]"
    expect(mock_writer)
      .to receive(:send_event)
      .with(
        '@timestamp': "#{Time.now.year}-09-16T18:17:23.009Z",
        ecs: {
          version: ECS_VERSION,
        },
        event: {
          created: match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
          sequence: 6214,
        },
        log: {
          logger: 'Syslogstash',
          original: msg,
          syslog: {
            facility: {
              code: 19,
              name: 'local3',
            },
            severity: {
              code: 5,
              name: 'notice',
            },
          },

        },
        process: {
          name: 'SEC_LOGIN-5-LOGIN_SUCCESS',
        },
        message: 'Login Success [user: admin]',
      )
    reader.send(:process_message, msg)
  end

  it "fixes the time on a message with unsynced timestamp" do
    msg = "<158>11600: *Apr 28 10:14:29.608: %DOT11-6-ASSOC: Interface Dot11Radio1, Station   c0ff.eec0.ffee Associated KEY_MGMT[WPAv2 PSK]"
    expect(mock_writer)
      .to receive(:send_event) do |e|
        expect(e).to match(
          '@timestamp': instance_of(String),
          ecs: {
            version: ECS_VERSION,
          },
          event: {
            created: match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
            sequence: 11600,
          },
          log: {
            logger: 'Syslogstash',
            original: msg,
            syslog: {
              facility: {
                code: 19,
                name: 'local3',
              },
              severity: {
                code: 6,
                name: 'info',
              },
            },
          },
          process: {
            name: 'DOT11-6-ASSOC',
          },
          message: 'Interface Dot11Radio1, Station   c0ff.eec0.ffee Associated KEY_MGMT[WPAv2 PSK]',
        )
      expect(e['@timestamp']).to_not eq('Apr 28 10:14:29.608')
      expect(e['@timestamp']).to_not eq("#{Time.now.year}-04-28T10:14:29.608Z")

      end
    reader.send(:process_message, msg)
  end

  it "adds information to a message with no timestamp or hostname received over IPv4" do
    msg = "<189>snmpd[26572]: [snmpd.NOTICE]: Got SNMP request from ip 172.16.1.100"
    expect(mock_writer)
      .to receive(:send_event)
      .with(
        '@timestamp': "#{Time.now.year}-01-09T01:02:03.000Z",
        ecs: {
          version: ECS_VERSION,
        },
        event: {
          created: "2020-01-09T01:02:03.000Z",
        },
        host: {
          hostname: '172.16.1.142'
        },
        log: {
          logger: 'Syslogstash',
          original: msg,
          syslog: {
            facility: {
              code: 23,
              name: 'local7',
            },
            severity: {
              code: 5,
              name: 'notice',
            },
          },
        },
        process: {
          name: 'snmpd',
          pid: 26572,
        },
        message: '[snmpd.NOTICE]: Got SNMP request from ip 172.16.1.100',
      )
    locked_time = Time.utc(2020, 1, 9, 1, 2, 3)
    allow(Time).to receive(:now).and_return(locked_time)
    addrinfo = Addrinfo.new(Socket.sockaddr_in(54321, '172.16.1.142'))
    reader.send(:process_message, msg, remote: addrinfo)
  end

  it "adds information to a message with no timestamp or hostname received over IPv6" do
    msg = "<189>snmpd[26572]: [snmpd.NOTICE]: Got SNMP request from ip 172.16.1.100"
    expect(mock_writer)
      .to receive(:send_event)
      .with(
        '@timestamp': "#{Time.now.year}-01-09T01:02:03.000Z",
        ecs: {
          version: ECS_VERSION,
        },
        event: {
          created: "2020-01-09T01:02:03.000Z",
        },
        host: {
          hostname: '2001:db8::f00f:1'
        },
        log: {
          logger: 'Syslogstash',
          original: msg,
          syslog: {
            facility: {
              code: 23,
              name: 'local7',
            },
            severity: {
              code: 5,
              name: 'notice',
            },
          },
        },
        process: {
          name: 'snmpd',
          pid: 26572,
        },
        message: '[snmpd.NOTICE]: Got SNMP request from ip 172.16.1.100',
      )

    locked_time = Time.utc(2020, 1, 9, 1, 2, 3)
    allow(Time).to receive(:now).and_return(locked_time)
    addrinfo = Addrinfo.new(Socket.sockaddr_in(54321, '2001:db8::f00f:1'))
    reader.send(:process_message, msg, remote: addrinfo)
  end

  it "adds information to a message with no timestamp or hostname received over a unix socket" do
    addrinfo = Addrinfo.new(Socket.sockaddr_un('/tmp/spec.socket'))
    msg = "<141>metad[2466]: TID 139915579090752: [metad.NOTICE]: Sending final query response for msg_id '117065370' (no error, has resp)"

    expect(mock_writer)
      .to receive(:send_event)
      .with(
        '@timestamp': "#{Time.now.year}-01-09T01:02:03.000Z",
        ecs: {
          version: ECS_VERSION,
        },
        event: {
          created: "2020-01-09T01:02:03.000Z",
        },
        host: {
          hostname: addrinfo.getnameinfo.first
        },
        log: {
          logger: 'Syslogstash',
          original: msg,
          syslog: {
            facility: {
              code: 17,
              name: 'local1',
            },
            severity: {
              code: 5,
              name: 'notice',
            },
          },
        },
        process: {
          name: 'metad',
          pid: 2466,
        },
        message: "TID 139915579090752: [metad.NOTICE]: Sending final query response for msg_id '117065370' (no error, has resp)",
      )

    locked_time = Time.utc(2020, 1, 9, 1, 2, 3)
    allow(Time).to receive(:now).and_return(locked_time)
    reader.send(:process_message, msg, remote: addrinfo)
  end

  it "parses a multi-line message" do
    expect(mock_writer)
      .to receive(:send_event) do |e|
        expect(e[:message]).to eq("This is\na multiline\nmessage!")
      end

    reader.send(:process_message, "<74>Jan  2 03:04:05 myhost This is\na multiline\nmessage!")
  end

  it "parses an invalid UTF-8 message" do
    expect(mock_writer)
      .to receive(:send_event) do |e|
        expect(e[:message]).to eq("This is br\uFFFDken")
      end

    reader.send(:process_message, "<74>Jan  2 03:04:05 myhost This is br\xE2ken")
  end

  context "dropping messages" do
    before do
      mock_config.drop_regex = 'any.*thing|(b[ao]mbs and keys$)'
    end

    it "will correctly drop" do
      expect(mock_writer).not_to receive(:send_event)
      reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram[12345]: any7thing")
      reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram[12345]: full of bombs and keys")
    end
  end

  context "with some tags" do
    before do
      mock_config.add_fields.merge!(foo: 'bar', baz: 'wombat')
    end

    it "includes the tags" do
      expect(mock_writer)
        .to receive(:send_event) do |e|
          expect(e[:foo]).to eq('bar')
          expect(e[:baz]).to eq('wombat')
        end

      reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!")
    end
  end
end
