require_relative './spec_helper'
require "ostruct"

require 'syslogstash'

describe Syslogstash::SyslogReader do
  let(:base_env) do
    {
      "SYSLOGSTASH_LOGSTASH_SERVER" => "localhost:5151",
      "SYSLOGSTASH_SYSLOG_SOCKET"   => "/somewhere/funny",
    }
  end
  let(:env) { base_env }

  let(:mock_writer) { instance_double(LogstashWriter) }
  let(:syslogstash) { Syslogstash.new(env) }
  let(:reader) { Syslogstash::SyslogReader.new(syslogstash.config, mock_writer, syslogstash.metrics) }

  it "parses an all-features-on message" do
    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg['@version']).to eq('1')
        expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

        expect(msg[:hostname]).to eq('myhost')
        expect(msg[:program]).to eq('myprogram')
        expect(msg[:pid]).to eq(12345)
        expect(msg[:syslog_timestamp]).to eq('Jan  2 03:04:05')
        expect(msg[:message]).to eq("I'm on a boat!")
        expect(msg[:severity_name]).to eq('crit')
        expect(msg[:facility_name]).to eq('cron')
      end

    reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!")
  end

  it "parses a no-PID message" do
    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg['@version']).to eq('1')
        expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

        expect(msg[:hostname]).to eq('myhost')
        expect(msg[:program]).to eq('myprogram')
        expect(msg).to_not have_key(:pid)
        expect(msg[:syslog_timestamp]).to eq('Jan  2 03:04:05')
        expect(msg[:message]).to eq("I'm on a boat!")
        expect(msg[:severity_name]).to eq('crit')
        expect(msg[:facility_name]).to eq('cron')
      end

    reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram: I'm on a boat!")
  end

  it "parses a no-program message" do
    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg['@version']).to eq('1')
        expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

        expect(msg[:hostname]).to eq('myhost')
        expect(msg).to_not have_key(:program)
        expect(msg).to_not have_key(:pid)
        expect(msg[:syslog_timestamp]).to eq('Jan  2 03:04:05')
        expect(msg[:message]).to eq("I'm on a boat!")
        expect(msg[:severity_name]).to eq('crit')
        expect(msg[:facility_name]).to eq('cron')
      end

    reader.send(:process_message, "<74>Jan  2 03:04:05 myhost I'm on a boat!")
  end

  it "parses a (non-standard) no-hostname message" do
    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg['@version']).to eq('1')
        expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

        expect(msg).to_not have_key(:hostname)
        expect(msg[:program]).to eq('myprogram')
        expect(msg[:pid]).to eq(12345)
        expect(msg[:syslog_timestamp]).to eq('Jan  2 03:04:05')
        expect(msg[:message]).to eq("I'm on a boat!")
        expect(msg[:severity_name]).to eq('crit')
        expect(msg[:facility_name]).to eq('cron')
      end

    reader.send(:process_message, "<74>Jan  2 03:04:05 myprogram[12345]: I'm on a boat!")
  end

  it "parses an IOS message with hostname" do
    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg['@version']).to eq('1')
        expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

        expect(msg[:hostname]).to eq('switch01.sjc3')
        expect(msg[:program]).to eq('SEC_LOGIN-5-LOGIN_SUCCESS')
        expect(msg[:pid]).to be_nil
        expect(msg[:syslog_timestamp]).to eq('Sep 16 18:17:23.009')
        expect(msg[:message]).to eq("Login Success [user: admin]")
        expect(msg[:severity_name]).to eq('notice')
        expect(msg[:facility_name]).to eq('local3')
      end

    reader.send(:process_message, "<157>6214: switch01.sjc3: Sep 16 18:17:23.009: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin]")
  end

  it "parses an IOS message without hostname" do
    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg['@version']).to eq('1')
        expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

        expect(msg[:hostname]).to be_nil
        expect(msg[:program]).to eq('SEC_LOGIN-5-LOGIN_SUCCESS')
        expect(msg[:pid]).to be_nil
        expect(msg[:syslog_timestamp]).to eq('Sep 16 18:17:23.009')
        expect(msg[:message]).to eq("Login Success [user: admin]")
        expect(msg[:severity_name]).to eq('notice')
        expect(msg[:facility_name]).to eq('local3')
      end

    reader.send(:process_message, "<157>6214: Sep 16 18:17:23.009: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin]")
  end

  it "adds information to a message with no timestamp or hostname received over IPv4" do
    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg['@version']).to eq('1')
        expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

        expect(msg[:hostname]).to eq '172.16.1.142'
        expect(msg[:program]).to eq('snmpd')
        expect(msg[:pid]).to eq 26572
        expect(msg[:syslog_timestamp]).to eq('Jan  9 01:02:03')
        expect(msg[:message]).to eq("[snmpd.NOTICE]: Got SNMP request from ip 172.16.1.100")
        expect(msg[:severity_name]).to eq('notice')
        expect(msg[:facility_name]).to eq('local7')
      end

    locked_time = Time.utc(2020, 1, 9, 1, 2, 3)
    allow(Time).to receive(:now).and_return(locked_time)
    addrinfo = Addrinfo.new(Socket.sockaddr_in(54321, '172.16.1.142'))
    reader.send(:process_message, "<189>snmpd[26572]: [snmpd.NOTICE]: Got SNMP request from ip 172.16.1.100", remote: addrinfo)
  end

  it "adds information to a message with no timestamp or hostname received over IPv6" do
    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg['@version']).to eq('1')
        expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

        expect(msg[:hostname]).to eq '2001:db8::f00f:1'
        expect(msg[:program]).to eq('snmpd')
        expect(msg[:pid]).to eq 26572
        expect(msg[:syslog_timestamp]).to eq('Jan  9 01:02:03')
        expect(msg[:message]).to eq("[snmpd.NOTICE]: Got SNMP request from ip 172.16.1.100")
        expect(msg[:severity_name]).to eq('notice')
        expect(msg[:facility_name]).to eq('local7')
      end

    locked_time = Time.utc(2020, 1, 9, 1, 2, 3)
    allow(Time).to receive(:now).and_return(locked_time)
    addrinfo = Addrinfo.new(Socket.sockaddr_in(54321, '2001:db8::f00f:1'))
    reader.send(:process_message, "<189>snmpd[26572]: [snmpd.NOTICE]: Got SNMP request from ip 172.16.1.100", remote: addrinfo)
  end

  it "adds information to a message with no timestamp or hostname received over a unix socket" do
    addrinfo = Addrinfo.new(Socket.sockaddr_un('/tmp/spec.socket'))

    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg['@version']).to eq('1')
        expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

        expect(msg[:hostname]).to eq "#{addrinfo.getnameinfo.first}"
        expect(msg[:program]).to eq('metad')
        expect(msg[:pid]).to eq 2466
        expect(msg[:syslog_timestamp]).to eq('Jan  9 01:02:03')
        expect(msg[:message]).to eq("TID 139915579090752: [metad.NOTICE]: Sending final query response for msg_id '117065370' (no error, has resp)")
        expect(msg[:severity_name]).to eq('notice')
        expect(msg[:facility_name]).to eq('local1')
      end

    locked_time = Time.utc(2020, 1, 9, 1, 2, 3)
    allow(Time).to receive(:now).and_return(locked_time)
    reader.send(:process_message, "<141>metad[2466]: TID 139915579090752: [metad.NOTICE]: Sending final query response for msg_id '117065370' (no error, has resp)", remote: addrinfo)
  end

  it "parses a multi-line message" do
    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg[:message]).to eq("This is\na multiline\nmessage!")
      end

    reader.send(:process_message, "<74>Jan  2 03:04:05 myhost This is\na multiline\nmessage!")
  end

  it "parses an invalid UTF-8 message" do
    expect(mock_writer)
      .to receive(:send_event) do |msg|
        expect(msg[:message]).to eq("This is br\uFFFDken")
      end

    reader.send(:process_message, "<74>Jan  2 03:04:05 myhost This is br\xE2ken")
  end

  context "dropping messages" do
    let(:env) do
      base_env.merge(
        "SYSLOGSTASH_DROP_REGEX" => 'any.*thing|(b[ao]mbs and keys$)'
      )
    end

    it "will correctly drop" do
      expect(mock_writer).not_to receive(:send_event)
      reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram[12345]: any7thing")
      reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram[12345]: full of bombs and keys")
    end

  end

  context "with some tags" do
    let(:env) do
      base_env.merge(
        'SYSLOGSTASH_ADD_FIELD_foo' => 'bar',
        'SYSLOGSTASH_ADD_FIELD_baz' => 'wombat'
      )
    end

    it "includes the tags" do
      expect(mock_writer)
        .to receive(:send_event) do |msg|
         expect(msg[:foo]).to eq('bar')
         expect(msg[:baz]).to eq('wombat')
        end

      reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!")
    end
  end
end
