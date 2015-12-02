require_relative './spec_helper'
require 'syslogstash'

describe Syslogstash::SyslogReader do
	let(:mock_writer) { instance_double(Syslogstash::LogstashWriter) }
	let(:tags)        { {} }
	let(:reader)      { Syslogstash::SyslogReader.new(nil, tags, mock_writer) }

	it "parses an all-features-on message" do
		expect(mock_writer)
		  .to receive(:send_entry) do |json_msg|
		    msg = JSON.parse(json_msg)

		    expect(msg['@version']).to eq('1')
		    expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

		    expect(msg['hostname']).to eq('myhost')
		    expect(msg['program']).to eq('myprogram')
		    expect(msg['pid']).to eq(12345)
		    expect(msg['syslog_timestamp']).to eq('Jan  2 03:04:05')
		    expect(msg['message']).to eq("I'm on a boat!")
		    expect(msg['severity_name']).to eq('crit')
		    expect(msg['facility_name']).to eq('cron')
		  end

		reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!")
	end

	it "parses a no-PID message" do
		expect(mock_writer)
		  .to receive(:send_entry) do |json_msg|
		    msg = JSON.parse(json_msg)

		    expect(msg['@version']).to eq('1')
		    expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

		    expect(msg['hostname']).to eq('myhost')
		    expect(msg['program']).to eq('myprogram')
		    expect(msg).to_not have_key('pid')
		    expect(msg['syslog_timestamp']).to eq('Jan  2 03:04:05')
		    expect(msg['message']).to eq("I'm on a boat!")
		    expect(msg['severity_name']).to eq('crit')
		    expect(msg['facility_name']).to eq('cron')
		  end

		reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram: I'm on a boat!")
	end

	it "parses a no-program message" do
		expect(mock_writer)
		  .to receive(:send_entry) do |json_msg|
		    msg = JSON.parse(json_msg)

		    expect(msg['@version']).to eq('1')
		    expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

		    expect(msg['hostname']).to eq('myhost')
		    expect(msg).to_not have_key('program')
		    expect(msg).to_not have_key('pid')
		    expect(msg['syslog_timestamp']).to eq('Jan  2 03:04:05')
		    expect(msg['message']).to eq("I'm on a boat!")
		    expect(msg['severity_name']).to eq('crit')
		    expect(msg['facility_name']).to eq('cron')
		  end

		reader.send(:process_message, "<74>Jan  2 03:04:05 myhost I'm on a boat!")
	end

	it "parses a (non-standard) no-hostname message" do
		expect(mock_writer)
		  .to receive(:send_entry) do |json_msg|
		    msg = JSON.parse(json_msg)

		    expect(msg['@version']).to eq('1')
		    expect(msg['@timestamp']).to match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

		    expect(msg).to_not have_key('hostname')
		    expect(msg['program']).to eq('myprogram')
		    expect(msg['pid']).to eq(12345)
		    expect(msg['syslog_timestamp']).to eq('Jan  2 03:04:05')
		    expect(msg['message']).to eq("I'm on a boat!")
		    expect(msg['severity_name']).to eq('crit')
		    expect(msg['facility_name']).to eq('cron')
		  end

		reader.send(:process_message, "<74>Jan  2 03:04:05 myprogram[12345]: I'm on a boat!")
	end

	context "with some tags" do
		let(:tags) { { 'foo' => 'bar', 'baz' => 'wombat' } }

		it "includes the tags" do
			expect(mock_writer)
			  .to receive(:send_entry) do |json_msg|
				 msg = JSON.parse(json_msg)

				 expect(msg['foo']).to eq('bar')
				 expect(msg['baz']).to eq('wombat')
			  end

			reader.send(:process_message, "<74>Jan  2 03:04:05 myhost myprogram[12345]: I'm on a boat!")
		end
	end
end
