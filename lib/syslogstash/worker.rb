# Common code shared between both readers and writers.
#
module Syslogstash::Worker
	# If you ever want to stop a reader, here's how.
	def stop
		if @worker
			@worker.kill
			@worker.join
			@worker = nil
		end
	end

	# If you want to wait for a reader to die, here's how.
	#
	def wait
		@worker.join
	end

	private

	def log
		puts "#{Time.now.strftime("%F %T.%L")} #{self.class} #{yield.to_s}"
	end

	def debug
		if ENV['DEBUG_SYSLOGSTASH']
			puts "#{Time.now.strftime("%F %T.%L")} #{self.class} #{yield.to_s}"
		end
	end
end
