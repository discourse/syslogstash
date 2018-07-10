require 'logger'

class Syslogstash::Config
	class ConfigurationError < StandardError; end

	# Raised if any problems were found with the config
	class InvalidEnvironmentError < StandardError; end

	attr_reader :logstash_server,
	            :syslog_socket,
	            :backlog_size,
	            :stats_server,
	            :add_fields,
	            :relay_sockets,
              :drop_regex

	attr_reader :logger

	attr_accessor :relay_to_stdout

	# Create a new syslogstash config based on environment variables.
	#
	# Examines the environment passed in, and then creates a new config
	# object if all is well.
	#
	# @param env [Hash] the set of environment variables to use.
	#
	# @param logger [Logger] the logger to which all diagnostic and error
	#   data will be sent.
	#
	# @raise [ConfigurationError] if any problems are detected with the
	#   environment variables found.
	#
	def initialize(env, logger:)
		@logger = logger

		parse_env(env)
	end

	private

	def parse_env(env)
		@logger.info("config") { "Parsing environment:\n" + env.map { |k, v| "#{k}=#{v.inspect}" }.join("\n") }

		@logstash_server = pluck_string(env, "LOGSTASH_SERVER")
		@syslog_socket   = pluck_string(env, "SYSLOG_SOCKET")
		@relay_to_stdout = pluck_boolean(env, "RELAY_TO_STDOUT", default: false)
		@stats_server    = pluck_boolean(env, "STATS_SERVER", default: false)
		@backlog_size    = pluck_integer(env, "BACKLOG_SIZE", valid_range: 0..(2**31 - 1), default: 1_000_000)
		@add_fields      = pluck_prefix_list(env, "ADD_FIELD_")
		@relay_sockets   = pluck_path_list(env, "RELAY_SOCKETS", default: [])

    regex = env["DROP_REGEX"]
    if regex && !regex.empty?
      @drop_regex = Regexp.new(regex)
    end
	end

	def pluck_string(env, key, default: nil)
		maybe_default(env, key, default) { env[key] }
	end

	def pluck_boolean(env, key, default: nil)
		maybe_default(env, key, default) do
			case env[key]
			when /\A(no|off|0|false)\z/
				false
			when /\A(yes|on|1|true)\z/
				true
			else
				raise ConfigurationError,
				      "Value for #{key} (#{env[key].inspect}) is not a valid boolean"
			end
		end
	end

	def pluck_integer(env, key, valid_range: nil, default: nil)
		maybe_default(env, key, default) do
			if env[key] !~ /\A\d+\z/
				raise InvalidEnvironmentError,
				      "Value for #{key} (#{env[key].inspect}) is not an integer"
			end

			env[key].to_i.tap do |v|
				unless valid_range.nil? || !valid_range.include?(v)
					raise InvalidEnvironmentError,
					      "Value for #{key} (#{env[key]}) out of range (must be between #{valid_range.first} and #{valid_range.last} inclusive)"
				end
			end
		end
	end

	def pluck_prefix_list(env, prefix)
		{}.tap do |list|
			env.each do |k, v|
				next unless k.start_with? prefix
				key = k.sub(prefix, '')
				list[key] = v
			end

			@logger.debug("config") { "Prefix list for #{prefix.inspect} is #{list.inspect}" }
		end
	end

	def pluck_path_list(env, key, default: nil)
		maybe_default(env, key, default) do
			env[key].split(":")
		end
	end

	def maybe_default(env, key, default)
		if env[key].nil? || env[key].empty?
			if default.nil?
				raise ConfigurationError,
				      "Required environment variable #{key} not specified"
			else
				@logger.debug("config") { "Using default value #{default.inspect} for config parameter #{key}" }
				default
			end
		else
			yield.tap { |v| @logger.debug("config") { "Using plucked value #{v.inspect} for config parameter #{key}" } }
		end
	end
end
