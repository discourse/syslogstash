begin
  require 'git-version-bump'
rescue LoadError
  nil
end

Gem::Specification.new do |s|
  s.name = "syslogstash"

  s.version = GVB.version rescue "0.0.0.1.NOGVB"
  s.date    = GVB.date    rescue Time.now.strftime("%Y-%m-%d")

  s.platform = Gem::Platform::RUBY

  s.summary  = "Send messages from syslog UNIX sockets to logstash"

  s.authors  = ["Matt Palmer"]
  s.email    = ["matt.palmer@discourse.org"]
  s.homepage = "https://github.com/discourse/syslogstash"

  s.files = `git ls-files -z`.split("\0").reject { |f| f =~ /^(G|spec|Rakefile)/ }
  s.executables = ["syslogstash"]

  s.required_ruby_version = ">= 2.4.0"

  s.add_runtime_dependency 'deep_merge'
  s.add_runtime_dependency 'frankenstein'
  s.add_runtime_dependency 'logstash_writer'
  s.add_runtime_dependency 'rack'
  s.add_runtime_dependency 'service_skeleton', '= 0.0.0.44.g75d07d7'

  s.add_development_dependency 'bundler'
  s.add_development_dependency 'github-release'
  s.add_development_dependency 'guard-rspec'
  s.add_development_dependency 'rake', '~> 10.4', '>= 10.4.2'
  # Needed for guard
  s.add_development_dependency 'rb-inotify', '~> 0.9'
  s.add_development_dependency 'redcarpet'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'webmock'
  s.add_development_dependency 'yard'
end
