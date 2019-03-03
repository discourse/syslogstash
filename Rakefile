exec(*(["bundle", "exec", $PROGRAM_NAME] + ARGV)) if ENV['BUNDLE_GEMFILE'].nil?

task :default => :test

begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end

require 'yard'

YARD::Rake::YardocTask.new :doc do |yardoc|
  yardoc.files = %w{lib/**/*.rb - README.md}
end

desc "Run guard"
task :guard do
  sh "guard --clear"
end

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new :test do |t|
  t.pattern = "spec/**/*_spec.rb"
end

Bundler::GemHelper.install_tasks

task :release do
  sh "git release"
end

desc "Build and push a new docker image"
task :docker => ["docker:push"]

namespace :docker do
  desc "Build a new docker image"
  task :build => "^build" do
    sh "for repo in $(sed -n 's/^FROM //p' Dockerfile); do docker pull \"$repo\"; done"
    sh "docker build -t discourse/syslogstash:#{GVB.version} --build-arg=GEM_VERSION=#{GVB.version} --build-arg=http_proxy=#{ENV['http_proxy']} ."
  end

  task :push => :build do
    sh "docker tag discourse/syslogstash:#{GVB.version} discourse/syslogstash:latest"
    sh "docker push discourse/syslogstash:#{GVB.version}"
    sh "docker push discourse/syslogstash:latest"
  end
end
