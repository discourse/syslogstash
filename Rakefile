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

docker_repo = ENV["DOCKER_REPO"] || "discourse/syslogstash"
docker_tag  = ENV["DOCKER_TAG"]  || GVB.version

namespace :docker do
  desc "Build a new docker image"
  task :build => "^build" do
    sh "docker build --pull -t #{docker_repo}:#{docker_tag} --build-arg=GEM_VERSION=#{ENV["GEM_VERSION"] || GVB.version} --build-arg=http_proxy=#{ENV['http_proxy']} ."
    unless ENV["DOCKER_NO_LATEST"]
      sh "docker tag #{docker_repo}:#{docker_tag} #{docker_repo}:latest"
    end
  end

  desc "Upload image to a docker image registry"
  task :publish => :build do
    sh "docker push #{docker_repo}:#{docker_tag}"
    unless ENV["DOCKER_NO_LATEST"]
      sh "docker push #{docker_repo}:latest"
    end
  end
end
