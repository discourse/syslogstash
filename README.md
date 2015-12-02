Feed everything from one or more syslog pipes to a logstash server.

# Installation

It's a gem:

    gem install syslogstash

There's also the wonders of [the Gemfile](http://bundler.io):

    gem 'syslogstash'

If you're the sturdy type that likes to run from git:

    rake install

Or, if you've eschewed the convenience of Rubygems entirely, then you
presumably know what to do already.


# Usage

Write a configuration file, then start `syslogstash` giving the name of the
config file as an argument:

    syslogstash /etc/syslogstash.conf

## Config File Format

The file which describes how `syslogstash` will operate is a fairly simple
YAML file.  It consists of two sections, `sockets` and `servers`, which list
the UNIX sockets to listen for syslog messages on, and the URLs of logstash
servers to send the resulting log entries to.  Optionally, you can specify
additional tags to insert into every message received from each syslog
socket.

It looks like this:

    sockets:
      # These sockets have no additional tags
      /tmp/sock1:
      /tmp/sock2:

      # This socket will have its messages tagged
      /tmp/taggedsock:
        foo: bar
        baz: wombat

    # Every log entry received will be sent to *exactly* one of these
    # servers.  This provides high availability for your log messages.
    # NOTE: Only tcp:// URLs are supported.
    servers:
      - tcp://10.0.0.1:5151
      - tcp://10.0.0.2:5151


## Logstash server configuration

You'll need to setup a TCP input, with the `json_lines` codec, for
`syslogstash` to send log entries to.  It can look as simple as this:

      tcp {
        port  => 5151
        codec => "json_lines"
      }


# Contributing

Bug reports should be sent to the [Github issue
tracker](https://github.com/discourse/syslogstash/issues).
Patches can be sent as a [Github pull
request](https://github.com/discourse/syslogstash/pulls].


# Licence

Unless otherwise stated, everything in this repo is covered by the following
copyright notice:

    Copyright (C) 2015 Civilized Discourse Construction Kit Inc.

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
