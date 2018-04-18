Syslogstash is intended to provide a syslog-compatible socket for one or
more applications to send their syslog messages to.  The messages are then
parsed and sent to a logstash server for posterity.  No more needing to run
a syslog server that writes to a file, just to have a second program that
reads those files again.  With syslogstash, everything is in one neat little
package.

If you're running a containerised environment, there's a reasonable chance
you've got multiple things that want to log to syslog, but you want to keep
them organised and separate.  That's easy: just run multiple syslogstash
instances, one per "virtual syslog socket" you want to provide.  Multiple
containers can share the same socket, they'll just share a logstash
connection and have the same metadata / extra tags.

For maximum flexibility, you can optionally feed the syslog messages to one
or more other "downstream" sockets, and/or print all the log messages to
stdout for ad-hoc "local" debugging.


# Installation

It's a gem:

    gem install syslogstash

There's also the wonders of [the Gemfile](http://bundler.io):

    gem 'syslogstash'

If you're the sturdy type that likes to run from git:

    rake install

Or, if you've eschewed the convenience of Rubygems entirely, then you
presumably know what to do already.

## Docker

Published image at https://hub.docker.com/r/discourse/syslogstash/

To build a new Docker image, run `rake docker:build`.  A `rake docker:push`
will push out a new release.


# Usage

Syslogstash is configured by means of environment variables.  At the very
least, `syslogstash` needs to know where logstash is (`LOGSTASH_SERVER`),
and the socket to listen on for syslog messages (`SYSLOG_SOCKET`).  You
specify those on the command line, like so:

    LOGSTASH_SERVER=logstash-json \
      SYSLOG_SOCKET=/dev/log \
      syslogstash

The full set of environment variables, and their meaning, is described in
the "Syslogstash Configuration" section, below.


## Logstash server setup

The logstash server(s) you send the collected messages to must be configured
to listen on a TCP port with the `json_lines` codec.  This can be done quite
easily as follows:

      tcp {
        port  => 5151
        codec => "json_lines"
      }

Adjust the port number to taste.


## Signals

There are a few signals that syslogstash recognises, to control various
aspects of runtime operation.  They are:

* **`SIGUSR1`** / **`SIGUSR2`** -- tell syslogstash to increase (`USR1`) or
  decrease (`USR2`) the verbosity of its own internal logging.  This doesn't
  change in *any* way the nature or volume of syslog messages that are
  processed and sent to logstash, it is *only* for syslogstash's own internal
  operational logging.

* **`SIGURG`** -- toggle whether or not relaying to stdout is enabled or
  disabled.


## Use with Docker

For convenience, `syslogstash` is available in a Docker container,
`discourse/syslogstash:v2`.  It requires a bit of gymnastics to get the
syslog socket from the `syslogstash` container to whatever container you
want to capture syslog messages from.  Typically, you'll want to share a
volume between the two containers, tell `syslogstash` to create its socket
there, and then symlink `/dev/log` from the other container to there.

For example, you might start the syslogstash container like this:

    docker run -v /srv/docker/syslogstash:/syslogstash \
      -e LOGSTASH_SERVER=logstash-json \
      -e SYSLOG_SOCKET=/syslogstash/log.sock \
      discourse/syslogstash:v2

Then use the same volume in your other container:

    docker run -v /srv/docker/syslogstash:/syslogstash something/funny

In the other container's startup script, include the following command:

    ln -sf /syslogstash/log.sock /dev/log

... and everything will work nicely.

If you feel like playing on nightmare mode, you can also mount the log
socket directly into the other container, like this:

    docker run -v /srv/docker/syslogstash/log.sock:/dev/log something/funny

This allows you to deal with poorly-implemented containers which run
software that logs to syslog but doesn't provide a way to override where
`/dev/log` points.  *However*, due to the way bind mounts and Unix sockets
interact, if the syslogstash container restarts *for any reason*, you also
need to restart any containers that have the socket itself as a volume.  If
you can coax your container management system into satisfying that
condition, then you're golden.


# Syslogstash Configuration

All configuration of syslogstash is done by placing values in environment
variables.  The environment variables that syslogstash recognises are listed
below.

* **`LOGSTASH_SERVER`** (required) -- the domain name or address of the
  logstash server(s) you wish to send entries to.  This can be any of:

  * An IPv4 address and port, separated by a colon.  For example,
    `192.0.2.42:5151`.  The port *must* be specified.

  * An IPv6 address (enclosed in square brackets) and port, separated by a
    colon.  For example, `[2001:db8::42]:5151`.  The port *must* be
    specified.

  * A fully-qualified or relative domain name and port, separated by a
    colon.  The name given will be resolved and all IPv4 and IPv6
    addresses returned will be tried in random order until a successful
    connection is made to one of them.  The port *must* be specified.

  * A fully-qualified or relative domain name *without a port*.  In this
    case, the name given will be resolved as a SRV record, and the names and
    ports returned will be used.

  In all cases, syslogstash respects DNS record TTLs and SRV record
  weight/priority selection rules.  We're not monsters.

* **`SYSLOG_SOCKET`** (required) -- the absolute path to the socket which
  syslogstash should create and listen on for syslog format messages.

* **`BACKLOG_SIZE`** (optional; default `"1000000"`) -- the maximum number of
  messages to queue if the logstash servers are unavailable.  Under normal
  operation, syslog messages are immediately relayed to the logstash server
  as they are received.  However, if no logstash servers are available,
  syslogstash will maintain a backlog of up to this many syslog messages,
  and will send the entire backlog once a logstash server becomes available
  again.

    In the event that the queue size limit is reached, the oldest messages
    will be dropped to make way for the new ones.

* **`RELAY_TO_STDOUT`** (optional; default `"no"`) -- if set to a
  true-ish string (any of `true`, `yes`, `on`, or `1`, compared
  case-insensitively), then all the syslog messages which are received will
  be printed to stdout (with the priority/facility prefix removed).  This
  isn't a replacement for a fully-featured syslog server, merely a quick way
  to dump messages if absolutely required.

* **`STATS_SERVER`** (optional; default `"no"`) -- if set to a true-ish
  string (any of `true`, `yes`, `on`, or `1`, compared case-insensitively),
  then a Prometheus-compatible statistics exporter will be started,
  listening on all interfaces on port 9159.

* **`ADD_FIELD_<name>`** (optional) -- if you want to add extra fields to
  the entries which are forwarded to logstash, you can specify them here,
  for example:

        ADD_FIELD_foo=bar ADD_FIELD_baz=wombat [...] syslogstash

    This will cause all entries sent to logstash to contain `"foo": "bar"`
    and `"baz": "wombat"`, in addition to the rest of the fields usually
    created by syslogstash.  Note that nested fields, and value types other
    than strings, are not supported.  Also, if you specify a field name also
    used by syslogstash, the results are explicitly undefined.

* **`RELAY_SOCKET`** (optional; default `""`) -- on the off-chance you want
  to feed the syslog messages that syslogstash receives to another
  syslog-compatible consumer (say, an old-school syslogd) you can specify
  additional filenames to use here.  Multiple socket filenames can be
  specified by separating each file name with a colon.  Syslogstash will open
  each of the specified sockets, if they exist, and write each received
  message to the socket.  If the socket does not exist, or the open or write
  operations fail, syslogstash **will not** retry.


# Contributing

Bug reports should be sent to the [Github issue
tracker](https://github.com/discourse/syslogstash/issues).
Patches can be sent as a [Github pull
request](https://github.com/discourse/syslogstash/pulls].


# Licence

Unless otherwise stated, everything in this repo is covered by the following
copyright notice:

    Copyright (C) 2015, 2018 Civilized Discourse Construction Kit Inc.

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
