# Last Modified: Wed Nov  5 03:32:59 2008

abi <abi/4.0>,

include <tunables/global>

profile firefox.sh /usr/lib/firefox/firefox.sh {
  include <abstractions/base>
  include <abstractions/bash>
  include <abstractions/consoles>

  deny capability sys_ptrace,

  /usr/lib/firefox/firefox.sh mr,

  /{usr/,}bin/basename rix,
  /{usr/,}bin/bash rix,
  /{usr/,}bin/grep rix,
  /etc/magic r,
  /usr/bin/file rix,
  /usr/lib/firefox/firefox px,
  /usr/share/misc/magic.mgc r,

  # Site-specific additions and overrides. See local/README for details.
  include if exists <local/firefox.sh>
}
