# ifcheck
Nagios IfCheck Plugin. Slightly more flexible than the stock standard PERL script.
Also warns of link flapping and interface reindexing.

Preconditions:
The NAGIOS process *MUST* be started with NAGIOS_PLUGIN_STATE_DIRECTORY set to a directory that the NAGIOS process can write to.

Refer to the example.cfg file for how to include this plugin into an existing site.

