# ifcheck
Nagios IfCheck Plugin. Slightly more flexible than the stock standard PERL script.
Also warns of link flapping and interface reindexing.

Preconditions:
The NAGIOS process *MUST* be started with NAGIOS_PLUGIN_STATE_DIRECTORY set to a directory that the NAGIOS process can write to.

Inclusion into an existing Nagios site configuration:

Something like the below needs to be added into the commands.cfg file.

define command {
        command_name    ifcheck
        command_line    /usr/local/libexec/ifcheck -H $HOSTADDRESS$ -C $_HOSTSNMPREAD$ -k $ARG1$
}
define command {
        command_name    ifcheck_descr
        command_line    /usr/local/libexec/ifcheck -H $HOSTADDRESS$ -C $_HOSTSNMPREAD$ -d $ARG1$
}
define command {
        command_name    ifcheck_noflap
        command_line    /usr/local/libexec/ifcheck -H $HOSTADDRESS$ -C $_HOSTSNMPREAD$ -k $ARG1$ -S
}

Then in whatever other cfg file holds the service definitions ( something like interfaces.cfg as referenced by the main nagios.cfg)

define service{
        service_description     Link-to-something
        use                     Service-Default
        host_name               Switch1
        check_command           ifcheck!10101
}

define service{
        service_description     Link-Gi0/1
        use                     Service-Default
        host_name               Switch1
        check_command           ifcheck_descr!GigabitEthernet0/1
}

define service{
        service_description     ISDN-Link
        use                     Service-Default
        host_name               SomeAwfulVoiceGateway
        check_command           ifcheck_noflap!1079772160
}

Which assumes the use of a service template called 'Service-Default'.
