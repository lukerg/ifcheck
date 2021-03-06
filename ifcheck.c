#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "filedata.h"

/* definitions */

const char* stroid_ifmibdesc		=".1.3.6.1.2.1.2.2.1.2";
const char* stroid_ifmiboperstatus	=".1.3.6.1.2.1.2.2.1.8";
const char* stroid_ifmiblastchange	=".1.3.6.1.2.1.2.2.1.9";

enum enummib {
	e_ifmibdesc,
	e_ifmiboperstatus,
	e_ifmiblastchange
};

enum {
	NAGIOS_OK,
	NAGIOS_WARN,
	NAGIOS_CRIT,
	NAGIOS_UNK
};

static int lookup_debug_out = 0;

size_t buildInstanceOID(oid* pOID, enum enummib em, int instance );

/* helper routines */

size_t strpos(const char* str, char c) {
	size_t rval=0;
	while ( str[rval] != 0 && str[rval] != c)
		rval++;
	return rval;
}

char attemptLookup(netsnmp_session* ss, const char* ifdescr, long* pIfDesc) {
	int status=0,searching=1,localidx=0;
	netsnmp_pdu *response=0;
	netsnmp_variable_list *vars;
	oid ifdOID[MAX_OID_LEN];
	size_t ifdOID_len, total_ifs=0;

	while ( searching ) {
		netsnmp_pdu* spdu = snmp_pdu_create(SNMP_MSG_GETBULK);
		spdu->non_repeaters=0;
		spdu->max_repetitions=100;
		if ( lookup_debug_out )
			fprintf(stderr,"building pdu with index %i\n",localidx);
		ifdOID_len=buildInstanceOID(ifdOID, e_ifmibdesc , localidx);
		snmp_add_null_var(spdu, ifdOID, ifdOID_len);
		status = snmp_synch_response(ss, spdu, &response);
		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
			for(vars = response->variables; vars; vars = vars->next_variable) {
				if ( snmp_oid_compare(ifdOID,ifdOID_len-1 , vars->name, vars->name_length-1) != 0 ) {
					if ( lookup_debug_out )
						fputs("reached end of ifDescr listing, interface not found!\n",stderr);
					searching = 0;
					break;
				}
				total_ifs++;
				localidx = vars->name [ vars->name_length-1 ];
				if (vars->type == ASN_OCTET_STR) {
					if (!strcmp(ifdescr,vars->val.string)){
						/* store the data */
						*pIfDesc=vars->name[vars->name_length-1];
						if ( lookup_debug_out )
							fprintf(stderr,"found %s on %i after looking at %i interfaces\n",
								ifdescr, *pIfDesc,total_ifs);
						snmp_free_pdu(response);
						return 'y';
					}
					else if ( lookup_debug_out )
						fprintf(stderr,"not mached %s\n", vars->val.string);
				}
				else {
					fprintf(stderr,"attempLookup: weird data type %s, vars->type is %i\n",ifdescr,vars->type);
					fprint_objid(stderr,vars->name, vars->name_length);
					searching=0;
					break;
				}
			}

		}
		else {
			/* ** FAILURE: print what went wrong **/
			if (status == STAT_SUCCESS)
				fprintf(stderr, "Error in packet\nReason: %s\n",
						snmp_errstring(response->errstat));
			else if (status == STAT_TIMEOUT)
				fprintf(stderr, "Timeout: No response from %s.\n",
						ss->peername);
			else
				snmp_sess_perror("ifcheck", ss);
			break;
		}
	}
	snmp_free_pdu(response);
	if ( lookup_debug_out )
		fprintf(stderr,"searched %i but didnt find %s\n",total_ifs,ifdescr);
	return 'n';
}

size_t buildInstanceOID(oid* pOID, enum enummib em, int instance ) {
	size_t anOID_len;
	anOID_len = MAX_OID_LEN;
	const char* whichToGet;
	
	switch (em) {
		case e_ifmibdesc:
			whichToGet=stroid_ifmibdesc;
			break;
		case e_ifmiboperstatus:
			whichToGet=stroid_ifmiboperstatus;
			break;
		case e_ifmiblastchange:
			whichToGet=stroid_ifmiblastchange;
			break;
	}
	
	if (!snmp_parse_oid(whichToGet, pOID, &anOID_len)) {
		snmp_perror("failed to parse oid");
		return -1;
	}

	pOID[anOID_len]=instance;
	anOID_len++;

	return anOID_len;
}

/*single use function, meaning static buffer is okay*/
const char* genkey(long index, char* descr) {
	static char retbuf[256];
	memset(retbuf,0,256);
	if (index != -1)
		snprintf(retbuf,256,"%i",index);
	else {
		/*need to reinvent the wheel to handle certain bumps*/
		size_t i;

		for (i = 0; i < 255 && descr[i] != '\0'; i++)
			if ( descr[i] == '/' ) //ifdescr's contain slashes, replace them
				retbuf[i] = '-';
			else
				retbuf[i] = descr[i];
		for ( ; i < 255; i++)
			retbuf[i] = '\0';
	}
	return retbuf;
}

const char* usage_string="Usage: %s -H {ipaddress] -C {snmp community} [-d ifDesc] [-k ifindex] [-S]\n";

int main(int argc, char ** argv, char** envp)
{
    netsnmp_session session, *ss=0;
    netsnmp_pdu *pdu=0;
    netsnmp_pdu *response=0;

    oid anOID[MAX_OID_LEN];
    size_t anOID_len;

	netsnmp_variable_list *vars;
	int status;
	int count=1;
	char* iphost=0;
	char* snmpcommunity=0;
	char* ifdesc=0;
	const char* statefilepath;
	long ifindex=-1;
	int flags, opt;
	short silentFlaps=0;
	
	/*nagios return data */
	char* statusline=0;
	char* perfdata=0;
	int nagios_rc=NAGIOS_UNK; /*default to unknown*/
	
	while ((opt = getopt(argc, argv, "H:C:d:k:SD")) != -1) {
		switch (opt) {
			case 'H':
				iphost=strdup(optarg);
				break;
			case 'C':
				snmpcommunity=strdup(optarg);
				break;
			case 'd':
				ifdesc=strdup(optarg);
				break;
			case 'k':
				ifindex=atoi(optarg);
				break;
			case 'S':
				silentFlaps=1;
				break;
			case 'D':
				lookup_debug_out=1;
				break;
			default:
				fprintf(stderr,usage_string,argv[0]);
				goto exit;
		}
	}
	if ( !iphost || !snmpcommunity ) {
			fprintf(stderr,usage_string,argv[0]);
			goto exit;
	}
	if ( !ifdesc && ( ifindex < 1) ) {
			fprintf(stderr,usage_string,argv[0]);
			goto exit;
	}
/*
 ** Initialize the SNMP library
 **/
    init_snmp("ifcheck");
/*
 ** Initialize a "session" that defines who we're going to talk to
 **/
    snmp_sess_init( &session );                   /* set up defaults */
    session.peername = iphost;
    /* set up the authentication parameters for talking to the server */
    /* set the SNMP version number */
    session.version = SNMP_VERSION_2c;
    /* set the SNMPv2c community name used for authentication */
    session.community = snmpcommunity;
    session.community_len = strlen(snmpcommunity);
/*
 ** Open the session
 **/
    SOCK_STARTUP;
    ss = snmp_open(&session);                     /* establish the session */
    if (!ss) {
      snmp_sess_perror("ifcheck", &session);
      SOCK_CLEANUP;
      goto exit;
    }
    
	/* set the path up here, for possible use by the lookup routine */
	statefilepath=makeStateFilePath("ifcheck", iphost, genkey(ifindex,ifdesc), envp);
	if ( !statefilepath )
		goto exit;

	/* if supplied with only the interface name */
	if ( ifindex == -1 && ifdesc != 0 ) {
		/* first attempt to load data from state file */
		status = loadIndexFromState(statefilepath,&ifindex);
		if ( status != 1 ) {
			/* first time lookup required */
			char outcome;
			outcome = attemptLookup(ss,ifdesc,&ifindex);
			if ( outcome == 'n' ) {
				printf("UNK - device has no interface '%s'\n",ifdesc);
				goto exit;
			}
			else {
				/* guaranteed to have a good index number */
				writeStateIndex(statefilepath,ifindex);
			}
		}
	}
	
/*
 ** Create the PDU for the data for our request.
 **/
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	
	/* doing not nice things here, ask for ifDescr first to make processing easier*/

	/* fetch the description to detect reindexing by the host*/
	anOID_len=buildInstanceOID(anOID, e_ifmibdesc , ifindex );
	snmp_add_null_var(pdu, anOID, anOID_len);
	/* want to get the operation status of the interface */
	anOID_len=buildInstanceOID(anOID, e_ifmiboperstatus , ifindex );
	snmp_add_null_var(pdu, anOID, anOID_len);
	/* and the last change, to catch link flapping */
	anOID_len=buildInstanceOID(anOID, e_ifmiblastchange , ifindex );
	snmp_add_null_var(pdu, anOID, anOID_len);

/*
 ** Send the Request out.
 **/
	status = snmp_synch_response(ss, pdu, &response);

	statusline=(char*)malloc(sizeof(char) * 1024);
	perfdata=(char*)malloc(512);
	memset(statusline,0,sizeof(char) * 1024);
	memset(perfdata,0,sizeof(char) * 512);
/*
 ** Process the response.
 **/
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
		char* healthtag, *variable_print;
		long lastChangeData;
		int loadstatus;
		size_t offset=0;
		
		variable_print=(char*)malloc(sizeof(char) * 256);
		vars = response->variables;

	/* 1 - examine the description first */

		/* if no CLI provided description */
		if ( !ifdesc ) {
			if (!vars) {
				fprintf(stderr,"non fatal problem of not getting an ifdesc back from host %s, try to fix this",iphost);
				ifdesc=strdup("mystery interface! (fix this if possible)"); /* put something into here */
			}
			else if ( vars->type != ASN_OCTET_STR)  { /* very strange but lets try to handle it gracefully */
				fprintf(stderr,"non fatal problem of host %s sending a non octet string back",iphost);
				ifdesc=strdup("garbled interface description, try to fix this");
			}
			else { /* somehow the data was valid, despite fate's best efforts to stop us */
				ifdesc = (char *)malloc(1 + vars->val_len);
				memcpy(ifdesc, vars->val.string, vars->val_len);
				ifdesc[vars->val_len] = '\0';
			}
		}
		else { /*otherwise, check that the returned ifDescr matches the CLI supplied one*/
			if (!strcmp(ifdesc,vars->val.string) ) {
				long oldindex=ifindex;
				char outcome = attemptLookup(ss,ifdesc,&ifindex);
				if ( outcome == 'n' ) { /* interface no longer exists at all? that is critical*/
					nagios_rc=NAGIOS_CRIT;
					healthtag="REMOVED!";
				}
				else {
					fprintf(stderr,"detected reindex of %s on %s from %li to %li\n",ifdesc,iphost,oldindex,ifindex);
					writeStateIndex(statefilepath,ifindex);
				}
			}
		}

	/* 2 - examine the operational status of the interface */
		vars = vars->next_variable;
		if (vars->type == ASN_INTEGER) {
			switch (*vars->val.integer) {
				case 1: /*up*/
					nagios_rc=NAGIOS_OK;
					healthtag="OK";
					break;
				case 2: /*down*/
					nagios_rc=NAGIOS_CRIT;
					healthtag="CRITICAL";
					break;
				case 5: /*dormant is bad for all EXCEPT Dialer interfaces*/
				{
					const char *descr_dialer="Dialer";
					if ( strncmp(descr_dialer, ifdesc, 6) == 0 ) {
						/* dont want to spam stderr with this dormant interface being okay */
						nagios_rc=NAGIOS_OK;
						healthtag="OK(dormant)";
						break;
					}
					else {
						/* not a dialer, this is not good */
						nagios_rc=NAGIOS_UNK;
						healthtag="UNKNOWN(dormant)";
						break;
					}
				}
				default: /*everything else is suspicious*/
					nagios_rc=NAGIOS_WARN;
					healthtag="WARNING";
					break;
			}
		}
		else if ( vars->type == SNMP_NOSUCHINSTANCE ) {
			fprintf(stderr, "host says it doesnt have an instance %i\n",ifindex );
			goto exit;
		}
		else {
			fprintf(stderr, "wanted an integer for ifoper check but got %i\n",vars->type);
		}

 		offset=snprint_variable(variable_print+offset,1024-offset,vars->name,vars->name_length,vars);
		
	/* 3 - examine the iflastchange data */
		vars = vars->next_variable;
		if (!vars) {
			puts("UNK - SNMP ifLastChange data missing, device unhealthy");
			goto exit;
		}
		if ( vars->type != ASN_TIMETICKS ) {
			puts("UNK - SNMP data type error for lastchange, device unhealthy");
			goto exit;
		}

		/* load data, if present then compare values */
		loadstatus=loadLastChange(statefilepath,&lastChangeData);
		memset(perfdata,0,512);
		if ( loadstatus ) {
			long delta = *vars->val.integer - lastChangeData;
			int bytes=snprintf(perfdata,512,"lastchange=%u",*vars->val.integer);
			if ( delta != 0) {
				perfdata[bytes]=',';
				snprintf(perfdata+bytes+1,512-bytes,"delta=%li,previous=%li",delta,lastChangeData);
				if ( !silentFlaps ){
					nagios_rc=NAGIOS_WARN;
					healthtag="WARNING - link flap";
				}
				else {
					healthtag ="OK(f)";
				}
				writeLastChange(statefilepath,*vars->val.integer);
			}
		}
		else
			writeLastChange(statefilepath,*vars->val.integer);

	/* 4 - format data for presentation to Nagios process */
		/* below code expects that ifdesc is populated either via arguments or the above code block */
		snprintf(statusline,1024,"%s %s %s",healthtag,ifdesc,variable_print);
	
		free(variable_print);
    } else {
		/* ** FAILURE: print what went wrong **/
		if (status == STAT_SUCCESS)
			snprintf(statusline,1024, "Error in packet\nReason: %s",
					snmp_errstring(response->errstat));
		else if (status == STAT_TIMEOUT)
			snprintf(statusline,1024, "UNKNOWN - Timeout: No response from %s",
					session.peername);
		else
			snmp_sess_perror("ifcheck", ss);
    }

	/* the big moment - present data to nagios */
	printf("%s | %s\n",statusline,perfdata);

/*
 ** Clean up:
 **  1) free the response.
 **  2) close the session.
 **/
 exit:
	if (response) snmp_free_pdu(response);
	if(ss) snmp_close(ss);
	
	if (iphost) free(iphost);
	if (snmpcommunity) free(snmpcommunity);
	if ( ifdesc ) free(ifdesc);
	
	SOCK_CLEANUP;
	
	if (statusline) free(statusline);
	if (perfdata) free(perfdata);
	return (nagios_rc);
} /* main() */

