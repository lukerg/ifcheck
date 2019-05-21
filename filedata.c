#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>
#include <sys/stat.h>

const char* env_nps ="NAGIOS_PLUGIN_STATE_DIRECTORY";

void recursemkdir(const char* path) {
	char* partialPath=0;
	int totalindex=1;
	int index=strpos(path+1,'/');
	while ( index ) {
		partialPath=strndup(path,totalindex+ index);
		if ( access(partialPath, F_OK) != 0 )
			mkdir(partialPath,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		totalindex=totalindex+ index+1;
		free(partialPath);
		index=strpos(path+totalindex+1,'/');
		totalindex++;
	}
}

const char* makeStateFilePath(char*progname, char*hostname, const char* key, char** envp) {
	char* candidate, *directory;
	char* fullpath=0;
	int index;
	for (index=0;envp[index]!=0;index++) {
		candidate=envp[index];
		if ( !strncmp(env_nps,candidate,strlen(env_nps)) ) {
			char* eqsign=strchr(candidate,'=');
			if ( !eqsign ) {
					fputs("environment variable NAGIOS_PLUGIN_STATE_DIRECTORY malformed",stderr);
					break; /* handled below */
			}
			candidate=eqsign+1;
			fullpath=(char*)malloc(sizeof(char)*1024);
			snprintf(fullpath,1024,"%s/%i/%s/%s_%s.state",
				candidate,
				getuid(),
				progname,
				hostname,
				key
				);
			directory=(char*)malloc(sizeof(char)*1024);
			snprintf(directory,1024,"%s/%i/%s",candidate,getuid(),progname);
			break;
		}
	}
	if ( !fullpath ) {
		fputs("environment variable NAGIOS_PLUGIN_STATE_DIRECTORY unset, please fix\n",stderr);
	}
	else { 
		recursemkdir(directory);
	}
	return fullpath;
}

/*
	check if file exists, open as new if it doesnt
	otherwise open in read/write mode
	since there is no non truncate variant of w+
*/
FILE* sfp_write_open(const char* sfpath) {
	int rc;

	rc=access(sfpath,F_OK);
	if ( rc == 0 ) /* file exists, use read write at beginning of file */
		return fopen(sfpath, "r+");
	else
		return fopen(sfpath, "w");
}

int loadLastChange(const char* stateFilePath, long* value) {
	int rc=0;
	FILE* fp =fopen(stateFilePath,"r");
	if (!fp) {
		fprintf(stderr,"cant open %s to read state data, assuming no existing data\n",stateFilePath);
		*value=0;
	}
	else {
		int bytes=fread(value,sizeof(long),1,fp);
		if ( bytes && *value != 0)
			rc=1; /* only good response comes from here */
		fclose(fp);
	}
	return rc;
}

void writeLastChange(const char* stateFilePath, long value) {
	FILE* fp =sfp_write_open(stateFilePath);
	if (!fp) {
		fprintf(stderr,"cant open %s to write state data, please fix(%s)\n",stateFilePath,strerror(errno));
	}
	else {
		fwrite(&value,sizeof(long),1,fp);
		fclose(fp);
	}
}

int loadIndexFromState(const char* stateFilePath, long* ifindex) {
	FILE* fp =fopen(stateFilePath,"r");
	int rc=0;
	long point;
	*ifindex=-1;
	if (!fp) {
		fprintf(stderr,"cant open %s to read index data\n",stateFilePath);
		return 0;
	}
	point = fseek(fp,sizeof(long),SEEK_SET);
	if ( point == 0 && fread(ifindex,sizeof(long),1,fp) ) {
		rc=1; /* only successful response comes from here */
	}
	else {
		fputs("no stored index data\n",stderr);
		rc=-1;
		*ifindex=-1;
	}
	fclose(fp);
	return rc;
}

void writeStateIndex(const char* stateFilePath, long ifindex) {
	FILE* fp =sfp_write_open(stateFilePath);
	int point=0;
	int bytes=0;
	if (!fp) {
		fprintf(stderr,"failed to open state file for update(%s)\n",strerror(errno));
		return;
	}
	point=fseek(fp,sizeof(long),SEEK_SET);

/* taken out for now
	fprintf(stderr,"point is %li, ifindex is %li\n", point,ifindex);
	if (point == -1 || point == 0) {
		long dummy = 0x6262;
		//future BUG - this happens due to bad desgin of all filedata.c's routines
		fputs("hit pad file bug\n",stderr);
		bytes=fwrite(&dummy,sizeof(long),1,fp);
		if ( bytes == 0 )
			fputs("failed to pad file\n",stderr);
	}
*/
	bytes=fwrite(&ifindex,sizeof(long),1,fp);
	if ( bytes == 0 )
		fputs("failed to write index!\n",stderr);
	fclose(fp);
}

