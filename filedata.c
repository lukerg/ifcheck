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

int loadLastChange(const char* stateFilePath, long* value) {
	FILE* fp =fopen(stateFilePath,"r");
	if (!fp) {
		fprintf(stderr,"cant open %s to read state data, assuming no existing data\n",stateFilePath);
		*value=0;
		return 0;
	}
	else {
		fread(value,sizeof(long),1,fp);
		fclose(fp);
		return 1;
	}
	return 1;
}

void writeLastChange(const char* stateFilePath, long value) {
	FILE* fp =fopen(stateFilePath,"w+");
	if (!fp) {
		fprintf(stderr,"cant open %s to write state data, please fix(%s)\n",stateFilePath,strerror(errno));
	}
	else {
		fwrite(&value,sizeof(long),1,fp);
		fclose(fp);
	}
}

int loadIndexFromState(const char* stateFilePath, int* ifindex) {
	FILE* fp =fopen(stateFilePath,"r");
	int rc=0;
	int point;
	*ifindex=-1;
	if (!fp) {
		fprintf(stderr,"cant open %s to read index data\n",stateFilePath);
		return 0;
	}
	point = fseek(fp,sizeof(long),SEEK_SET);
	if ( point == 0 ) {
		fread(ifindex,sizeof(long),1,fp);
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

void writeStateIndex(const char* stateFilePath, int ifindex) {
	FILE* fp =fopen(stateFilePath,"w+"); /* must use update open */
	int point=0;
	if (!fp) {
		fprintf(stderr,"failed to open state file for update(%s)\n",strerror(errno));
	}
	point=fseek(fp,sizeof(long),SEEK_SET);

	if (point == -1) {
		//future BUG - this happens due to bad desgin of all filedata.c's routines
		fwrite(&point,sizeof(long),1,fp);
	}
	fwrite(&ifindex,sizeof(long),1,fp);
	fclose(fp);
}

