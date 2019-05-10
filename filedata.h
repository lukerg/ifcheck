#ifndef __FILEDATA_H__
#define __FILEDATA_H__

/* key maybe either the string representation of the ifIndex or ifDescr */
const char* makeStateFilePath(char*progname, char*hostname, const char* key, char** envp);

int loadLastChange(const char* stateFilePath, long* value);
void writeLastChange(const char* stateFilePath, long value);
int loadIndexFromState(const char* stateFilePath, long* ifindex);
void writeStateIndex(const char* stateFilePath, long ifindex);

#endif //__FILEDATA_H__
