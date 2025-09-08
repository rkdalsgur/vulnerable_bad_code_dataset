/*
 * CWE: 23 Relative Path Traversal
 */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE23_Relative_Path_Traversal__char_environment_fopen_83.h"

#define ENV_VARIABLE "ADD"

#ifdef _WIN32
#define GETENV getenv
#else
#define GETENV getenv
#endif

#ifdef _WIN32
#define FOPEN fopen
#else
#define FOPEN fopen
#endif

namespace CWE23_Relative_Path_Traversal__char_environment_fopen_83 {
CWE23_Relative_Path_Traversal__char_environment_fopen_83_bad::CWE23_Relative_Path_Traversal__char_environment_fopen_83_bad(char * dataCopy) {
 data = dataCopy; {
 /* Append input from an environment variable to data */
 size_t dataLen = strlen(data);
 char * environment = GETENV(ENV_VARIABLE);
 /* If there is data in the environment variable */
 if (environment != NULL) {
 /* VULNERABILITY: Read data from an environment variable */
 strncat(data+dataLen, environment, FILENAME_MAX-dataLen-1);
 }
 }
}

CWE23_Relative_Path_Traversal__char_environment_fopen_83_bad::~CWE23_Relative_Path_Traversal__char_environment_fopen_83_bad() { {
 FILE *pFile = NULL;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 pFile = FOPEN(data, "wb+");
 if (pFile != NULL) {
 fclose(pFile);
 }
 }
}
}
#endif /* OMITBAD */