/*
 * CWE: 23 Relative Path Traversal
 */

#include "std_testcase.h"

#ifdef _WIN32
#define BASEPATH "c:\\temp\\"
#else
#include <wchar.h>
#define BASEPATH "/tmp/"
#endif

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

/* The two variables below are not defined as "const", but are never
 assigned any other value, so a tool should be able to identify that
 reads of these will always return their initialized values. */
static int staticTrue = 1; /* true */
static int staticFalse = 0; /* false */

namespace CWE23_Relative_Path_Traversal__char_environment_fopen_05 {

void bad() {
 char * data;
 char dataBuffer[FILENAME_MAX] = BASEPATH;
 data = dataBuffer;
 if(staticTrue) { {
 /* Append input from an environment variable to data */
 size_t dataLen = strlen(data);
 char * environment = GETENV(ENV_VARIABLE);
 /* If there is data in the environment variable */
 if (environment != NULL) {
 /* VULNERABILITY: Read data from an environment variable */
 strncat(data+dataLen, environment, FILENAME_MAX-dataLen-1);
 }
 }
 } {
 FILE *pFile = NULL;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 pFile = FOPEN(data, "wb+");
 if (pFile != NULL) {
 fclose(pFile);
 }
 }
}
printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");

#ifdef INCLUDEMAIN

using namespace CWE23_Relative_Path_Traversal__char_environment_fopen_05; /* so that we can use good and bad easily */

int main(int argc, char * argv[]) {
 /* seed randomness */
 srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
 printLine("Calling good()...");
 good();
 printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
 printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");
#endif /* OMITBAD */
 return 0;
}

#endif