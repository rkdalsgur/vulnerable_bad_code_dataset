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

#include <fstream>
using namespace std;

/* The two function below always return the same value, so a tool
 should be able to identify that calls to the functions will always
 return a fixed value. */
static int staticReturnsTrue() {
 return 1;
}

static int staticReturnsFalse() {
 return 0;
}

namespace CWE23_Relative_Path_Traversal__char_environment_ofstream_08 {

void bad() {
 char * data;
 char dataBuffer[FILENAME_MAX] = BASEPATH;
 data = dataBuffer;
 if(staticReturnsTrue()) { {
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
 ofstream outputFile;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 outputFile.open((char *)data);
 outputFile.close();
 }
}
printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");

#ifdef INCLUDEMAIN

using namespace CWE23_Relative_Path_Traversal__char_environment_ofstream_08; /* so that we can use good and bad easily */

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