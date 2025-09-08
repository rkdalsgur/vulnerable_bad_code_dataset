/*
 * CWE: 23 Relative Path Traversal
 */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE23_Relative_Path_Traversal__char_environment_ifstream_84.h"

#define ENV_VARIABLE "ADD"

#ifdef _WIN32
#define GETENV getenv
#else
#define GETENV getenv
#endif

#include <fstream>
using namespace std;

namespace CWE23_Relative_Path_Traversal__char_environment_ifstream_84 {
CWE23_Relative_Path_Traversal__char_environment_ifstream_84_bad::CWE23_Relative_Path_Traversal__char_environment_ifstream_84_bad(char * dataCopy) {
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

CWE23_Relative_Path_Traversal__char_environment_ifstream_84_bad::~CWE23_Relative_Path_Traversal__char_environment_ifstream_84_bad() { {
 ifstream inputFile;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 inputFile.open((char *)data);
 inputFile.close();
 }
}
}
#endif /* OMITBAD */