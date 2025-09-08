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

namespace CWE23_Relative_Path_Traversal__char_environment_ofstream_51 {

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

void badSink(char * data) { {
 ofstream outputFile;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 outputFile.open((char *)data);
 outputFile.close();
 }
}