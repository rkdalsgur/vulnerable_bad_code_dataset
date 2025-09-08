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

extern char * CWE23_Relative_Path_Traversal__char_environment_ifstream_68_badData;
extern char * CWE23_Relative_Path_Traversal__char_environment_ifstream_68_goodG2BData;

namespace CWE23_Relative_Path_Traversal__char_environment_ifstream_68 {

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

void badSink() {
 char * data = CWE23_Relative_Path_Traversal__char_environment_ifstream_68_badData; {
 ifstream inputFile;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 inputFile.open((char *)data);
 inputFile.close();
 }
}