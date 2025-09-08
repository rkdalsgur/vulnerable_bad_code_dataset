/*
 * CWE: 23 Relative Path Traversal
 */

#include "std_testcase.h"
#include <vector>

#ifdef _WIN32
#define BASEPATH "c:\\temp\\"
#else
#include <wchar.h>
#define BASEPATH "/tmp/"
#endif

#include <fstream>
using namespace std;

using namespace std;

namespace CWE23_Relative_Path_Traversal__char_console_ofstream_72 {

void badSink(vector<char *> dataVector) {
 /* copy data out of dataVector */
 char * data = dataVector[2]; {
 ofstream outputFile;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 outputFile.open((char *)data);
 outputFile.close();
 }
}