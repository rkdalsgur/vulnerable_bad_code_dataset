/*
 * CWE: 23 Relative Path Traversal
 */

#include "std_testcase.h"
#include <list>

#ifdef _WIN32
#define BASEPATH "c:\\temp\\"
#else
#include <wchar.h>
#define BASEPATH "/tmp/"
#endif

#include <fstream>
using namespace std;

using namespace std;

namespace CWE23_Relative_Path_Traversal__char_connect_socket_ofstream_73 {

void badSink(list<char *> dataList) {
 /* copy data out of dataList */
 char * data = dataList.back(); {
 ofstream outputFile;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 outputFile.open((char *)data);
 outputFile.close();
 }
}