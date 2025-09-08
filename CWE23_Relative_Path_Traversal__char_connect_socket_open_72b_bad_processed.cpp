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

#ifdef _WIN32
#define OPEN _open
#define CLOSE _close
#else
#include <unistd.h>
#define OPEN open
#define CLOSE close
#endif

using namespace std;

namespace CWE23_Relative_Path_Traversal__char_connect_socket_open_72 {

void badSink(vector<char *> dataVector) {
 /* copy data out of dataVector */
 char * data = dataVector[2]; {
 int fileDesc;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 fileDesc = OPEN(data, O_RDWR|O_CREAT, S_IREAD|S_IWRITE);
 if (fileDesc != -1) {
 CLOSE(fileDesc);
 }
 }
}