/*
 * CWE: 23 Relative Path Traversal
 */

#include "std_testcase.h"
#include <map>

#ifdef _WIN32
#define BASEPATH "c:\\temp\\"
#else
#include <wchar.h>
#define BASEPATH "/tmp/"
#endif

#ifdef _WIN32
#define FOPEN fopen
#else
#define FOPEN fopen
#endif

using namespace std;

namespace CWE23_Relative_Path_Traversal__char_connect_socket_fopen_74 {

void badSink(map<int, char *> dataMap) {
 /* copy data out of dataMap */
 char * data = dataMap[2]; {
 FILE *pFile = NULL;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 pFile = FOPEN(data, "wb+");
 if (pFile != NULL) {
 fclose(pFile);
 }
 }
}