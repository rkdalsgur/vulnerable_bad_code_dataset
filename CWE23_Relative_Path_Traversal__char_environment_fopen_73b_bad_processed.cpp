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

#ifdef _WIN32
#define FOPEN fopen
#else
#define FOPEN fopen
#endif

using namespace std;

namespace CWE23_Relative_Path_Traversal__char_environment_fopen_73 {

void badSink(list<char *> dataList) {
 /* copy data out of dataList */
 char * data = dataList.back(); {
 FILE *pFile = NULL;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 pFile = FOPEN(data, "wb+");
 if (pFile != NULL) {
 fclose(pFile);
 }
 }
}