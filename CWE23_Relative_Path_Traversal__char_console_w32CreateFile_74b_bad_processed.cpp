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

#include <windows.h>

using namespace std;

namespace CWE23_Relative_Path_Traversal__char_console_w32CreateFile_74 {

void badSink(map<int, char *> dataMap) {
 /* copy data out of dataMap */
 char * data = dataMap[2]; {
 HANDLE hFile;
 /* VULNERABILITY: Possibly creating and opening a file without validating the file name or path */
 hFile = CreateFileA(data,
 (GENERIC_WRITE|GENERIC_READ),
 0,
 NULL,
 OPEN_ALWAYS,
 FILE_ATTRIBUTE_NORMAL,
 NULL);
 if (hFile != INVALID_HANDLE_VALUE) {
 CloseHandle(hFile);
 }
 }
}