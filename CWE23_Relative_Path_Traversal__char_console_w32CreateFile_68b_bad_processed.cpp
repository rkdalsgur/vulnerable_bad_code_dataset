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

#include <windows.h>

extern char * CWE23_Relative_Path_Traversal__char_console_w32CreateFile_68_badData;
extern char * CWE23_Relative_Path_Traversal__char_console_w32CreateFile_68_goodG2BData;

namespace CWE23_Relative_Path_Traversal__char_console_w32CreateFile_68 {

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

void badSink() {
 char * data = CWE23_Relative_Path_Traversal__char_console_w32CreateFile_68_badData; {
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