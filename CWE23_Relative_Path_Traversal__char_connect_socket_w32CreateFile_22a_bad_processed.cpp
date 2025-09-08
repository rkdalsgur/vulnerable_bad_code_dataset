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

namespace CWE23_Relative_Path_Traversal__char_connect_socket_w32CreateFile_22 {

/* The global variable below is used to drive control flow in the source function. Since it is in
a C++ namespace, it doesn't need a globally unique name. */
int badGlobal = 0;

char * badSource(char * data);

void bad() {
 char * data;
 char dataBuffer[FILENAME_MAX] = BASEPATH;
 data = dataBuffer;
 badGlobal = 1; /* true */
 data = badSource(data); {
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
 ;
}
printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");

#ifdef INCLUDEMAIN

using namespace CWE23_Relative_Path_Traversal__char_connect_socket_w32CreateFile_22; /* so that we can use good and bad easily */

int main(int argc, char * argv[]) {
 /* seed randomness */
 srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
 printLine("Calling good()...");
 good();
 printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
 printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");
#endif /* OMITBAD */
 return 0;
}

#endif