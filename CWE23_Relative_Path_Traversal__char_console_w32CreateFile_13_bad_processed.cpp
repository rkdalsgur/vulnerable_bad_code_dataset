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

namespace CWE23_Relative_Path_Traversal__char_console_w32CreateFile_13 {

void bad() {
 char * data;
 char dataBuffer[FILENAME_MAX] = BASEPATH;
 data = dataBuffer;
 if(GLOBAL_CONST_FIVE==5) { {
 /* Read input from the console */
 size_t dataLen = strlen(data);
 /* if there is room in data, read into it from the console */
 if (FILENAME_MAX-dataLen > 1) {
 /* VULNERABILITY: Read data from the console */
 if (fgets(data+dataLen, (int)(FILENAME_MAX-dataLen), stdin) != NULL) {
 /* The next few lines remove the carriage return from the string that is
 * inserted by fgets() */
 dataLen = strlen(data);
 if (dataLen > 0 && data[dataLen-1] == '\n') {
 data[dataLen-1] = '\0';
 }
 }
 else {
 printLine("fgets() failed");
 /* Restore NUL terminator if fgets fails */
 data[dataLen] = '\0';
 }
 }
 }
 } {
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
printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");

#ifdef INCLUDEMAIN

using namespace CWE23_Relative_Path_Traversal__char_console_w32CreateFile_13; /* so that we can use good and bad easily */

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