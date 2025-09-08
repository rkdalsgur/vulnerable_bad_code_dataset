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

#ifdef _WIN32
#define OPEN _open
#define CLOSE _close
#else
#include <unistd.h>
#define OPEN open
#define CLOSE close
#endif

namespace CWE23_Relative_Path_Traversal__char_console_open_61 {

char * badSource(char * data) { {
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
 return data;
}