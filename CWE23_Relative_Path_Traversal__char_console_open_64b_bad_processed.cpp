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

namespace CWE23_Relative_Path_Traversal__char_console_open_64 {

void badSink(void * dataVoidPtr) {
 /* cast void pointer to a pointer of the appropriate type */
 char * * dataPtr = (char * *)dataVoidPtr;
 /* dereference dataPtr into data */
 char * data = (*dataPtr); {
 int fileDesc;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 fileDesc = OPEN(data, O_RDWR|O_CREAT, S_IREAD|S_IWRITE);
 if (fileDesc != -1) {
 CLOSE(fileDesc);
 }
 }
}