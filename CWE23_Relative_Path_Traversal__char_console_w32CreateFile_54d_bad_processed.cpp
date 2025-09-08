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

namespace CWE23_Relative_Path_Traversal__char_console_w32CreateFile_54 {

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

/* bad function declaration */
void badSink_e(char * data);

void badSink_d(char * data) {
 badSink_e(data);
}