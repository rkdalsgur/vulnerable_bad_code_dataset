/*
 * CWE: 23 Relative Path Traversal
 */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE23_Relative_Path_Traversal__char_console_ofstream_84.h"

#include <fstream>
using namespace std;

namespace CWE23_Relative_Path_Traversal__char_console_ofstream_84 {
CWE23_Relative_Path_Traversal__char_console_ofstream_84_bad::CWE23_Relative_Path_Traversal__char_console_ofstream_84_bad(char * dataCopy) {
 data = dataCopy; {
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
}

CWE23_Relative_Path_Traversal__char_console_ofstream_84_bad::~CWE23_Relative_Path_Traversal__char_console_ofstream_84_bad() { {
 ofstream outputFile;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 outputFile.open((char *)data);
 outputFile.close();
 }
}
}
#endif /* OMITBAD */