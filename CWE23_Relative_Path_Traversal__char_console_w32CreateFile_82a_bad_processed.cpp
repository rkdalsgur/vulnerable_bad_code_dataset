/*
 * CWE: 23 Relative Path Traversal
 */

#include "std_testcase.h"
#include "CWE23_Relative_Path_Traversal__char_console_w32CreateFile_82.h"

namespace CWE23_Relative_Path_Traversal__char_console_w32CreateFile_82 {

void bad() {
 char * data;
 char dataBuffer[FILENAME_MAX] = BASEPATH;
 data = dataBuffer; {
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
 CWE23_Relative_Path_Traversal__char_console_w32CreateFile_82_base* baseObject = new CWE23_Relative_Path_Traversal__char_console_w32CreateFile_82_bad;
 baseObject->action(data);
 delete baseObject;
}
printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");

#ifdef INCLUDEMAIN

using namespace CWE23_Relative_Path_Traversal__char_console_w32CreateFile_82; /* so that we can use good and bad easily */

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