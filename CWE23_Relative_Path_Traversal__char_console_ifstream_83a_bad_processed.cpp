/*
 * CWE: 23 Relative Path Traversal
 */

#include "std_testcase.h"
#include "CWE23_Relative_Path_Traversal__char_console_ifstream_83.h"

namespace CWE23_Relative_Path_Traversal__char_console_ifstream_83 {

void bad() {
 char * data;
 char dataBuffer[FILENAME_MAX] = BASEPATH;
 data = dataBuffer;
 CWE23_Relative_Path_Traversal__char_console_ifstream_83_bad badObject(data);
}
printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");

#ifdef INCLUDEMAIN

using namespace CWE23_Relative_Path_Traversal__char_console_ifstream_83; /* so that we can use good and bad easily */

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