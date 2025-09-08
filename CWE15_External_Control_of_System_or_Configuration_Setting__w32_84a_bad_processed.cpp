/*
 * CWE: 15 External Control of System or Configuration Setting
 */

#include "std_testcase.h"
#include "CWE15_External_Control_of_System_or_Configuration_Setting__w32_84.h"

namespace CWE15_External_Control_of_System_or_Configuration_Setting__w32_84 {

void bad() {
 char * data;
 char dataBuffer[100] = "";
 data = dataBuffer;
 CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_bad * badObject = new CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_bad(data);
 delete badObject;
}
printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");

#ifdef INCLUDEMAIN

using namespace CWE15_External_Control_of_System_or_Configuration_Setting__w32_84; /* so that we can use good and bad easily */

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