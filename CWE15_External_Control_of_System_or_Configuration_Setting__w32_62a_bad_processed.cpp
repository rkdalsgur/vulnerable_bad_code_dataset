/*
 * CWE: 15 External Control of System or Configuration Setting
 */

#include "std_testcase.h"

#include <windows.h>

namespace CWE15_External_Control_of_System_or_Configuration_Setting__w32_62 {

/* bad function declaration */
void badSource(char * &data);
/*123*/
void bad() {
 char * data;
 char dataBuffer[100] = "";
 data = dataBuffer;
 badSource(data);
 /* VULNERABILITY: set the hostname to data obtained from a potentially external source */
 if (!SetComputerNameA(data)) {
 printLine("Failure setting computer name");
 exit(1);
 }
}
printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");

#ifdef INCLUDEMAIN

using namespace CWE15_External_Control_of_System_or_Configuration_Setting__w32_62; /* so that we can use good and bad easily */

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