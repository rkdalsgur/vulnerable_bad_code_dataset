/*
 * CWE: 15 External Control of System or Configuration Setting
 */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE15_External_Control_of_System_or_Configuration_Setting__w32_81.h"

#include <windows.h>

namespace CWE15_External_Control_of_System_or_Configuration_Setting__w32_81 {

void CWE15_External_Control_of_System_or_Configuration_Setting__w32_81_bad::action(char * data) const {
 /* VULNERABILITY: set the hostname to data obtained from a potentially external source */
 if (!SetComputerNameA(data)) {
 printLine("Failure setting computer name");
 exit(1);
 }
}

}
#endif /* OMITBAD */