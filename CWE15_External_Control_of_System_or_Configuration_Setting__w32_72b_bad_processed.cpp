/*
 * CWE: 15 External Control of System or Configuration Setting
 */

#include "std_testcase.h"
#include <vector>

#include <windows.h>

using namespace std;

namespace CWE15_External_Control_of_System_or_Configuration_Setting__w32_72 {

void badSink(vector<char *> dataVector) {
 /* copy data out of dataVector */
 char * data = dataVector[2];
 /* VULNERABILITY: set the hostname to data obtained from a potentially external source */
 if (!SetComputerNameA(data)) {
 printLine("Failure setting computer name");
 exit(1);
 }
}