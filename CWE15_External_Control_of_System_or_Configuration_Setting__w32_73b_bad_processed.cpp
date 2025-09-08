/*
 * CWE: 15 External Control of System or Configuration Setting
 */

#include "std_testcase.h"
#include <list>

#include <windows.h>

using namespace std;

namespace CWE15_External_Control_of_System_or_Configuration_Setting__w32_73 {

void badSink(list<char *> dataList) {
 /* copy data out of dataList */
 char * data = dataList.back();
 /* VULNERABILITY: set the hostname to data obtained from a potentially external source */
 if (!SetComputerNameA(data)) {
 printLine("Failure setting computer name");
 exit(1);
 }
}