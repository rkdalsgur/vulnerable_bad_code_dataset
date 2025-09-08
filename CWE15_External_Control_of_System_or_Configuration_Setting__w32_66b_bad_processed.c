/*
 * CWE: 15 External Control of System or Configuration Setting
 */

#include "std_testcase.h"

#include <winsock2.h>
#pragma comment(lib, "ws2_32")

#define LISTEN_PORT 999
#define LISTEN_BACKLOG 5

#include <windows.h>

void CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b_badSink(char * dataArray[]) {
 /* copy data out of dataArray */
 char * data = dataArray[2];
 /* VULNERABILITY: set the hostname to data obtained from a potentially external source */
 if (!SetComputerNameA(data)) {
 printLine("Failure setting computer name");
 exit(1);
 }
}