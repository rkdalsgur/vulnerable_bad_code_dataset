/*
 * CWE: 15 External Control of System or Configuration Setting
 */

#include "std_testcase.h"

#include <winsock2.h>
#pragma comment(lib, "ws2_32")

#define LISTEN_PORT 999
#define LISTEN_BACKLOG 5

#include <windows.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

void CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e_badSink(char * data) {
 /* VULNERABILITY: set the hostname to data obtained from a potentially external source */
 if (!SetComputerNameA(data)) {
 printLine("Failure setting computer name");
 exit(1);
 }
}