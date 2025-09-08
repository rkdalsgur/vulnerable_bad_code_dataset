/*
 * CWE: 15 External Control of System or Configuration Setting
 */

#include "std_testcase.h"

#include <winsock2.h>
#pragma comment(lib, "ws2_32")

#define LISTEN_PORT 999
#define LISTEN_BACKLOG 5

#include <windows.h>

typedef struct _CWE15_External_Control_of_System_or_Configuration_Setting__w32_67_structType {
 char * structFirst;
} CWE15_External_Control_of_System_or_Configuration_Setting__w32_67_structType;

void CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b_badSink(CWE15_External_Control_of_System_or_Configuration_Setting__w32_67_structType myStruct) {
 char * data = myStruct.structFirst;
 /* VULNERABILITY: set the hostname to data obtained from a potentially external source */
 if (!SetComputerNameA(data)) {
 printLine("Failure setting computer name");
 exit(1);
 }
}