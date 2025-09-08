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

/* bad function declaration */
void CWE15_External_Control_of_System_or_Configuration_Setting__w32_52c_badSink(char * data);

void CWE15_External_Control_of_System_or_Configuration_Setting__w32_52b_badSink(char * data) {
 CWE15_External_Control_of_System_or_Configuration_Setting__w32_52c_badSink(data);
}