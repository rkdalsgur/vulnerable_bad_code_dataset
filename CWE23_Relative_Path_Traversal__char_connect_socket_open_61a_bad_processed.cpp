/*
 * CWE: 23 Relative Path Traversal
 */

#include "std_testcase.h"

#ifdef _WIN32
#define BASEPATH "c:\\temp\\"
#else
#include <wchar.h>
#define BASEPATH "/tmp/"
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32") /* include ws2_32.lib when linking */
#define CLOSE_SOCKET closesocket
#else /* NOT _WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define SOCKET int
#endif

#define TCP_PORT 27015
#define IP_ADDRESS "127.0.0.1"

#ifdef _WIN32
#define OPEN _open
#define CLOSE _close
#else
#define OPEN open
#define CLOSE close
#endif

namespace CWE23_Relative_Path_Traversal__char_connect_socket_open_61 {

/* bad function declaration */
char * badSource(char * data);

void bad() {
 char * data;
 char dataBuffer[FILENAME_MAX] = BASEPATH;
 data = dataBuffer;
 data = badSource(data); {
 int fileDesc;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 fileDesc = OPEN(data, O_RDWR|O_CREAT, S_IREAD|S_IWRITE);
 if (fileDesc != -1) {
 CLOSE(fileDesc);
 }
 }
}
printLine("Calling bad()...");
 bad();
 printLine("Finished bad()");

#ifdef INCLUDEMAIN

using namespace CWE23_Relative_Path_Traversal__char_connect_socket_open_61; /* so that we can use good and bad easily */

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