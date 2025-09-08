/*
 * CWE: 23 Relative Path Traversal
 */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE23_Relative_Path_Traversal__char_connect_socket_open_82.h"

#ifdef _WIN32
#define OPEN _open
#define CLOSE _close
#else
#include <unistd.h>
#define OPEN open
#define CLOSE close
#endif

namespace CWE23_Relative_Path_Traversal__char_connect_socket_open_82 {

void CWE23_Relative_Path_Traversal__char_connect_socket_open_82_bad::action(char * data) { {
 int fileDesc;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 fileDesc = OPEN(data, O_RDWR|O_CREAT, S_IREAD|S_IWRITE);
 if (fileDesc != -1) {
 CLOSE(fileDesc);
 }
 }
}

}
#endif /* OMITBAD */