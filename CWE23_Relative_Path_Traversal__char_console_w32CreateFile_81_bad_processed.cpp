/*
 * CWE: 23 Relative Path Traversal
 */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE23_Relative_Path_Traversal__char_console_w32CreateFile_81.h"

#include <windows.h>

namespace CWE23_Relative_Path_Traversal__char_console_w32CreateFile_81 {

void CWE23_Relative_Path_Traversal__char_console_w32CreateFile_81_bad::action(char * data) const { {
 HANDLE hFile;
 /* VULNERABILITY: Possibly creating and opening a file without validating the file name or path */
 hFile = CreateFileA(data,
 (GENERIC_WRITE|GENERIC_READ),
 0,
 NULL,
 OPEN_ALWAYS,
 FILE_ATTRIBUTE_NORMAL,
 NULL);
 if (hFile != INVALID_HANDLE_VALUE) {
 CloseHandle(hFile);
 }
 }
}

}
#endif /* OMITBAD */