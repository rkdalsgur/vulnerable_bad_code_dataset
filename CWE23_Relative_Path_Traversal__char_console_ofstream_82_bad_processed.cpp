/*
 * CWE: 23 Relative Path Traversal
 */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE23_Relative_Path_Traversal__char_console_ofstream_82.h"

#include <fstream>
using namespace std;

namespace CWE23_Relative_Path_Traversal__char_console_ofstream_82 {

void CWE23_Relative_Path_Traversal__char_console_ofstream_82_bad::action(char * data) { {
 ofstream outputFile;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 outputFile.open((char *)data);
 outputFile.close();
 }
}

}
#endif /* OMITBAD */