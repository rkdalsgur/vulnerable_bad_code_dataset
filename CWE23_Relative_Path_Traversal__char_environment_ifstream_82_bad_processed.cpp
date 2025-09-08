/*
 * CWE: 23 Relative Path Traversal
 */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE23_Relative_Path_Traversal__char_environment_ifstream_82.h"

#include <fstream>
using namespace std;

namespace CWE23_Relative_Path_Traversal__char_environment_ifstream_82 {

void CWE23_Relative_Path_Traversal__char_environment_ifstream_82_bad::action(char * data) { {
 ifstream inputFile;
 /* VULNERABILITY: Possibly opening a file without validating the file name or path */
 inputFile.open((char *)data);
 inputFile.close();
 }
}

}
#endif /* OMITBAD */