void vulnerability_example() {
char * data;
 char dataBuffer[100] = "";
 data = dataBuffer;
 CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badGlobal = 1; /* true */
 data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_badSource(data);
 /* VULNERABILITY: set the hostname to data obtained from a potentially external source */
 if (!SetComputerNameA(data)) {
 printLine("Failure setting computer name");
 exit(1);
 }
}