void vulnerability_example() {
char * data;
 char dataBuffer[100] = "";
 data = dataBuffer;
 data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b_badSource(data);
 /* VULNERABILITY: set the hostname to data obtained from a potentially external source */
 if (!SetComputerNameA(data)) {
 printLine("Failure setting computer name");
 exit(1);
 }
}