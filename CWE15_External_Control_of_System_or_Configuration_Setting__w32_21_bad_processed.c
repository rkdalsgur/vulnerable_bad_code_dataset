void vulnerability_example() {
char * data;
 char dataBuffer[100] = "";
 data = dataBuffer;
 badStatic = 1; /* true */
 data = badSource(data);
 /* VULNERABILITY: set the hostname to data obtained from a potentially external source */
 if (!SetComputerNameA(data)) {
 printLine("Failure setting computer name");
 exit(1);
 }
}