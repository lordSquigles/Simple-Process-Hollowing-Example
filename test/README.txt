Here is just the code I used as my "malicious program," for testing. Make sure the file injected is 32-bit as well as the suspended process. 
If the target process is a Windows subsystem application, the injected one must be also. 
If the target process is a console application, also must be the injected file.
I compile my test executable as a Windows subsystem application for injection into a default windows app (in this case, calc.exe).
