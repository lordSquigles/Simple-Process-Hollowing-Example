# Simple-Process-Hollowing-Example
Process Hollowing is a malware evasion technique by which a process is run in the memory space of another. 

Here is a helpful article that explains the process in detail: https://medium.com/@jain.sm/process-hollowing-930b30452279.

Thank you zwclose on Rohitab for your fantastic error handling bits! I borrowed a lot of it: http://www.rohitab.com/discuss/topic/40262-dynamic-forking-process-hollowing/.

Process Hollowing involves creating a suspended process, unmapping the suspended process's executable section, writing at the base address of the unmapped section new, malicious memory, and resuming the suspended process. By this, malware can run in memory (not off of the disk) and under another, less suspicious process.

Windows methods used are:

  - ZeroMemory
  - CloseHandle
  - WaitForSingleObject
  - CreateFile
  - GetFileSize
  - ReadFile
  - CreateProcess
  - ResumeThread
  - VirtualAllocEx
  - VirtualFree
  - GetThreadContext
  - SetThreadContext
  - ReadProcessMemory
  - WriteProcessMemory
  - NtUnmapViewOfSection
  
  It is worth familiarizing oneself with all of these methods for the best understanding. Documentation for each of them can be found on https://docs.microsoft.com, except for NtUnmapViewOfSection, which can be found at http://undocumented.ntinternals.net. I have also included an ntdll.h file which will allow the use of the NT "user mode," methods.
