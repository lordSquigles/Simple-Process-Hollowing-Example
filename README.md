# Simple-Process-Hollowing-Example
Process Hollowing is an antivirus evasion technique by which a process is run in the memory space of another. 

## Files:
- [Process Hollowing code](https://github.com/LordSquigles/Simple-Process-Hollowing-Example/blob/main/processHollowing/Source.cpp)
- [Test executable code](https://github.com/LordSquigles/Simple-Process-Hollowing-Example/blob/main/test/Source.cpp)

Process Hollowing involves creating a suspended process, unmapping the suspended process's executable section, writing at the base address of the unmapped section new, malicious memory, and resuming the suspended process. By this, malware can run in memory (not off of the disk) and under another, less suspicious process.

Here is a [helpful article](https://medium.com/@jain.sm/process-hollowing-930b30452279) that explains the process in detail.

Helpful examples have also been done by [hasherzade](https://github.com/hasherezade) and [Zer0Mem0ry](https://github.com/Zer0Mem0ry/).

## Methods:

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
  
## Notes: 
 
1. [Zer0Mem0ry's example](https://github.com/Zer0Mem0ry/RunPE/blob/master/RunPE.cpp) differs from mine in that the process hollowing program injects ITSELF with the malicious memory. In this example also, the malicious program is never stored on or read off the disk. Instead, its [shellcode](https://github.com/hasherezade/pe_to_shellcode) is stored in the code of the RunPE program before compilation. This has the benefit of avoiding signature detection of the malicious file. Combined with obfuscation and/or packing, the malicious data may never see itself on the disk in a readable format and offers potentially better antivirus evasion. If having everything in the same file but still injecting ANOTHER process is important to you, feel free to combine these methods and replace the components of mine that read the data from the malicious file on disk into memory, with theirs.

## Sources: 

- https://medium.com/@jain.sm/process-hollowing-930b30452279.
- http://www.rohitab.com/discuss/topic/40262-dynamic-forking-process-hollowing/.
- https://github.com/Zer0Mem0ry/RunPE/blob/master/RunPE.cpp
- https://github.com/hasherezade/
- https://github.com/Zer0Mem0ry/
- https://www.autosectools.com/process-hollowing.pdf
- https://github.com/hasherezade/pe_to_shellcode
