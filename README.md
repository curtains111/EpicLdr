Early Bird Injection

Overview

Early Bird Injection is a proof-of-concept (PoC) tool designed to demonstrate process injection using the "Early Bird" technique. This method leverages asynchronous procedure call (APC) injection to inject shellcode into a newly created, suspended process before the entry point is reached. This helps evade certain process-based defenses and potentially bypass security hooks.

Note: This tool is intended for educational purposes and authorized security testing only. Unauthorized use is illegal and unethical.

Features

Creates a new process in a suspended state (e.g., werfault.exe).

Allocates memory in the target process and writes shellcode.

Queues an APC to execute shellcode before the entry point.

Resumes the suspended process to trigger execution.

Requirements

Windows operating system (compatible with Windows 10 and later).

Visual Studio or any C/C++ compiler capable of building Windows applications.

Administrative privileges to execute process injection.

Installation

Clone the repository:

git clone https://github.com/yourusername/early-bird-injection.git

Navigate to the project directory:

cd early-bird-injection

Build the project using your preferred C/C++ compiler.

Usage

Compile the code:

cl /EHsc early_bird_injection.cpp

or use your preferred build tool.

Run the compiled executable:

early_bird_injection.exe <path/to/shellcode.bin>

Example

./early_bird_injection.exe shellcode.bin

This will create a suspended werfault.exe process, inject the specified shellcode, queue an APC, and resume the thread to execute the code.

How It Works

CreateProcess: Launches a process (e.g., werfault.exe) in a suspended state.

VirtualAllocEx: Allocates memory in the target process.

WriteProcessMemory: Writes shellcode to the allocated memory.

QueueUserAPC: Queues the APC to execute the shellcode in the context of the target process.

ResumeThread: Resumes the suspended process, triggering the shellcode.

Disclaimer

This project is for educational and research purposes only. Use responsibly and ensure you have proper authorization before running the tool in any environment.
