# 🛡️ Dirty Little DotNet Hooker - BSides SLC 2025 Demo Code

This repository contains demonstration code for the BSides SLC 2025 presentation on dynamic binary instrumentation and hooking techniques using Frida.

## 📋 Overview

These demos showcase various techniques for hooking and monitoring Windows API calls and .NET applications, with a focus on:

1. Basic Win32 API hooking for file operations
2. Browser-based hooking with Fermion
3. Advanced .NET runtime instrumentation

## 🧰 Demos

### 01-demo: Basic Frida Windows API Hooking

This section demonstrates fundamental Frida hooking techniques for Windows API functions.

#### 01_frida_trace

- **frida_trace_hook.bat**: Simple script to find Notepad's PID and trace CreateFileW API calls using frida-trace.

#### 02_CreateFileW

- **CreateFileW_frida_hook.bat**: Launches a targeted Frida script against Notepad.
- **CreateFileW_handler.js**: Hooks the CreateFileW API to monitor file operations with detailed parameter logging.

#### 03_CreateFileW_WriteFile

- **CreateFileW_WriteFile_handler.bat**: Similar to the previous demo but adds WriteFile monitoring.
- **CreateFileW_WriteFile_handler.js**: Hooks both CreateFileW and WriteFile to observe file creation and write operations, including content analysis.

#### 04_Hook_by_offset

- **01_get_kernel32_offsets.bat**: Extracts memory offsets for target functions in kernel32.dll.
- **02_hook_by_offset.js**: Hooks functions by their memory offsets rather than by name.
- **03_hook_by_offset.bat**: Executes the offset-based hooking script.

### 02-fermion_demo: Browser-based Instrumentation

This section demonstrates browser-based instrumentation using Fermion (Frida's browser integration).

- **00_begin.js**: Disables F5 and Ctrl+R in the browser to prevent accidental refreshes during demos.
- **01_fermion_createfilew_hook.js**: Simple hook for CreateFileW from the browser context.
- **02_fermion_WriteFile_hook.js**: Advanced WriteFile hook with content extraction and hex dumping.
- **03_graphviz_createfilew.js**: Generates call graphs of CreateFileW calls using Graphviz.

### 03-DLDNH_demo: .NET Debugging Live .NET Hooking

This section demonstrates advanced techniques for instrumenting .NET applications, with a focus on KeePass as the target application.

- **01_fermion_dotnet_hooking_script.js**: Script to enumerate .NET methods and export them to CSV.
- **02_static_instance_hook_read.js**: Differentiates between static and instance methods in .NET for more accurate hooking.
- **03_keepass_keyboard_hook_master_password.js**: Demonstrates keyboard hooking to capture password input.
- **04_execute_cmd.js**: Shows how to execute arbitrary commands by hooking .NET methods.
- **FunctionEnumerator.cs**: C# source for a helper library that enumerates .NET methods and their addresses.

## 🚀 Usage

Each demo directory contains batch files to run the corresponding demo. Most demos target Notepad as a safe process to hook.

For the .NET hooking demos:

1. Ensure KeePass 2.58 is installed in the specified path
2. Compile the FunctionEnumerator.cs to a DLL
3. Run the relevant scripts with Frida

## ⚠️ Security Notice

These demonstrations are for educational purposes only. The techniques shown could be used maliciously if applied to production systems without authorization. Always practice responsible security research and obtain proper permissions before using these techniques.

## 📚 Prerequisites

- Windows operating system
- Frida (latest version)
- Visual Studio Community Edition (for compiling the C# components)
- Developer Command Prompt to use for `.bat` scripts
  - Part of Visual Studio Community Edition
- KeePass 2.58 (for .NET demos)
- Python 3.x

## 🔗 Related Resources

- [Frida Documentation](https://frida.re/docs/home/)
- [.NET Runtime Internals](https://github.com/dotnet/runtime)
- [BSides SLC](https://www.bsidesslc.org/)
