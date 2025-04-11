/*
 * Frida script to hook CreateFileW and log its arguments and return value.
 */

// Helper function to read wide strings (UTF-16)
function readWideString(ptr) {
    if (!ptr || ptr.isNull()) {
        return "<null>";
    }
    try {
        return ptr.readUtf16String();
    } catch (e) {
        return "<error reading string>";
    }
}

// Helper to display file access constants in a readable way
function formatAccess(access) {
    const accessMap = {
        0x80000000: "GENERIC_READ",
        0x40000000: "GENERIC_WRITE",
        0x20000000: "GENERIC_EXECUTE",
        0x10000000: "GENERIC_ALL"
    };
    let result = [];
    for (const [flag, name] of Object.entries(accessMap)) {
        if ((access & flag) === parseInt(flag)) {
            result.push(name);
        }
    }
    return result.length > 0 ? result.join(" | ") : "0x" + access.toString(16);
}

// Helper to display share mode constants
function formatShareMode(shareMode) {
    const modeMap = {
        0x00000000: "0 (Exclusive)",
        0x00000001: "FILE_SHARE_READ",
        0x00000002: "FILE_SHARE_WRITE",
        0x00000004: "FILE_SHARE_DELETE"
    };
    let result = [];
    for (const [flag, name] of Object.entries(modeMap)) {
        if ((shareMode & flag) === parseInt(flag) && parseInt(flag) !== 0) {
            result.push(name);
        }
    }
    return shareMode === 0 ? modeMap[0] : (result.length > 0 ? result.join(" | ") : "0x" + shareMode.toString(16));
}

// Helper to display creation disposition constants
function formatCreationDisposition(disposition) {
    const dispositionMap = {
        1: "CREATE_NEW",
        2: "CREATE_ALWAYS",
        3: "OPEN_EXISTING",
        4: "OPEN_ALWAYS",
        5: "TRUNCATE_EXISTING"
    };
    return dispositionMap[disposition] || "0x" + disposition.toString(16);
}

// Helper to display flags and attributes constants
function formatFlagsAndAttributes(flags) {
    const flagsMap = {
        0x00000001: "FILE_ATTRIBUTE_READONLY",
        0x00000002: "FILE_ATTRIBUTE_HIDDEN",
        0x00000004: "FILE_ATTRIBUTE_SYSTEM",
        0x00000010: "FILE_ATTRIBUTE_DIRECTORY",
        0x00000020: "FILE_ATTRIBUTE_ARCHIVE",
        0x00000080: "FILE_ATTRIBUTE_NORMAL",
        0x00000100: "FILE_ATTRIBUTE_TEMPORARY",
        0x00000800: "FILE_ATTRIBUTE_COMPRESSED",
        0x00000200: "FILE_ATTRIBUTE_OFFLINE",
        0x02000000: "FILE_FLAG_BACKUP_SEMANTICS",
        0x04000000: "FILE_FLAG_POSIX_SEMANTICS",
        0x08000000: "FILE_FLAG_OPEN_REPARSE_POINT",
        0x20000000: "FILE_FLAG_OPEN_NO_RECALL",
        0x40000000: "FILE_FLAG_FIRST_PIPE_INSTANCE"
    };
    let result = [];
    for (const [flag, name] of Object.entries(flagsMap)) {
        if ((flags & flag) === parseInt(flag)) {
            result.push(name);
        }
    }
    return result.length > 0 ? result.join(" | ") : "0x" + flags.toString(16);
}

// Hook CreateFileW
Interceptor.attach(Module.getExportByName("kernel32.dll", "CreateFileW"), {
    onEnter(args) {
        console.log("\n============ CreateFileW Called ============");

        const filePath = readWideString(args[0]);
        const accessMode = args[1].toUInt32();
        const shareMode = args[2].toUInt32();
        const securityAttributes = args[3];
        const creationDisposition = args[4].toUInt32();
        const flagsAndAttributes = args[5].toUInt32();
        const templateFile = args[6];

        console.log("File Path: " + filePath);
        console.log("Access Mode: " + formatAccess(accessMode) + " (0x" + accessMode.toString(16) + ")");
        console.log("Share Mode: " + formatShareMode(shareMode) + " (0x" + shareMode.toString(16) + ")");
        console.log("Security Attributes: " + securityAttributes);
        console.log("Creation Disposition: " + formatCreationDisposition(creationDisposition) + " (0x" + creationDisposition.toString(16) + ")");
        console.log("Flags and Attributes: " + formatFlagsAndAttributes(flagsAndAttributes) + " (0x" + flagsAndAttributes.toString(16) + ")");
        console.log("Template File Handle: " + templateFile);

        this.filePath = filePath; // Store for onLeave
        console.log("------------------------------------------");
    },

    onLeave(retval) {
        const handleValue = retval.toUInt32();

        if (handleValue === 0xFFFFFFFF) {
            console.log("Result: INVALID_HANDLE_VALUE (Operation Failed)");
            const getLastError = Module.getExportByName("kernel32.dll", "GetLastError");
            const GetLastError = new NativeFunction(getLastError, "uint", []);
            const errorCode = GetLastError();
            console.log("Error Code: 0x" + errorCode.toString(16));
        } else {
            console.log("Result: Valid Handle 0x" + handleValue.toString(16) + " for " + (this.filePath || "<unknown>"));
        }

        console.log("============ CreateFileW Return ============\n");
    }
});