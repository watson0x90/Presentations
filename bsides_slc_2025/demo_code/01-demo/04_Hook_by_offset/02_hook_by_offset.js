/*
 * Frida script to hook CreateFileW and WriteFile by calculating offsets from kernel32.dll base address.
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

// Store file handles and their paths
const fileHandles = new Map();

// Offsets (replace with actual values from your kernel32.dll)
const CREATE_FILE_W_OFFSET = 0x00024B60; // Example offset, replace with real RVA
const WRITE_FILE_OFFSET = 0x00024FD0;    // Example offset, replace with real RVA

// Get the base address of kernel32.dll
const kernel32Module = Process.getModuleByName("kernel32.dll");
const kernel32Base = kernel32Module.base;
console.log("kernel32.dll base address: " + kernel32Base);

// Calculate absolute addresses
const createFileWAddr = kernel32Base.add(CREATE_FILE_W_OFFSET);
const writeFileAddr = kernel32Base.add(WRITE_FILE_OFFSET);

console.log("Hooking CreateFileW at: " + createFileWAddr);
console.log("Hooking WriteFile at: " + writeFileAddr);

// Hook CreateFileW
Interceptor.attach(createFileWAddr, {
    onEnter(args) {
        console.log("\n============ CreateFileW Called ============");
        const filePath = readWideString(args[0]);
        console.log("File Path: " + filePath);
        this.filePath = filePath; // Store for onLeave
        console.log("------------------------------------------");
    },

    onLeave(retval) {
        const handleValue = retval.toUInt32();
        if (handleValue === 0xFFFFFFFF) {
            console.log("Result: INVALID_HANDLE_VALUE (Operation Failed)");
        } else {
            console.log("Result: Valid Handle 0x" + handleValue.toString(16) + " for " + (this.filePath || "<unknown>"));
            fileHandles.set(handleValue, this.filePath);
        }
        console.log("============ CreateFileW Return ============\n");
    }
});

// Hook WriteFile
Interceptor.attach(writeFileAddr, {
    onEnter(args) {
        const handle = args[0].toUInt32(); // HANDLE hFile
        const buffer = args[1];            // LPCVOID lpBuffer
        const numBytesToWrite = args[2].toUInt32(); // DWORD nNumberOfBytesToWrite

        const filePath = fileHandles.get(handle) || "<unknown file>";
        console.log("\n============ WriteFile Called ============");
        console.log("File Handle: 0x" + handle.toString(16) + " (" + filePath + ")");
        console.log("Bytes to Write: " + numBytesToWrite);

        // Log raw bytes for debugging
        const rawBytes = buffer.readByteArray(numBytesToWrite);
        console.log("Raw Bytes: " + Array.from(new Uint8Array(rawBytes)).map(b => b.toString(16).padStart(2, '0')).join(' '));

        // Try UTF-8 first
        let text = "";
        try {
            text = buffer.readUtf8String(numBytesToWrite);
            if (!text) throw new Error("Empty UTF-8 string");
        } catch (e1) {
            try {
                text = buffer.readUtf16String(numBytesToWrite * 2);
            } catch (e2) {
                text = "<non-text data: " + rawBytes.toString() + ">";
            }
        }
        console.log("Text Being Written: " + text);
        console.log("------------------------------------------");
    },

    onLeave(retval) {
        const success = retval.toUInt32() !== 0;
        console.log("Result: " + (success ? "Success" : "Failed"));
        console.log("============ WriteFile Return ============\n");
    }
});

console.log("Script loaded! Hooking CreateFileW and WriteFile by offset...");