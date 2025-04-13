/*
 * Enhanced GraphViz CALL Tracing with Stalker
 * -----------------------------------------
 * Produces clean, sequential call flow similar to the original
 * 
 * Original: https://github.com/FuzzySecurity/Fermion/blob/master/Examples/graphviz.js
 * Original Author: @FuzzySec aka b33f  
 */

// Target function to hook
const TARGET_MODULE = 'kernel32.dll';
const TARGET_EXPORT = 'CreateFileW';

// Globals
let modMap = new ModuleMap();
let callSites = [];
let isInitialCall = true;
let previousNode;
let startNode;
let endNode;

// Generate GraphViz header
function printGraphVizHead() {
    return `digraph G {
    ratio=fill;
    node[fontsize=10,style=filled,shape=rectangle];
    edge [style=solid];
`;
}

// Generate GraphViz footer
function printGraphVizFooter(start, end) {
    return `\n    "${start}" [shape=invhouse, color=green];
    "${end}" [shape=house, color=red];
}`;
}

// Parse call sites and generate graph
function parseCallSites(sites) {
    if (!sites || sites.length === 0) {
        send('⚠️ No call sites recorded');
        return '';
    }
    
    send(`🔍 Processing ${sites.length} call sites`);
    
    try {
        // Print Header
        let output = printGraphVizHead();
        
        // Set start node
        const functionPtr = Module.findExportByName(TARGET_MODULE, TARGET_EXPORT);
        startNode = functionPtr;
        
        // Process each call site
        for (let i = 0; i < sites.length; i++) {
            const fromAddress = sites[i][1];
            const toAddress = sites[i][2];
            
            // Get module info for filtering
            const fromModuleInfo = modMap.find(ptr(fromAddress.toString()));
            const toModuleInfo = modMap.find(ptr(toAddress.toString()));
            
            // Skip if module name contains frida or stalker (case-insensitive)
            if (!fromModuleInfo || !toModuleInfo || 
                fromModuleInfo.name.toLowerCase().indexOf("frida") !== -1 ||
                toModuleInfo.name.toLowerCase().indexOf("frida") !== -1 || 
                fromModuleInfo.name.toLowerCase().indexOf("stalker") !== -1 ||
                toModuleInfo.name.toLowerCase().indexOf("stalker") !== -1) {
                continue;
            }
            
            // Resolve symbols
            const fromSymbol = DebugSymbol.fromAddress(ptr(fromAddress.toString()));
            const toSymbol = DebugSymbol.fromAddress(ptr(toAddress.toString()));
            
            // Format labels exactly like the original
            const fromLabel = `${fromAddress}\\n${fromModuleInfo.name}!${fromSymbol.name}`;
            const toLabel = `${toAddress}\\n${toModuleInfo.name}!${toSymbol.name}`;
            
            // Add to graph
            if (isInitialCall) {
                output += `    "${startNode}"->\"${fromLabel}\";\n`;
                output += `    \"${fromLabel}\"->\"${toLabel}\";\n`;
                isInitialCall = false;
            } else {
                output += `    \"${previousNode}\"->\"${fromLabel}\"->\"${toLabel}\";\n`;
            }
            
            // Save previous node for chaining
            previousNode = toLabel;
            
            // Update end node
            endNode = toLabel;
        }
        
        // Add footer
        output += printGraphVizFooter(startNode, endNode);
        
        return output;
    } catch (e) {
        send(`❌ Error processing call sites: ${e.message}\n${e.stack}`);
        return '';
    }
}

// Hook the target function
function hookTargetFunction() {
    // Find function pointer
    const functionPtr = Module.findExportByName(TARGET_MODULE, TARGET_EXPORT);
    
    if (functionPtr === null) {
        send(`❌ Could not find ${TARGET_MODULE}!${TARGET_EXPORT}`);
        return;
    }
    
    send(`[+] Hooking ${TARGET_MODULE}!${TARGET_EXPORT} at ${functionPtr}`);
    
    // Intercept function calls
    Interceptor.attach(functionPtr, {
        onEnter: function (args) {
            send("\n[+] Calling function..");
            send("    |-> Tracing execution with stalker\n");
            
            const threadId = Process.getCurrentThreadId();
            Stalker.follow(threadId, {
                events: {
                    call: true,  // Track function calls
                    ret: false,  // Don't track returns
                    exec: false, // Don't track all instructions
                    block: false // Don't track blocks
                },
                
                // Process events as they arrive
                onReceive: function (events) {
                    const newCallSites = Stalker.parse(events);
                    if (newCallSites && newCallSites.length > 0) {
                        callSites = callSites.concat(newCallSites);
                    }
                }
            });
            
            // Store threadId for later use
            this.threadId = threadId;
        },
        
        onLeave: function (retval) {
            send("[+] Function returned, processing trace data...");
            
            // Stop stalking
            Stalker.flush();
            Stalker.unfollow(this.threadId);
            Stalker.garbageCollect();
            
            // Process call sites if we have any
            if (callSites && callSites.length > 0) {
                const graphOutput = parseCallSites(callSites);
                
                if (graphOutput) {
                    // Print graph to console
                    send("\n" + graphOutput + "\n");
                    
                    // Add message about Sketchviz
                    send("\n🔗 Visualize this graph by copying the output above and pasting it at https://sketchviz.com/");
                }
                
                // Reset for next time
                callSites = [];
                isInitialCall = true;
                previousNode = null;
            } else {
                send("⚠️ No call sites were recorded");
                                
                send("\n🔗 To visualize GraphViz output, visit https://sketchviz.com/ and paste the graph output");
            }
        }
    });
    
    send(`✅ Hook installed successfully, waiting for ${TARGET_EXPORT} to be called...`);
}

// Main entry point
function main() {
    send("🚀 Starting Call Graph Tracer");
    
    // Initialize the module map
    modMap = new ModuleMap();
    
    // Hook the target function
    hookTargetFunction();
}

// Start the script
main();
