var rl_replace_line = null;
var rl_forward_byte = null;
var rl_redisplay    = null;

try {
    Process.getModuleByName("bash").enumerateExports().forEach(function(exp) {
        switch (exp.name) {
            case 'rl_replace_line':
                rl_replace_line = new NativeFunction(exp.address, 'int', ['pointer', 'int']);
                break;
            case 'rl_forward_byte':
                rl_forward_byte = new NativeFunction(exp.address, 'int', ['int', 'int']);
                break;
            case 'rl_redisplay':
                rl_redisplay = new NativeFunction(exp.address, 'void', []);
                break;
            default:
                break;
        }
    });
} catch (e) {
    console.log("Frida error: " + e.stack);
}

// Function to write a string to the readline buffer
function writeToReadline(input) {
    var inputPtr = Memory.allocUtf8String(input);
    rl_replace_line(inputPtr, 0);
    rl_forward_byte(input.length, 0);
    rl_redisplay();
}

// Expose the writeToReadline function to be callable from Python
rpc.exports = {
    writeToTty: writeToReadline
};
