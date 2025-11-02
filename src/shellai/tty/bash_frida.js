var rl_replace_line = null;
var rl_forward_byte = null;
var rl_redisplay    = null;
var describe_command = null;
var write = null;

try {
    var exp = Process.getModuleByName("libc.so.6").getExportByName("write");
    write = new NativeFunction(exp, 'int', ['int', 'pointer', 'int']);
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
            case 'describe_command':
                describe_command = new NativeFunction(exp.address, 'int', ['pointer', 'int']);
                break;
            case 'printf_chk@plt':
                write = new NativeFunction(exp.address, 'int', ['int', 'pointer']);
                break;
            default:
                break;
        }
    });
} catch (e) {
    console.log("Frida error: " + e.stack);
}

// checkCommand uses the describe_command function to check if a command is a valid callable type within the shell.
// Equivalent to `type -t <command>`
// This isn't perfect since a file isn't necessarily executable, but I'm using an injected javascript engine
// to directly call internal functions so nothing is perfect.
function checkCommand(command) {
    if (describe_command === null) {
        throw new Error("describe_command function not found");
    }
    var commandPtr = Memory.allocUtf8String(command);
    // Capture stdout/stderr so we don't clutter the terminal
    Interceptor.attach(write, {
        onEnter: function (args) {
            if (args[0].toInt32() === 1 || args[0].toInt32() === 2) {
                args[1] = ptr("");
            }
        },
    });
    var result = describe_command(commandPtr, 8);
    Interceptor.detachAll();
    return result === 1; // Assuming 1 indicates a valid command.
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
    writeToTty: writeToReadline,
    checkCommand: checkCommand
};
