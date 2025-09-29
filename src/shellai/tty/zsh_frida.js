var setline = null;
var zrefresh = null;

try {
    Process.enumerateModules().forEach(function(module) {
        module.enumerateExports().forEach(function(exp) {
            switch (exp.name) {
                case 'setline':
                    setline = new NativeFunction(exp.address, 'int', ['pointer', 'int']);
                    break;
                case 'zrefresh':
                    zrefresh = new NativeFunction(exp.address, 'void', []);
                    break;
                default:
                    break;
            }
        });
    });
} catch (e) {
    console.log("Frida error: " + e.stack);
}

// Function to write a string to the readline buffer
function writeToReadline(input) {
    var inputPtr = Memory.allocUtf8String(input);
    setline(inputPtr, 3);
    zrefresh();
}

// Expose the writeToReadline function to be callable from Python
rpc.exports = {
    writeToTty: writeToReadline
};
