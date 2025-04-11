Interceptor.attach(Module.getExportByName('kernel32.dll', 'CreateFileW'), {
  onEnter(args) {
    const filename = args[0].readUtf16String();
    send(`CreateFileW called with: "${filename}"`);
  },
  onLeave(retval) {
    send(`CreateFileW returned: ${retval}`);
  }
});