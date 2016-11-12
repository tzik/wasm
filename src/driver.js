
class Timing {
  constructor() {
    this.start = Date.now();
    this.prev_start = this.start;
  }

  emit(msg) {
    let now = Date.now();
    print(msg + ': ' + (now - this.prev_start) + 'ms');
    this.prev_start = now;
  }
};
  
class Runtime {
  constructor() {
    this.instance = null;
    this.utf8Args = [];
    // 4 for argc. 4 for the trailing nullptr.
    this.argsBufSize = 4 + 4;
  }

  set_args(...args) {
    // 4 for argc. 4 for the trailing nullptr.
    let argsBufSize = 4 + 4;
    let utf8Args = [];
    for (let arg of args) {
      let x = toUTF8(arg);
      // 4 for the argv value. 1 for the trailing '\0'.
      argsBufSize += x.length + 4 + 1;
      utf8Args.push(x);
    }

    this.utf8Args = utf8Args;
    this.argsBufSize = argsBufSize;
  }

  env_get_args_buffer_size() {
    return this.argsBufSize;
  }
  
  env_get_args(p) {
    let mem = this.memory.buffer;
    let view = new DataView(mem, p, this.argsBufSize);
    let argc = this.utf8Args.length;

    view.setUint32(0, argc, true);

    // 4 for argc. 4 each for argv values. 4 for the trailing nullptr.
    let k = 4 + 4 * argc + 4;
    for (let i = 0; i < argc; ++i) {
      view.setUint32(4 * (i + 1), k + p, true);
      for (let c of this.utf8Args[i])
        view.setUint8(k++, c);
      ++k; // for '\0'.
    }
  }

  env_brk(p) {
    let mem = this.memory.buffer;
    return mem.byteLength;
  }

  env_stdout(p, n) {
    let mem = this.memory.buffer;
    let s = new Uint8Array(mem, p, n);
    let cs = [];
    for (let c of s)
      cs.push(String.fromCharCode(c));

    write(cs.join(''));
    return n;
  }

  makeEnvObject() {
    return {
      env_exit: ec=>{throw ec},
      crash: ()=>quit(1),
      env_get_args_buffer_size: this.env_get_args_buffer_size.bind(this),
      env_get_args: this.env_get_args.bind(this),
      env_brk: this.env_brk.bind(this),
      env_stdout: this.env_stdout.bind(this),
      env_dump: x => print(x)
    };
  }
}

function toUTF8(s) {
  let encoded = encodeURIComponent(s);
  let result = [];
  for (let i = 0; i < encoded.length; ++i) {
    if (encoded[i] === '%') {
      result.push(parseInt(encoded.slice(i+1, i+3), 16));
      i += 2;
    } else {
      result.push(encoded[i].charCodeAt(0));
    }
  }
  return result;
}

// main
(async function(program_file, metadata_file, ...args) {
  let timing = new Timing();
  let binary = readbuffer(program_file);
  timing.emit('load');

  print('binary size: ' + binary.byteLength);
  
  let module = await WebAssembly.compile(binary);
  timing.emit('compile');
  
  let runtime = new Runtime;
  let env = runtime.makeEnvObject();
  runtime.set_args(program_file, ...args);

  let metadata_string = read(metadata_file)
  let metadata = null;
  if (metadata_string) {
    metadata = JSON.parse(metadata_string);
    env.memory = new WebAssembly.Memory({
      'initial': Math.ceil(metadata.staticBump / (64 * 1024))
    });
  }

  let instance = new WebAssembly.Instance(module, {env});
  let memory = env.memory || instance.exports.memory;
  runtime.instance = instance;
  runtime.memory = memory;
  timing.emit('instantiate');

  if (metadata) {
    for (let i of metadata.initializers)
      instance.exports[i]();
  }

  let rv = -1;
  try {
    rv = instance.exports._start();
  } catch(e) {
    if (typeof e === 'number')
      quit(e);
    throw e;
  }
  timing.emit('execute');
  quit(rv);
})(...arguments).catch(e => {
  print(e.stack);
  quit(1);
});
