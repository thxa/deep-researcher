# Browser and JavaScript Engine Fuzzing

## 1. V8 Fuzzing

### 1.1 Overview

V8 is Google's JavaScript engine, powering Chrome, Node.js, and Deno. It's one of the most security-critical software components in the world: a V8 vulnerability can be exploited through any website visited by a Chrome user. V8 is also one of the most heavily fuzzed software projects, with Google running massive fuzzing campaigns through ClusterFuzz and OSS-Fuzz.

### 1.2 V8 Attack Surface

The V8 attack surface includes:
- **JavaScript parser**: Converts source code to AST
- **Ignition interpreter**: Executes bytecode
- **TurboFan/Maglev JIT compiler**: Optimizes hot functions to native code
- **Garbage collector**: Manages object lifetimes
- **Built-in functions**: `Array.prototype.*`, `Object.*`, `RegExp`, `Promise`, etc.
- **WebAssembly**: Compilation and execution of Wasm modules
- **IC (Inline Cache) system**: Caches property access patterns
- **Deoptimization**: Falls back from JIT code to interpreter

### 1.3 fuzzilli

fuzzilli is Google's primary V8 fuzzer, developed by Samuel Groß (saelo). Unlike traditional fuzzers that mutate byte streams, fuzzilli generates JavaScript programs using a **domain-specific language (DSL)** that maps to V8's internal operations.

**Key innovation**: fuzzilli generates JavaScript programs at the **IR (Intermediate Representation) level**, then compiles them to JavaScript. This ensures that generated programs are always syntactically valid and exercise V8's optimization pipeline.

```
fuzzilli IR → JavaScript → V8 → Coverage feedback → Mutation → fuzzilli IR → ...
```

**fuzzilli IR operations:**
```
LoadProperty    obj, "prop"       → obj.prop
StoreProperty   obj, "prop", val  → obj.prop = val
LoadElement     arr, idx         → arr[idx]
StoreElement    arr, idx, val    → arr[idx] = val
CreateObject    [prop1:val1, ...] → {prop1: val1, ...}
CreateArray     [val1, val2, ...] → [val1, val2, ...]
CallFunction    func, [arg1, ...] → func(arg1, ...)
NewObject       constructor, [args] → new constructor(args)
BeginIf         condition         → if (condition) { ... }
BeginWhile      condition         → while (condition) { ... }
BeginFor        init, cond, inc  → for (init; cond; inc) { ... }
Return          value             → return value
Throw           value             → throw value
```

### 1.4 v8_fuzzer

The `v8_fuzzer` (also called `v8_simple_inspector_fuzzer`) is a simpler V8 fuzzer that feeds raw JavaScript to V8:

```c
#include <include/v8.h>
#include <include/libplatform/libplatform.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    
    v8::Isolate *isolate = v8::Isolate::New(create_params);
    {
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);
        
        // Convert fuzz input to JavaScript source
        std::string source(reinterpret_cast<const char *>(data), size);
        
        // Compile and run
        v8::Local<v8::String> source_str =
            v8::String::NewFromUtf8(isolate, source.c_str())
                .ToLocalChecked();
        
        v8::TryCatch try_catch(isolate);
        v8::Script::Compile(context, source_str).ToLocalChecked()->Run(context);
    }
    isolate->Dispose();
    delete create_params.array_buffer_allocator;
    return 0;
}
```

### 1.5 DSL-Based JS Generation

fuzzilli's program generator creates JavaScript programs by assembling IR operations. The generator:
1. Maintains a **variable pool** of typed values
2. Selects an IR operation that's compatible with available variable types
3. Adds the operation to the program
4. Stores the result as a new variable in the pool

**Example generated program:**
```javascript
// fuzzilli-generated program that triggers TurboFan optimization
function foo(a, b) {
    let result = a + b;
    if (result > 100) {
        result = result * 2;
    }
    return result;
}

// Trigger JIT compilation
for (let i = 0; i < 100000; i++) {
    foo(i, i + 1);
}

// Type confusion: pass unexpected types after JIT compilation
foo({}, []);
foo(1.5, 2.5);
```

The key insight: **JIT bugs often require specific type transition patterns**. The function must be called many times with one type (to trigger JIT compilation with that type assumption), then called with a different type (to trigger deoptimization or type confusion).

### 1.6 Notable V8 Bugs Found by Fuzzing

- **CVE-2024-0519**: V8 OOB write in `WasmGraphBuilding::S128Shift` for WebAssembly SIMD. Found by ClusterFuzz. This was a critical vulnerability that allowed OOB memory access from JavaScript.
- **CVE-2023-44299**: V8 type confusion in `OptimizeGraph::ReduceJSAdd` for optimized arithmetic. Found by fuzzilli.
- **CVE-2022-4904**: V8 regexp OOB access in `RegExpBuiltinsHasForeignKeyedIC`. Found by ClusterFuzz.
- **CVE-2021-37975**: V8 incorrect handling of `Map` transitions in `Map::FindLastMatchMapForMap`. Found by fuzzilli.

## 2. JSC (JavaScriptCore) Fuzzing

### 2.1 Overview

JavaScriptCore (JSC) is the JavaScript engine in WebKit, powering Safari. It uses a tiered compilation system:
- **LLInt** (Low Level Interpreter): Bytecode interpreter
- **Baseline JIT**: Simple JIT compilation
- **DFG JIT**: Data Flow Graph JIT with type speculation
- **FTL JIT**: Faster Than LLVM, highest optimization level

### 2.2 JSC Fuzzing with libFuzzer

```c
#include <JavaScriptCore/JavaScript.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    JSGlobalContextRef ctx = JSGlobalContextCreate(NULL);
    
    // Convert fuzz input to JS string
    JSStringRef script = JSStringCreateWithUTF8CString(
        reinterpret_cast<const char *>(data), size);
    
    // Evaluate
    JSValueRef exception = NULL;
    JSEvaluateScript(ctx, script, NULL, NULL, 1, &exception);
    
    JSStringRelease(script);
    JSGlobalContextRelease(ctx);
    return 0;
}
```

### 2.3 JSC-Specific Fuzzing Patterns

JSC's DFG/FTL JIT compiler is the primary source of security bugs. Effective fuzzing requires:
- Generating programs that trigger **speculative type assumptions**
- Then violating those assumptions with **type confusion inputs**
- Testing the deoptimization path for correctness

```javascript
// Pattern that often triggers DFG JIT bugs
function trigger(shouldBeObject) {
    // DFG speculates this is an int32
    let x = shouldBeObject + 1;
    
    // If x is used in a bounds check with speculated type
    let arr = [1, 2, 3, 4];
    return arr[x];
}

// Warm up with integers (DFG speculates int32)
for (let i = 0; i < 10000; i++) {
    trigger(42);
}

// Trigger type confusion
trigger({valueOf: function() { return -1; }});
```

## 3. SpiderMonkey Fuzzing

### 3.1 Overview

SpiderMonkey is Mozilla's JavaScript engine, powering Firefox. It uses:
- **Baseline Interpreter/Compiler**: Quick compilation
- **Warp/IonMonkey**: Optimizing JIT compiler
- **GC (Garbage Collector)**: Generational, incremental

### 3.2 SpiderMonkey Fuzz Targets

Mozilla runs multiple fuzz targets for SpiderMonkey:
- **`js::Fuzzer`**: Raw JavaScript source fuzzing
- **`js::StructuredCloneFuzzer`**: Fuzzes the structured clone algorithm
- **`js::WasmFuzzer`**: WebAssembly module fuzzing
- **`js::BigIntFuzzer`**: BigInt arithmetic fuzzing

```c
// SpiderMonkey fuzz target
#include "jsapi.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    JSContext *cx = JS_NewContext(8L * 1024 * 1024);
    if (!cx) return 0;
    
    JS::RealmOptions options;
    JS::RootedObject global(cx, JS_NewGlobalObject(cx, &global_class,
        nullptr, JS::FireOnNewGlobalHook, options));
    
    JSAutoRealm ar(cx, global);
    
    std::string source(reinterpret_cast<const char *>(data), size);
    JS::CompileOptions opts(cx);
    opts.setFile("fuzz");
    
    JS::RootedValue result(cx);
    JS::EvaluateUtf8(cx, opts, source.c_str(), source.length(), &result);
    
    JS_DestroyContext(cx);
    return 0;
}
```

## 4. DOM Fuzzer

### 4.1 DOMato

DOMato is a grammar-based DOM fuzzer developed by Google Project Zero. It generates HTML documents with JavaScript that manipulate the DOM:

```
// DOMato grammar sample
<dom> ::= <html_doc>
<html_doc> ::= "<!DOCTYPE html><html><head></head><body>" <body_content> "</body></html>"
<body_content> ::= <element>*
<element> ::= <div> | <span> | <iframe> | <svg> | <canvas> | <table> | <input>
<div> ::= "<div id=\"" <id> "\">" <body_content> "</div>"
<svg> ::= "<svg>" <svg_content> "</svg>"
<script> ::= "<script>" <js_code> "</script>"
<js_code> ::= <var_decl> <stmt_list>
<var_decl> ::= "var " <var_name> " = document.getElementById('" <id> "');"
<stmt> ::= <method_call> | <prop_assign> | <event_attach>
<method_call> ::= <var_name> "." <method> "(" <args> ");"
```

### 4.2 Dharma

Dharma is Mozilla's grammar-based fuzzer:

```python
# Dharma grammar for DOM fuzzing
+grammar_dom
-d Grammar_DOM_Elements
-d Grammar_DOM_Attributes
-d Grammar_DOM_Methods

Grammar_DOM_Elements ::= 
    div
  | span
  | iframe
  | svg
  | canvas
  | video
  | audio
  | table
  | input

Grammar_DOM_Methods ::= 
    getBoundingClientRect
  | getClientRects
  | querySelector
  | querySelectorAll
  | insertBefore
  | appendChild
  | removeChild
  | replaceChild
  | cloneNode
  | normalize
```

### 4.3 DOM Fuzzing Patterns

DOM fuzzing focuses on:
- **Layout invalidation**: Modify DOM, trigger layout, modify again
- **Frame tree manipulation**: Add/remove iframes, navigate between documents
- **Style recalculation**: Change CSS properties, force style recalc
- **Event dispatch**: Fire events during DOM manipulation (reentrancy bugs)
- **Range/Selection manipulation**: Create and modify ranges during DOM changes

```html
<!-- DOM fuzzing pattern: layout invalidation -->
<div id="target">Text</div>
<script>
    var el = document.getElementById('target');
    // Force layout
    el.offsetHeight;
    // Modify DOM during layout
    el.innerHTML = '<svg><foreignObject>...</foreignObject></svg>';
    // Force another layout
    el.offsetHeight;
    // Remove during pending layout
    el.remove();
</script>
```

## 5. CSS Fuzzer

### 5.1 Overview

CSS fuzzing targets the CSS parser, selector matching, cascading, and layout computation. CSS bugs can lead to use-after-free (when style references stale DOM nodes), OOB reads (in layout computation), and type confusion (in property value handling).

### 5.2 CSS Fuzzing Approach

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a minimal HTML document with embedded CSS
    std::string html = "<html><head><style>";
    html.append(reinterpret_cast<const char *>(data), size);
    html.append("</style></head><body><div id='a'>");
    html.append("</div></body></html>");
    
    // Load into browser engine
    load_html(html.c_str(), html.size());
    force_layout();
    
    return 0;
}
```

### 5.3 CSS Property Fuzzing

Focus on properties that trigger complex layout:
- `display: flex/grid/table`
- `position: fixed/absolute/sticky`
- `transform`, `perspective`, `backface-visibility`
- `writing-mode: vertical-lr/vertical-rl`
- `contain: strict/content`
- `content-visibility: auto/hidden`
- `container-type: inline-size/size`

## 6. Layout Engine Fuzzing

### 6.1 Overview

Layout engine bugs are among the most complex to find and exploit. They involve use-after-free in layout objects, incorrect geometry computations, and crashes during layout invalidation.

### 6.2 Layout Fuzzing Patterns

```html
<!-- Grid layout fuzzing -->
<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr))">
    <div style="grid-column: span 999999">A</div>
    <div style="grid-row: span 999999">B</div>
    <div style="grid-column: -1 / -2">C</div>
</div>

<!-- Flex layout with extreme values -->
<div style="display: flex; flex-direction: row">
    <div style="flex: 1.7976931348623157e+308">X</div>
    <div style="flex: -1.7976931348623157e+308">Y</div>
    <div style="min-width: 0; max-width: -1">Z</div>
</div>

<!-- Table layout edge cases -->
<table style="border-collapse: collapse">
    <colgroup span="0">
    <tr><td colspan="65535">cell</td></tr>
</table>
```

## 7. Font Fuzzer

### 7.1 Overview

Font parsing is a critical attack surface: web fonts are loaded from arbitrary URLs, and font parsers must handle malformed font data without crashing or allowing memory corruption.

### 7.2 woff2 Fuzzing

WOFF2 is a compressed web font format based on Brotli compression:

```c
#include <woff2/woff2_dec.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Decode WOFF2
    std::string output;
    woff2::WOFF2StringOut out(&output);
    out.SetMaxSize(30 * 1024 * 1024);  // 30MB max
    
    woff2::ConvertWOFF2ToTTF(data, size, &out);
    return 0;
}
```

### 7.3 COLRv1 Font Fuzzing

COLRv1 is a new color font format (SVG-like paint records):

```c
#include "SkTypeface.h"
#include "SkCanvas.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a font from fuzz data
    sk_sp<SkTypeface> typeface = SkTypeface::MakeDeserialize(
        SkMemoryStream::MakeDirect(data, size).get());
    
    if (!typeface) return 0;
    
    // Render glyphs
    SkCanvas canvas;
    SkPaint paint;
    paint.setTypeface(typeface);
    paint.setTextSize(100);
    
    // Render all glyphs up to a limit
    int glyph_count = typeface->countGlyphs();
    for (int i = 0; i < glyph_count && i < 256; i++) {
        SkGlyphID glyph = i;
        paint.measureText(&glyph, sizeof(glyph));
    }
    
    return 0;
}
```

## 8. WebIDL Fuzzing

### 8.1 Overview

WebIDL (Web Interface Definition Language) defines the API surface of the web platform. WebIDL fuzzing generates JavaScript that calls DOM APIs with unusual argument combinations, testing the binding layer between JavaScript and C++.

### 8.2 WebIDL Fuzz Target

```c
// WebIDL fuzz target for a specific interface
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    
    // Get the interface object
    auto interface = get_interface(fdp.ConsumeRandomLengthString(32));
    if (!interface) return 0;
    
    // Select a method
    auto method = select_method(interface, fdp.ConsumeIntegralInRange(0, interface->method_count()));
    
    // Generate arguments based on parameter types
    std::vector<JSValue> args;
    for (auto &param : method.parameters) {
        switch (param.type) {
            case Type::Long:
                args.push_back(fdp.ConsumeIntegral<int32_t>());
                break;
            case Type::String:
                args.push_back(fdp.ConsumeRandomLengthString(256));
                break;
            case Type::Boolean:
                args.push_back(fdp.ConsumeBool());
                break;
            case Type::Object:
                args.push_back(create_object(fdp));
                break;
            case Type::ArrayBuffer:
                args.push_back(create_arraybuffer(fdp));
                break;
        }
    }
    
    // Call method
    call_method(interface, method, args);
    return 0;
}
```

## 9. WebAssembly Fuzzing

### 9.1 Overview

WebAssembly (Wasm) is a binary instruction format for stack-based virtual machines. Wasm fuzzing targets the decoder, validator, and JIT compiler (Liftoff/TurboFan in V8, Baseline/IonMonkey in SpiderMonkey).

### 9.2 Wasm Binary Format

```
Wasm Module:
┌────────────────────────────────┐
│ Magic (0x00 0x61 0x73 0x6D)    │
│ Version (0x01 0x00 0x00 0x00)  │
├────────────────────────────────┤
│ Type Section (1)               │
│ Import Section (2)             │
│ Function Section (3)           │
│ Table Section (4)              │
│ Memory Section (5)             │
│ Global Section (6)             │
│ Export Section (7)             │
│ Start Section (8)              │
│ Element Section (9)            │
│ Code Section (10)              │
│ Data Section (11)              │
│ DataCount Section (12)         │
└────────────────────────────────┘
```

### 9.3 Wasm Fuzzing with libFuzzer

```c
#include <wasm.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Validate and decode Wasm module
    wasm_byte_vec_t binary;
    wasm_byte_vec_new(&binary, size, (const char *)data);
    
    wasm_module_t *module = wasm_module_decode(&binary);
    if (!module) {
        wasm_byte_vec_delete(&binary);
        return 0;
    }
    
    // Validate
    if (!wasm_module_validate(module)) {
        wasm_module_delete(module);
        wasm_byte_vec_delete(&binary);
        return 0;
    }
    
    // Instantiate (if validation passes)
    wasm_store_t *store = wasm_store_new();
    wasm_instance_t *instance = wasm_instance_new(store, module, NULL, NULL);
    if (instance) {
        // Call exports
        wasm_instance_delete(instance);
    }
    
    wasm_module_delete(module);
    wasm_store_delete(store);
    wasm_byte_vec_delete(&binary);
    return 0;
}
```

### 9.4 Wasm-Specific Fuzzing Patterns

```javascript
// Trigger Liftoff JIT compilation
const buf = new Uint8Array([...wasm_binary...]);
const mod = new WebAssembly.Module(buf);
const inst = new WebAssembly.Instance(mod);

// Call function many times to trigger optimization
for (let i = 0; i < 100000; i++) {
    inst.exports.func(i);
}

// Then call with edge-case values
inst.exports.func(0x7FFFFFFF);
inst.exports.func(-2147483648);
inst.exports.func(NaN);
inst.exports.func(Infinity);
```

## 10. Mojo IPC Fuzzing

### 10.1 MojoFuzzer

MojoFuzzer is Chromium's fuzzer for Mojo IPC messages. It generates valid Mojo message structures and mutates their fields:

```c++
// MojoFuzzer target
#include "mojo/public/interfaces/bindings/interface_validator.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mojo::internal::MessageValidator validator;
    
    // Parse as Mojo message
    mojo::Message message;
    if (!mojo::Message::ParseFromWire(
            base::span<const uint8_t>(data, size), &message)) {
        return 0;
    }
    
    // Validate message structure
    validator.Validate(message);
    
    return 0;
}
```

### 10.2 Chrome Mojo Fuzzing Infrastructure

Chrome's fuzzing infrastructure includes:
- **Mojo message fuzzers**: Fuzz individual Mojo interface methods
- **Mojo connection fuzzers**: Fuzz the connection setup and teardown
- **Browser-side Mojo fuzzers**: Fuzz the browser process's handling of Mojo messages from the renderer

## 11. GPU Process Fuzzing

### 11.1 Overview

Chrome's GPU process handles rendering, video decode, and WebGL/WebGPU commands. GPU process bugs are particularly dangerous because the GPU process has elevated privileges (access to GPU hardware, shared memory with the browser process).

### 11.2 GPU Fuzzing Targets

- **Command buffer fuzzing**: Fuzz the GPU command buffer protocol
- **WebGL parameter fuzzing**: Fuzz WebGL API calls with invalid parameters
- **WebGPU shader fuzzing**: Fuzz WebGPU shader compilation (WGSL, SPIR-V)
- **Video decode fuzzing**: Fuzz hardware video decoder integration

```c++
// GPU command buffer fuzzer
#include "gpu/command_buffer/common/cmd_buffer_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    gpu::CommandBufferNode node;
    
    // Interpret fuzz data as GPU commands
    auto cmds = base::span_cast<const gpu::CommandHeader>(data, size);
    
    for (const auto &cmd : cmds) {
        node.ProcessCommand(cmd);
    }
    
    return 0;
}
```

## 12. Site Isolation Fuzzing

### 12.1 Overview

Chrome's Site Isolation architecture ensures that different origin's content is rendered in separate processes. Fuzzing Site Isolation targets the **Cross-Origin Read Blocking (CORB)**, **Cross-Origin Opener Policy (COOP)**, and **Cross-Origin Embedder Policy (COEP)** mechanisms.

### 12.2 Fuzzing Patterns

- Cross-origin frame navigation during page load
- Popup creation with COOP/COEP headers
- Service worker intercepting cross-origin requests
- `<object>` and `<embed>` loading cross-origin resources

## 13. Chrome/Chromium Fuzzing Infrastructure

### 13.1 ClusterFuzz

ClusterFuzz is the backbone of Chrome's fuzzing infrastructure. It runs 24/7 on Google's infrastructure with:
- **5,000+ cores** allocated for fuzzing
- **Multiple fuzzing engines**: libFuzzer, AFL++, Centipede
- **Multiple sanitizers**: ASan, MSan, UBSan, TSan
- **Continuous builds**: Fuzz targets are rebuilt every 6 hours
- **Automatic crash triage**: Deduplication, minimization, regression testing

### 13.2 OSS-Fuzz Integration

Chrome's fuzz targets are also part of OSS-Fuzz:
- **Project**: chromium
- **Targets**: 100+ individual fuzz targets covering all major components
- **Seed corpora**: Generated from test data and example inputs
- **Dictionaries**: Auto-generated from WebIDL definitions

### 13.3 Key Chrome Fuzz Targets

| Target | Component | Engine |
|--------|-----------|--------|
| `v8_fuzzer` | V8 JavaScript | libFuzzer |
| `v8_wasm_fuzzer` | WebAssembly | libFuzzer |
| `blink_parser_fuzzer` | HTML parser | libFuzzer |
| `css_parser_fuzzer` | CSS parser | libFuzzer |
| `woff2_fuzzer` | WOFF2 fonts | libFuzzer |
| `pdfium_fuzzer` | PDF rendering | libFuzzer |
| `mojo_fuzzer` | Mojo IPC | libFuzzer |
| `gpu_fuzzer` | GPU commands | libFuzzer |
| `skia_fuzzer` | Skia graphics | libFuzzer |
| `media_fuzzer` | Media decoding | libFuzzer |
| `net_fuzzer` | Network stack | libFuzzer |
| `xml_fuzzer` | XML parser | libFuzzer |

### 13.4 Chrome Bug Discovery Statistics

ClusterFuzz has found over **30,000 bugs** in Chrome, including:
- **~500 security bugs** (memory corruption, use-after-free, type confusion)
- **~2,000 stability bugs** (null dereferences, assertion failures)
- **~27,500 other bugs** (incorrect rendering, performance issues)

## 14. MathML Fuzzing

### 14.1 Overview

MathML (Mathematical Markup Language) is an XML-based format for describing mathematical notation. While less widely used than HTML or SVG, MathML is supported in all major browsers and presents a unique fuzzing surface due to its complex layout requirements.

### 14.2 MathML Attack Surface

- **Layout computation**: MathML elements require specialized layout algorithms (fraction bars, subscripts, superscripts, under/over scripts)
- **Stretchy operators**: Operators that stretch to fit their container require dynamic glyph selection
- **Nested structures**: Deeply nested MathML elements stress layout recursion
- **Interaction with CSS**: MathML layout must integrate with CSS flex/grid layout

### 14.3 MathML Fuzzing Patterns

```html
<!-- Deep nesting stress test -->
<math>
  <mfrac>
    <mfrac>
      <mfrac>
        <mfrac>
          <mi>x</mi>
          <mn>1</mn>
        </mfrac>
        <mn>2</mn>
      </mfrac>
      <mn>3</mn>
    </mfrac>
    <mn>4</mn>
  </mfrac>
</math>

<!-- Stretchy operator with extreme dimensions -->
<math>
  <mo stretchy="true" minsize="99999pt" maxsize="1pt">(</mo>
  <mfrac><mi>a</mi><mi>b</mi></mfrac>
  <mo stretchy="true">)</mo>
</math>

<!-- Mixed MathML + CSS stress -->
<math style="display: flex; width: 0px; font-size: 0px;">
  <mtable style="display: grid;">
    <mtr><mtd><mi>x</mi></mtd></mtr>
  </mtable>
</math>
```

## 15. Advanced Browser Fuzzing Techniques

### 14.1 JIT Spray Fuzzing

JIT compiler bugs are among the most valuable because they can lead to arbitrary code execution. Fuzzing for JIT bugs requires:

1. **Warm-up phase**: Execute a function many times with consistent types
2. **Compilation trigger**: The JIT compiler compiles the function with type assumptions
3. **Type confusion phase**: Execute the function with different types, violating assumptions
4. **Exploitation**: The JIT-compiled code accesses memory based on incorrect type information

### 14.2 Garbage Collection Fuzzing

GC bugs (especially moving GC bugs) can cause use-after-free when references are not properly updated:

```javascript
// GC stress pattern
function gcStress() {
    // Allocate many objects
    let arr = [];
    for (let i = 0; i < 10000; i++) {
        arr.push({x: i, y: [i, i+1, i+2]});
    }
    
    // Trigger GC
    for (let i = 0; i < 10; i++) {
        new ArrayBuffer(1024 * 1024);
    }
    
    // Access objects after GC (potential UAF)
    for (let i = 0; i < arr.length; i++) {
        arr[i].y[0];
    }
}
```

### 14.3 Race Condition Fuzzing

Browser engines have concurrent execution (main thread, worker threads, GC thread). Race conditions can lead to use-after-free:

```javascript
// Worker + GC race pattern
let shared = new SharedArrayBuffer(1024);
let worker = new Worker('worker.js');

// Main thread modifies shared state
setInterval(() => {
    let view = new Int32Array(shared);
    view[0] = Date.now();
    
    // Trigger GC concurrently
    if (Math.random() > 0.9) {
        new ArrayBuffer(10 * 1024 * 1024);
    }
}, 0);

// Worker reads shared state
// worker.js: let view = new Int32Array(shared); ...
```

## References

[1] Groß, S. (2019). *fuzzilli: Fuzzing for JavaScript JIT Compiler Bugs*. Google Project Zero. https://github.com/googleprojectzero/fuzzilli

[2] Google. *ClusterFuzz*. https://github.com/google/clusterfuzz

[3] Google. *Chromium Fuzzing*. https://www.chromium.org/Home/chromium-security/

[4] Mozilla. *Fuzzing SpiderMonkey*. https://wiki.mozilla.org/Security/Fuzzing

[5] WebKit. *Fuzzing WebKit*. https://trac.webkit.org/

[6] Holz, S. & Groß, S. (2023). *JIT-Fuzzing: Attacking JIT Compilers with Compiler Techniques*. USENIX Security.

[7] Serebryany, K. (2016). *Announcing OSS-Fuzz: Continuous Fuzzing for Open Source Software*. Google Security Blog.

[8] CVE-2024-0519. *V8 WebAssembly SIMD OOB Write*. https://nvd.nist.gov/vuln/detail/CVE-2024-0519

[9] CVE-2023-44299. *V8 Type Confusion in Optimized Arithmetic*. https://nvd.nist.gov/vuln/detail/CVE-2023-44299

[10] CVE-2022-4904. *V8 RegExp OOB Access*. https://nvd.nist.gov/vuln/detail/CVE-2022-4904

[11] CVE-2021-37975. *V8 Map Transition Bug*. https://nvd.nist.gov/vuln/detail/CVE-2021-37975

[12] Chen, T., et al. (2023). *GraphicsFuzz: Shader Compiler Fuzzing*. ISSTA.

[13] Google. *fuzzilli: JavaScript Engine Fuzzer*. https://github.com/googleprojectzero/fuzzilli

[14] Google Project Zero. *DOMato: DOM Fuzzer*. https://github.com/googleprojectzero/DOMATO

[15] Mozilla. *Dharma: Grammar-Based Fuzzer*. https://github.com/MozillaSecurity/dharma

[16] V8 Team. *V8 JavaScript Engine*. https://v8.dev/

[17] Google. *WebAssembly Specification*. https://webassembly.github.io/spec/
