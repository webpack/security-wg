# The Webpack Threat Model

The Webpack threat model delineates what Webpack trusts at build time and what it does not trust (chiefly, inputs that can cross a network boundary when using dev tooling).

For a security issue to be considered a vulnerability in Webpack (or other official tooling), it must not require compromise of trusted elements.

## Elements Webpack Does NOT Trust

1. **Network data passed to development tooling**  
   Any data received by [webpack-dev-server](https://webpack.js.org/configuration/dev-server/) (or equivalent dev middleware), including HTTP requests, headers, query strings, WebSocket/HMR messages, and static-file requests from a browser.  
   *If data passing through these interfaces can trigger behavior beyond what is documented (e.g., directory traversal, arbitrary file read outside the configured static roots, state corruption, injection into HMR control channels), that likely indicates a security vulnerability.*

2. **Untrusted clients interacting with dev tooling**  
   When dev tooling is reachable from non-developer networks (mistakes, port-forwarding, Wi-Fi sharing, etc.), those clients are untrusted. The server must enforce its documented isolation guarantees (e.g., path normalization, origin checks where applicable).

> [!NOTE]
> This model is based on the assumption that **Webpack is not used as your production edge server**. If someone deploys webpack-dev-server in a production environment or makes it accessible on the public internet, the security risks that arise should be considered an operational misconfiguration, not a Webpack vulnerability. While it is still worthwhile to make development tools more resilient against misuse, that is not the primary responsibility of Webpack itself.

## Elements Webpack Trusts

1. **Developers and development infrastructure**  
   Local machines, CI/CD runners, container images, shell environment, and the people operating them.

2. **Operating system and Node.js runtime**  
   Including their configuration and anything under OS control.

3. **All code executed at build time**  
   - `webpack.config.*` and any code it imports  
   - Loaders and plugins (including transitive npm dependencies)  
   - Dev server/middleware configuration hooks  
   These are considered trusted application code.

4. **Project sources and assets**  
   JavaScript/TypeScript, styles, templates, images, fonts, etc., within the configured project context and any paths the build intentionally resolves (`resolve.modules`, aliases, loader `include`/`exclude`, etc.).

5. **Build-time environment and configuration inputs**  
   CLI flags, environment variables, and values injected via `DefinePlugin`, `EnvironmentPlugin`, etc., are trusted inputs provided by the developer/build system.

6. **Explicitly configured network resources**  
   Any outbound fetches/proxies that the developer *intentionally* configures in dev tooling (e.g., `devServer.proxy`) are considered trusted choices made by the developer.

7. **Privileges of the executing user**  
   Whatever the invoking user can access (files, sockets, processes) is inherited by the build and thus by code it executes.


## Examples of Vulnerabilities (in scope)

- **Path traversal / arbitrary file read** via `webpack-dev-server` static file serving escaping configured roots.
- **HMR/WebSocket message injection** that lets an unauthenticated client corrupt dev-server state, run client-side JS outside the documented HMR protocol, or crash the server.
- **Reflected file serving bugs** that allow reading source maps or files outside intended scopes through crafted URLs.
- **Denial of service** in dev tooling where a single unauthenticated request can lock the event loop or exhaust memory beyond documented behavior.
- **Insufficient origin/host checks** in dev tooling that permit cross-origin misuse of privileged endpoints (when such checks are part of the documented guarantees).

*(All of the above assume default/documented configurations and no compromise of trusted elements.)*

> [!NOTE]  
> **[CVE-2024-43788](https://www.cve.org/CVERecord?id=CVE-2024-43788) – DOM Clobbering → XSS in Webpack Runtime**  
> In affected versions, the `AutoPublicPathRuntimeModule` relied on `document.currentScript` without verifying it was actually a `<script>` element.  
> Attacker-controlled HTML elements (e.g., with `name="currentScript"`) could override this, causing Webpack’s runtime to miscompute `__webpack_require__.p` and load attacker-controlled scripts.  
> Fixed in **Webpack 5.94.0**.  
> *This falls in scope because it lets untrusted network input alter Webpack’s runtime behavior beyond documented guarantees.*

## Examples of Non-Vulnerabilities (out of scope)

### Malicious Third-Party Loaders/Plugins ([CWE-1357](https://cwe.mitre.org/data/definitions/1357.html))
Code executed at build time (loaders/plugins/config and their deps) is trusted. If a malicious or vulnerable loader causes RCE, file exfiltration, or DoS during the build, that is a supply-chain risk for the project, not a Webpack vulnerability.

### Application Bugs in the Bundled Output
XSS, CSRF, CSP misconfigurations, or logic flaws in the application bundle served in production are not Webpack vulnerabilities. Webpack is a compiler/bundler; correctness and security of the resulting app code are the app’s responsibility.

### Leaking Secrets by Misconfiguration
Accidentally injecting secrets into client bundles via `DefinePlugin`/`EnvironmentPlugin`, or bundling dev-only code because of incorrect `mode`/`define` settings, is an application/config issue, not a Webpack vulnerability.

### Uncontrolled Search Path / Arbitrary File Access ([CWE-427](https://cwe.mitre.org/data/definitions/427.html)) Within Trusted Context
Webpack (and loaders) reading any file reachable by the invoking user or configured resolve paths is expected behavior. If a developer points `resolve.modules` or a loader at a sensitive directory, that is not a Webpack vulnerability.

### External Control of Build Configuration ([CWE-15](https://cwe.mitre.org/data/definitions/15.html))
If an attacker can modify environment variables, CLI flags, or `webpack.config.*`, they already control trusted inputs. Consequences are out of scope for Webpack’s threat model.

### Vulnerabilities in Node.js / OS
Bugs in Node.js, the kernel, or OpenSSL—especially on EOL versions—are outside Webpack’s scope.
