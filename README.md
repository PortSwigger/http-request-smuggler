# HTTP Request Smuggler

This Burp Suite extension automatically detects and exploits [HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling) vulnerabilities using advanced desynchronization techniques developed by PortSwigger researcher James Kettle. It supports comprehensive scanning for HTTP/1.1 and HTTP/2-downgrade desync vulnerabilities, client-side desyncs, and connection state attacks.

Version 3.0 landed in 2025 and adds parser discrepancy detection, which bypasses widespread desync defences and makes it significantly more effective. For further information on this, refer to the whitepaper [HTTP/1.1 Must Die: The Desync Endgame](https://portswigger.net/research/http1-must-die).

It's fully compatible with Burp Suite DAST, Professional, and Community editions. Pro and Community editions have a "research mode" for exploring novel techniques, and the DAST integration is useful if you want recurring scans to flag novel threats as soon as they're released.

### Features
- Detection based on root-cause detection of underlying parsing discrepancies, which is significantly more reliable and resistant to target-specific quirks.
- Many permutation techniques for bypassing different server configurations
- HTTP/1.1 CL.TE and TE.CL desync detection with timeout-based confirmation
- HTTP/2 request smuggling including tunneling and header injection attacks
- Client-side desync detection for browser-powered attacks
- Header smuggling and removal vulnerability detection
- Connection state manipulation and pause-based desync techniques
- Automated exploit generation with Turbo Intruder integration
- False positive reduction through multiple validation techniques


### Install
The easiest way to install this is in Burp Suite, via `Extender -> BApp Store`.

If you prefer to load the jar manually, in Burp Suite (community or pro), use `Extender -> Extensions -> Add` to load `build/libs/http-request-smuggler-all.jar`

### Compile
[Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) is a dependency of this project, add it to the root of this source tree as `turbo-intruder-all.jar`

Build using:

Linux: `./gradlew build fatjar`

Windows: `gradlew.bat build fatjar`

Grab the output from `build/libs/desynchronize-all.jar`

### Use
Right click on a request and click `Launch Smuggle probe`, then watch the Organizer and extension's output pane under `Extender->Extensions->HTTP Request Smuggler`

If you're using Burp Pro, any findings will also be reported as scan issues.

If you right click on a request that uses chunked encoding, you'll see another option marked `Launch Smuggle attack`. This will open a Turbo Intruder window in which you can try out various attacks by editing the `prefix` variable.

For more advanced use watch the [video](https://portswigger.net/blog/http-desync-attacks).

### Practice

We've released a collection of [free online labs to practise against](https://portswigger.net/web-security/request-smuggling). Here's how to use the tool to solve the first lab - [HTTP request smuggling, basic CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te):

1. Use the Extender->BApp store tab to install the 'HTTP Request Smuggler' extension.
2. Load the lab homepage, find the request in the proxy history, right click and select 'Launch smuggle probe', then click 'OK'.
3. Wait for the probe to complete, indicated by 'Completed 1 of 1' appearing in the extension's output tab.
4. If you're using Burp Suite Pro, find the reported vulnerability in the dashboard and open the first attached request.
5. If you're using Burp Suite Community, copy the request from the output tab and paste it into the repeater, then complete the 'Target' details on the top right.
6. Right click on the request and select 'Smuggle attack (CL.TE)'.
7. Change the value of the 'prefix' variable to 'G', then click 'Attack' and confirm that one response says 'Unrecognised method GPOST'.

By changing the 'prefix' variable in step 7, you can solve all the labs and virtually every real-world scenario.
