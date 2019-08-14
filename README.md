# HTTP Request Smuggler

This is an extension for Burp Suite designed to help you launch [HTTP Request Smuggling](https://portswigger.net/blog/http-desync-attacks) attacks. It supports scanning for Request Smuggling vulnerabilities, and also aids exploitation by handling cumbersome offset-tweaking for you.

### Install
The easiest way to install this is in Burp Suite, via Extender -> BApp Store.

If you prefer to load the jar manually, in Burp Suite (community or pro), use Extender -> Extensions -> Add to load `build/libs/http-request-smuggler-all.jar`

### Compile
* [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) is a dependency of this project, add it to the root of this source tree as `turbo-intruder-all.jar`
* Build with `gradle fatJar`

### Use
Right click on a request and click 'Launch Desync probe', then watch the extension's output pane. 

For more advanced use watch the [video](https://portswigger.net/blog/http-desync-attacks).

### Practice

We've released [free online labs to practise against](https://portswigger.net/web-security/request-smuggling).
