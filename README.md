# HTTP Request Smuggler

This is an extension for Burp Suite designed to help you launch [HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling) attacks, originally created during [HTTP Desync Attacks](https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn) research. It supports scanning for Request Smuggling vulnerabilities, and also aids exploitation by handling cumbersome offset-tweaking for you.

This extension should not be confused with [Burp Suite HTTP Smuggler](https://github.com/nccgroup/BurpSuiteHTTPSmuggler), which uses similar techniques but is focused exclusively bypassing WAFs.

### Install
The easiest way to install this is in Burp Suite, via `Extensions -> BApp Store`.

If you prefer to load the jar manually, in Burp Suite (community or pro), use `Extensions -> Add` to load `build/libs/http-request-smuggler-all.jar`

### Compile

Build using:

Linux: `./gradlew build fatjar`

Windows: `gradlew.bat build fatjar`

Grab the output from `build/libs/http-request-smuggler-all.jar`

### Use
Right-click on a request and click `Extensions -> HTTP Request Smuggler -> Smuggle probe`, then watch the extension's Output pane under `Extensions->HTTP Request Smuggler`

If you're using Burp Pro, any findings will also be reported as scan issues.

If you right-click on a request that uses chunked encoding, you'll see another option marked `Launch Smuggle attack`. This will open a Turbo Intruder window in which you can try out various attacks by editing the `prefix` variable.

For more advanced use watch the [video](https://portswigger.net/blog/http-desync-attacks).

### Practice

We've released a collection of [free online labs to practise against](https://portswigger.net/web-security/request-smuggling). Here's how to use the tool to solve the first lab - [HTTP request smuggling, basic CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te):

1. Use the Extensions->BApp Store tab to install the 'HTTP Request Smuggler' extension.
2. Load the lab homepage, find the request in the proxy history, right-click and select 'Extensions -> HTTP Request Smuggler -> Smuggle probe', then click 'OK'.
3. Wait for the probe to complete, indicated by 'Completed request with key ...' appearing in the extension's output tab.
4. If you're using Burp Suite Pro, find the reported vulnerability in the dashboard and open the first attached request.
5. If you're using Burp Suite Community, copy the request from the output tab and paste it into the repeater, then complete the 'Target' details on the top right.
6. Right-click on the request and select 'Extensions -> HTTP Request Smuggler -> Smuggle attack (CL.TE)'.
7. Change the value of the 'prefix' variable to 'G', then click 'Attack' and confirm that one response says 'Unrecognized method GPOST'.

By changing the 'prefix' variable in step 7, you can solve all the labs and virtually every real-world scenario.
