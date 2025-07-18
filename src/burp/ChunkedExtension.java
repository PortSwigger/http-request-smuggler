package burp;

import java.util.HashMap;
import java.util.List;

public class ChunkedExtension extends Scan {

    // Track which hosts we've already scanned
    private static HashMap<String, Boolean> scannedHosts = new HashMap<>();

    ChunkedExtension(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        // Only scan each host once
        String hostKey = service.getHost() + ":" + service.getPort();
        if (scannedHosts.containsKey(hostKey)) {
            Utilities.log("Skipping " + hostKey + " - already scanned");
            return null;
        }
        
        scannedHosts.put(hostKey, true);
        Utilities.log("Running TERM.EXT detection against " + hostKey);
        
        // First, check if we can perform a normal GET request (connectivity test)
        byte[] normalGetReq = buildNormalGetRequest(service);
        Resp connectivityTest = request(service, normalGetReq, 0, true);
        if (connectivityTest.timedOut()) {
            Utilities.log("Host " + hostKey + " appears unresponsive. Skipping...");
            return null;
        }
        
        // Convert to POST request if it's GET
        byte[] postReq = baseReq;
        if (baseReq[0] == 'G') {
            postReq = Utilities.setMethod(baseReq, "POST");
            postReq = Utilities.addOrReplaceHeader(postReq, "Content-Type", "application/x-www-form-urlencoded");
            postReq = Utilities.setBody(postReq, "test=value");
        }
        
        // Add Transfer-Encoding: chunked header
        postReq = Utilities.addOrReplaceHeader(postReq, "Transfer-Encoding", "chunked");
        postReq = Utilities.addOrReplaceHeader(postReq, "Connection", "close");
        
        // Test TERM.EXT (Terminator in Extension)
        testTermExt(postReq, service);
        
        // Test EXT.TERM (Extension Terminator)
        testExtTerm(postReq, service);
        
        // Test TERM.SPILL (Terminator Spill)
        testTermSpill(postReq, service);
        
        // Test SPILL.TERM (Spill Terminator)
        testSpillTerm(postReq, service);
        
        // Test Length-based: ONE.TWO
        testOneTwo(postReq, service);
        
        // Test Length-based: TWO.ONE
        testTwoOne(postReq, service);
        
        // Test Length-based: ZERO.TWO
        testZeroTwo(postReq, service);
        
        // Test Length-based: TWO.ZERO
        testTwoZero(postReq, service);
        
        return null;
    }
    
    // TERM.EXT: Discrepancies in parsing of line terminators in chunk extensions
    private void testTermExt(byte[] baseReq, IHttpService service) {
        String[] lineTerminators = {"\n", "\r", "\rX", "\r\r"};
        
        for (String terminator : lineTerminators) {
            byte[] testReq = buildTermExtPayload(baseReq, terminator);
            
            // Send the request
            Resp response = request(service, testReq, 0, true);
            
            // Check for timeout or unusual behavior
            if (response.timedOut()) {
                Utilities.log("TERM.EXT potential vulnerability detected with terminator: " + 
                            terminator.replace("\n", "\\n").replace("\r", "\\r"));
                
                // Create a follow-up request to confirm
                byte[] normalReq = buildNormalChunkedRequest(baseReq);
                Resp normalResponse = request(service, normalReq, 0, true);
                
                if (!normalResponse.timedOut()) {
                    // This suggests a parsing discrepancy
                    String title = "Possible HTTP Request Smuggling: TERM.EXT (Chunk Extension Parsing)";
                    String description = "A timeout was observed when using line terminator '" + 
                                       terminator.replace("\n", "\\n").replace("\r", "\\r") + 
                                       "' in chunk extensions, while normal chunked requests work fine. " +
                                       "This suggests a discrepancy in how the front-end and back-end parse " +
                                       "line terminators in chunk extensions, which could be exploitable " +
                                       "for HTTP request smuggling attacks.";
                    
                    report(title, description, response, normalResponse);
                }
            }
        }
    }
    
    // EXT.TERM: Discrepancies in parsing of line terminators in chunk extensions (different payload)
    private void testExtTerm(byte[] baseReq, IHttpService service) {
        String[] lineTerminators = {"\n", "\r", "\rX", "\r\r"};
        
        for (String terminator : lineTerminators) {
            byte[] testReq = buildExtTermPayload(baseReq, terminator);
            
            // Send the request
            Resp response = request(service, testReq, 0, true);
            
            // Check for timeout or unusual behavior
            if (response.timedOut()) {
                Utilities.log("EXT.TERM potential vulnerability detected with terminator: " + 
                            terminator.replace("\n", "\\n").replace("\r", "\\r"));
                
                // Create a follow-up request to confirm
                byte[] normalReq = buildNormalChunkedRequest(baseReq);
                Resp normalResponse = request(service, normalReq, 0, true);
                
                if (!normalResponse.timedOut()) {
                    // This suggests a parsing discrepancy
                    String title = "Possible HTTP Request Smuggling: EXT.TERM (Chunk Extension Parsing)";
                    String description = "A timeout was observed when using line terminator '" + 
                                       terminator.replace("\n", "\\n").replace("\r", "\\r") + 
                                       "' in chunk extensions with different chunk sizes, while normal chunked requests work fine. " +
                                       "This suggests a discrepancy in how the front-end and back-end parse " +
                                       "line terminators in chunk extensions, which could be exploitable " +
                                       "for HTTP request smuggling attacks.";
                    
                    report(title, description, response, normalResponse);
                }
            }
        }
    }
    
    // TERM.SPILL: Discrepancies in parsing of line terminators in oversized chunks
    private void testTermSpill(byte[] baseReq, IHttpService service) {
        String[] lineTerminators = {"\n", "\r", "", "XX", "\rX", "\r\r"};
        
        for (String terminator : lineTerminators) {
            byte[] testReq = buildTermSpillPayload(baseReq, terminator);
            
            // Send the request
            Resp response = request(service, testReq, 0, true);
            
            // Check for timeout or unusual behavior
            if (response.timedOut()) {
                Utilities.log("TERM.SPILL potential vulnerability detected with terminator: " + 
                            terminator.replace("\n", "\\n").replace("\r", "\\r"));
                
                // Create a follow-up request to confirm
                byte[] normalReq = buildNormalChunkedRequest(baseReq);
                Resp normalResponse = request(service, normalReq, 0, true);
                
                if (!normalResponse.timedOut()) {
                    // This suggests a parsing discrepancy
                    String title = "Possible HTTP Request Smuggling: TERM.SPILL (Terminator Spill)";
                    String description = "A timeout was observed when using line terminator '" + 
                                       terminator.replace("\n", "\\n").replace("\r", "\\r") + 
                                       "' in oversized chunks, while normal chunked requests work fine. " +
                                       "This suggests a discrepancy in how the front-end and back-end parse " +
                                       "line terminators in chunk bodies, which could be exploitable " +
                                       "for HTTP request smuggling attacks.";
                    
                    report(title, description, response, normalResponse);
                }
            }
        }
    }
    
    // SPILL.TERM: Discrepancies in parsing of line terminators in oversized chunks (different payload)
    private void testSpillTerm(byte[] baseReq, IHttpService service) {
        String[] lineTerminators = {"\n", "\r", "", "XX", "\rX", "\r\r"};
        
        for (String terminator : lineTerminators) {
            byte[] testReq = buildSpillTermPayload(baseReq, terminator);
            
            // Send the request
            Resp response = request(service, testReq, 0, true);
            
            // Check for timeout or unusual behavior
            if (response.timedOut()) {
                Utilities.log("SPILL.TERM potential vulnerability detected with terminator: " + 
                            terminator.replace("\n", "\\n").replace("\r", "\\r"));
                
                // Create a follow-up request to confirm
                byte[] normalReq = buildNormalChunkedRequest(baseReq);
                Resp normalResponse = request(service, normalReq, 0, true);
                
                if (!normalResponse.timedOut()) {
                    // This suggests a parsing discrepancy
                    String title = "Possible HTTP Request Smuggling: SPILL.TERM (Spill Terminator)";
                    String description = "A timeout was observed when using line terminator '" + 
                                       terminator.replace("\n", "\\n").replace("\r", "\\r") + 
                                       "' in oversized chunks with different chunk sizes, while normal chunked requests work fine. " +
                                       "This suggests a discrepancy in how the front-end and back-end parse " +
                                       "line terminators in chunk bodies, which could be exploitable " +
                                       "for HTTP request smuggling attacks.";
                    
                    report(title, description, response, normalResponse);
                }
            }
        }
    }
    
    // Length-based: ONE.TWO - Discrepancies in perceived length of line terminators in chunk bodies
    private void testOneTwo(byte[] baseReq, IHttpService service) {
        String[] lineTerminators = {"\n", "\r"};
        
        for (String terminator : lineTerminators) {
            byte[] testReq = buildOneTwoPayload(baseReq, terminator);
            
            // Send the request
            Resp response = request(service, testReq, 0, true);
            
            // Check for timeout or unusual behavior
            if (response.timedOut()) {
                Utilities.log("ONE.TWO potential vulnerability detected with terminator: " + 
                            terminator.replace("\n", "\\n").replace("\r", "\\r"));
                
                // Create a follow-up request to confirm
                byte[] normalReq = buildNormalChunkedRequest(baseReq);
                Resp normalResponse = request(service, normalReq, 0, true);
                
                if (!normalResponse.timedOut()) {
                    // This suggests a parsing discrepancy
                    String title = "Possible HTTP Request Smuggling: ONE.TWO (Length-based Chunk Body)";
                    String description = "A timeout was observed when using line terminator '" + 
                                       terminator.replace("\n", "\\n").replace("\r", "\\r") + 
                                       "' in chunk bodies with specific length calculations, while normal chunked requests work fine. " +
                                       "This suggests a discrepancy in how the front-end and back-end calculate " +
                                       "chunk lengths when line terminators are present, which could be exploitable " +
                                       "for HTTP request smuggling attacks.";
                    
                    report(title, description, response, normalResponse);
                }
            }
        }
    }
    
    // Length-based: TWO.ONE - Discrepancies in perceived length of line terminators in chunk bodies
    private void testTwoOne(byte[] baseReq, IHttpService service) {
        String[] lineTerminators = {"\n", "\r"};
        
        for (String terminator : lineTerminators) {
            byte[] testReq = buildTwoOnePayload(baseReq, terminator);
            
            // Send the request
            Resp response = request(service, testReq, 0, true);
            
            // Check for timeout or unusual behavior
            if (response.timedOut()) {
                Utilities.log("TWO.ONE potential vulnerability detected with terminator: " + 
                            terminator.replace("\n", "\\n").replace("\r", "\\r"));
                
                // Create a follow-up request to confirm
                byte[] normalReq = buildNormalChunkedRequest(baseReq);
                Resp normalResponse = request(service, normalReq, 0, true);
                
                if (!normalResponse.timedOut()) {
                    // This suggests a parsing discrepancy
                    String title = "Possible HTTP Request Smuggling: TWO.ONE (Length-based Chunk Body)";
                    String description = "A timeout was observed when using line terminator '" + 
                                       terminator.replace("\n", "\\n").replace("\r", "\\r") + 
                                       "' in chunk bodies with different length calculations, while normal chunked requests work fine. " +
                                       "This suggests a discrepancy in how the front-end and back-end calculate " +
                                       "chunk lengths when line terminators are present, which could be exploitable " +
                                       "for HTTP request smuggling attacks.";
                    
                    report(title, description, response, normalResponse);
                }
            }
        }
    }
    
    // Length-based: ZERO.TWO - Discrepancies in perceived length of line terminators in chunk bodies
    private void testZeroTwo(byte[] baseReq, IHttpService service) {
        String[] lineTerminators = {""}; // Only empty string for ZERO.TWO
        
        for (String terminator : lineTerminators) {
            byte[] testReq = buildZeroTwoPayload(baseReq, terminator);
            
            // Send the request
            Resp response = request(service, testReq, 0, true);
            
            // Check for timeout or unusual behavior
            if (response.timedOut()) {
                Utilities.log("ZERO.TWO potential vulnerability detected with empty terminator");
                
                // Create a follow-up request to confirm
                byte[] normalReq = buildNormalChunkedRequest(baseReq);
                Resp normalResponse = request(service, normalReq, 0, true);
                
                if (!normalResponse.timedOut()) {
                    // This suggests a parsing discrepancy
                    String title = "Possible HTTP Request Smuggling: ZERO.TWO (Length-based Chunk Body)";
                    String description = "A timeout was observed when using an empty line terminator in chunk bodies " +
                                       "with specific length calculations, while normal chunked requests work fine. " +
                                       "This suggests a discrepancy in how the front-end and back-end calculate " +
                                       "chunk lengths when empty terminators are present, which could be exploitable " +
                                       "for HTTP request smuggling attacks.";
                    
                    report(title, description, response, normalResponse);
                }
            }
        }
    }
    
    // Length-based: TWO.ZERO - Discrepancies in perceived length of line terminators in chunk bodies
    private void testTwoZero(byte[] baseReq, IHttpService service) {
        String[] lineTerminators = {""}; // Only empty string for TWO.ZERO
        
        for (String terminator : lineTerminators) {
            byte[] testReq = buildTwoZeroPayload(baseReq, terminator);
            
            // Send the request
            Resp response = request(service, testReq, 0, true);
            
            // Check for timeout or unusual behavior
            if (response.timedOut()) {
                Utilities.log("TWO.ZERO potential vulnerability detected with empty terminator");
                
                // Create a follow-up request to confirm
                byte[] normalReq = buildNormalChunkedRequest(baseReq);
                Resp normalResponse = request(service, normalReq, 0, true);
                
                if (!normalResponse.timedOut()) {
                    // This suggests a parsing discrepancy
                    String title = "Possible HTTP Request Smuggling: TWO.ZERO (Length-based Chunk Body)";
                    String description = "A timeout was observed when using an empty line terminator in chunk bodies " +
                                       "with different length calculations, while normal chunked requests work fine. " +
                                       "This suggests a discrepancy in how the front-end and back-end calculate " +
                                       "chunk lengths when empty terminators are present, which could be exploitable " +
                                       "for HTTP request smuggling attacks.";
                    
                    report(title, description, response, normalResponse);
                }
            }
        }
    }
    
    private byte[] buildTermExtPayload(byte[] baseReq, String lineTerminator) {
        // Build the TERM.EXT payload based on smugchunks implementation
        String host = Utilities.getHeader(baseReq, "Host");
        String path = Utilities.getPathFromRequest(baseReq);
        String method = Utilities.getMethod(baseReq);
        
        // TERM.EXT payload structure:
        // 2;{line_terminator}XX\r\n
        // 10\r\n
        // 1f\r\n
        // AAAABBBBCCCC\r\n
        // 0\r\n
        // \r\n
        // DDDDEEEEFFFF\r\n
        // 0\r\n
        // \r\n
        
        StringBuilder payload = new StringBuilder();
        payload.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        payload.append("Host: ").append(host).append("\r\n");
        payload.append("Transfer-Encoding: chunked\r\n");
        payload.append("Connection: close\r\n");
        payload.append("\r\n");
        payload.append("2;").append(lineTerminator).append("XX\r\n");
        payload.append("10\r\n");
        payload.append("1f\r\n");
        payload.append("AAAABBBBCCCC\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        payload.append("DDDDEEEEFFFF\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        
        return payload.toString().getBytes();
    }
    
    private byte[] buildNormalChunkedRequest(byte[] baseReq) {
        // Build a normal chunked request for comparison
        String host = Utilities.getHeader(baseReq, "Host");
        String path = Utilities.getPathFromRequest(baseReq);
        String method = Utilities.getMethod(baseReq);
        
        StringBuilder payload = new StringBuilder();
        payload.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        payload.append("Host: ").append(host).append("\r\n");
        payload.append("Transfer-Encoding: chunked\r\n");
        payload.append("Connection: close\r\n");
        payload.append("\r\n");
        payload.append("4\r\n");
        payload.append("test\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        
        return payload.toString().getBytes();
    }
    
    private byte[] buildExtTermPayload(byte[] baseReq, String lineTerminator) {
        // Build the EXT.TERM payload based on smugchunks implementation
        String host = Utilities.getHeader(baseReq, "Host");
        String path = Utilities.getPathFromRequest(baseReq);
        String method = Utilities.getMethod(baseReq);
        
        // EXT.TERM payload structure:
        // 2;{line_terminator}XX\r\n
        // 22\r\n
        // c\r\n
        // AAAABBBBCCCC\r\n
        // 0\r\n
        // \r\n
        // DDDDEEEEFFFF\r\n
        // 0\r\n
        // \r\n
        
        StringBuilder payload = new StringBuilder();
        payload.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        payload.append("Host: ").append(host).append("\r\n");
        payload.append("Transfer-Encoding: chunked\r\n");
        payload.append("Connection: close\r\n");
        payload.append("\r\n");
        payload.append("2;").append(lineTerminator).append("XX\r\n");
        payload.append("22\r\n");
        payload.append("c\r\n");
        payload.append("AAAABBBBCCCC\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        payload.append("DDDDEEEEFFFF\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        
        return payload.toString().getBytes();
    }
    
    private byte[] buildTermSpillPayload(byte[] baseReq, String lineTerminator) {
        // Build the TERM.SPILL payload based on smugchunks implementation
        String host = Utilities.getHeader(baseReq, "Host");
        String path = Utilities.getPathFromRequest(baseReq);
        String method = Utilities.getMethod(baseReq);
        
        // TERM.SPILL payload structure:
        // 5\r\n
        // AAAAA{line_terminator}c\r\n
        // 17\r\n
        // AAAABBBB\r\n
        // 0\r\n
        // \r\n
        // CCCCDDDD\r\n
        // 0\r\n
        // \r\n
        
        StringBuilder payload = new StringBuilder();
        payload.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        payload.append("Host: ").append(host).append("\r\n");
        payload.append("Transfer-Encoding: chunked\r\n");
        payload.append("Connection: close\r\n");
        payload.append("\r\n");
        payload.append("5\r\n");
        payload.append("AAAAA").append(lineTerminator).append("c\r\n");
        payload.append("17\r\n");
        payload.append("AAAABBBB\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        payload.append("CCCCDDDD\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        
        return payload.toString().getBytes();
    }
    
    private byte[] buildSpillTermPayload(byte[] baseReq, String lineTerminator) {
        // Build the SPILL.TERM payload based on smugchunks implementation
        String host = Utilities.getHeader(baseReq, "Host");
        String path = Utilities.getPathFromRequest(baseReq);
        String method = Utilities.getMethod(baseReq);
        
        // SPILL.TERM payload structure:
        // 5\r\n
        // AAAAA{line_terminator}1a\r\n
        // 8\r\n
        // AAAABBBB\r\n
        // 0\r\n
        // \r\n
        // CCCCDDDD\r\n
        // 0\r\n
        // \r\n
        
        StringBuilder payload = new StringBuilder();
        payload.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        payload.append("Host: ").append(host).append("\r\n");
        payload.append("Transfer-Encoding: chunked\r\n");
        payload.append("Connection: close\r\n");
        payload.append("\r\n");
        payload.append("5\r\n");
        payload.append("AAAAA").append(lineTerminator).append("1a\r\n");
        payload.append("8\r\n");
        payload.append("AAAABBBB\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        payload.append("CCCCDDDD\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        
        return payload.toString().getBytes();
    }
    
    private byte[] buildOneTwoPayload(byte[] baseReq, String lineTerminator) {
        // Build the ONE.TWO payload based on smugchunks implementation
        String host = Utilities.getHeader(baseReq, "Host");
        String path = Utilities.getPathFromRequest(baseReq);
        String method = Utilities.getMethod(baseReq);
        
        // ONE.TWO payload structure:
        // 2\r\n
        // XX{line_terminator}
        // 12\r\n
        // XX\r\n
        // 19\r\n
        // XXAAAABBBB\r\n
        // 0\r\n
        // \r\n
        // CCCCDDDD\r\n
        // 0\r\n
        // \r\n
        
        StringBuilder payload = new StringBuilder();
        payload.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        payload.append("Host: ").append(host).append("\r\n");
        payload.append("Transfer-Encoding: chunked\r\n");
        payload.append("Connection: close\r\n");
        payload.append("\r\n");
        payload.append("2\r\n");
        payload.append("XX").append(lineTerminator);
        payload.append("12\r\n");
        payload.append("XX\r\n");
        payload.append("19\r\n");
        payload.append("XXAAAABBBB\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        payload.append("CCCCDDDD\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        
        return payload.toString().getBytes();
    }
    
    private byte[] buildTwoOnePayload(byte[] baseReq, String lineTerminator) {
        // Build the TWO.ONE payload based on smugchunks implementation
        String host = Utilities.getHeader(baseReq, "Host");
        String path = Utilities.getPathFromRequest(baseReq);
        String method = Utilities.getMethod(baseReq);
        
        // TWO.ONE payload structure:
        // 2\r\n
        // XX{line_terminator}
        // 10\r\n
        // \r\n
        // AAAABBBBCCCCDD\r\n
        // 0\r\n
        // \r\n
        
        StringBuilder payload = new StringBuilder();
        payload.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        payload.append("Host: ").append(host).append("\r\n");
        payload.append("Transfer-Encoding: chunked\r\n");
        payload.append("Connection: close\r\n");
        payload.append("\r\n");
        payload.append("2\r\n");
        payload.append("XX").append(lineTerminator);
        payload.append("10\r\n");
        payload.append("\r\n");
        payload.append("AAAABBBBCCCCDD\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        
        return payload.toString().getBytes();
    }
    
    private byte[] buildZeroTwoPayload(byte[] baseReq, String lineTerminator) {
        // Build the ZERO.TWO payload based on smugchunks implementation
        String host = Utilities.getHeader(baseReq, "Host");
        String path = Utilities.getPathFromRequest(baseReq);
        String method = Utilities.getMethod(baseReq);
        
        // ZERO.TWO payload structure:
        // 2\r\n
        // XX{line_terminator}
        // 012\r\n
        // XX\r\n
        // 19\r\n
        // XXAAAABBBB\r\n
        // 0\r\n
        // \r\n
        // CCCCDDDD\r\n
        // 0\r\n
        // \r\n
        
        StringBuilder payload = new StringBuilder();
        payload.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        payload.append("Host: ").append(host).append("\r\n");
        payload.append("Transfer-Encoding: chunked\r\n");
        payload.append("Connection: close\r\n");
        payload.append("\r\n");
        payload.append("2\r\n");
        payload.append("XX").append(lineTerminator);
        payload.append("012\r\n");
        payload.append("XX\r\n");
        payload.append("19\r\n");
        payload.append("XXAAAABBBB\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        payload.append("CCCCDDDD\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        
        return payload.toString().getBytes();
    }
    
    private byte[] buildTwoZeroPayload(byte[] baseReq, String lineTerminator) {
        // Build the TWO.ZERO payload based on smugchunks implementation
        String host = Utilities.getHeader(baseReq, "Host");
        String path = Utilities.getPathFromRequest(baseReq);
        String method = Utilities.getMethod(baseReq);
        
        // TWO.ZERO payload structure:
        // 2\r\n
        // xx{line_terminator}
        // 010\r\n
        // \r\n
        // AAAABBBBCCCCDD\r\n
        // 0\r\n
        // \r\n
        
        StringBuilder payload = new StringBuilder();
        payload.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        payload.append("Host: ").append(host).append("\r\n");
        payload.append("Transfer-Encoding: chunked\r\n");
        payload.append("Connection: close\r\n");
        payload.append("\r\n");
        payload.append("2\r\n");
        payload.append("xx").append(lineTerminator);
        payload.append("010\r\n");
        payload.append("\r\n");
        payload.append("AAAABBBBCCCCDD\r\n");
        payload.append("0\r\n");
        payload.append("\r\n");
        
        return payload.toString().getBytes();
    }
    
    private byte[] buildNormalGetRequest(IHttpService service) {
        // Build a normal GET request for connectivity testing
        String host = service.getHost();
        String path = "/";
        
        StringBuilder payload = new StringBuilder();
        payload.append("GET ").append(path).append(" HTTP/1.1\r\n");
        payload.append("Host: ").append(host).append("\r\n");
        payload.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n");
        payload.append("Connection: close\r\n");
        payload.append("\r\n");
        
        return payload.toString().getBytes();
    }
} 