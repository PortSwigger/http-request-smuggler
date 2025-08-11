## Overview

This document provides a categorized breakdown of the features, gadgets, and smuggling techniques implemented in the HTTP Request Smuggler Burp Suite extension, based on an in-depth review of the source code and official documentation.

---

## Core Features

| **Category** | **Feature** | **Summary & how it works** |
|---|---|---|
| **Detection & scanning** | **Parser‑discrepancy detection** | Uses a root‑cause approach to identify front‑end vs. back‑end parsing differences by crafting mismatched requests and comparing responses. |
| | **Many permutation techniques** | Applies numerous mutation “gadgets” to request lines, headers, and metadata to trigger desynchronisation. |
| | **HTTP/1.1 CL.TE & TE.CL desync detection** | Detects classic smuggling types by mismatching `Content‑Length` and `Transfer‑Encoding`. |
| | **HTTP/2 smuggling** | Supports HTTP/2 desync, tunnelling, and pseudo‑header tricks during downgrade to HTTP/1.1. |
| | **Client‑side desync detection** | Leverages browser‑powered secondary requests to detect injected response bodies. |
| | **Header smuggling/removal detection** | Tests for injection or removal of hop‑by‑hop headers across intermediaries. |
| | **Connection state & pause‑based attacks** | Manipulates keep‑alive and packet timing to bypass inspection. |
| **Exploitation & automation** | **Turbo Intruder integration** | Auto‑generates Turbo Intruder scripts for confirmed desync vectors. |
| | **Report and practice support** | Integrates with Burp Scanner and links to labs for training. |
| **False‑positive reduction** | **Multiple validation techniques** | Replays and compares requests to confirm genuine vulnerabilities. |

---

## Smuggling Techniques

| **Technique** | **Script** | **Summary** |
|---|---|---|
| **CL.TE smuggling** | `resources/CL-TE.py` | Sends a prefix containing an extra request inside a body with mismatched `Content‑Length` and `Transfer‑Encoding`. |
| **TE.CL smuggling** | `resources/TE-CL.py` | Wraps a smuggled request in chunked encoding with a `Content‑Length`. |
| **HTTP/2 smuggling (TE)** | `resources/H2-TE.py` | Appends a malicious prefix to a victim request in HTTP/2, triggering desync on downgrade. |
| **HTTP/2 tunnelling** | `resources/H2-TUNNEL.py` | Embeds a full nested HTTP/1.1 request inside an HTTP/2 request. |

---

## Gadget Categories

### Whitespace & spacing
`spacefix1`, `spacefix1:3`, `spacefix1:10`, `spacefix1:12`, `spacefix1:27`, `nbsp`, `tabwrap`, `unipace` - modify spacing around headers and colons, including Unicode spaces.

### Header name prefix/suffix
`prefix1:*`, `suffix1:*`, `nameprefix*`, `namesuffix*` - prepend/append characters to header names.

### Content‑Length manipulations
`CL-plus`, `CL-minus`, `CL-dec`, `CL-pad`, `CL-commaPrefix`, `CL-commaSuffix`, `CL-error`, `CL-expect`, `CL-expect:obs` - alter numeric values, add punctuation, or hide inside other headers.

### Transfer‑Encoding manipulations
`accentTE`, `accentCH`, `qencode`, `quoted` - obfuscate the `Transfer‑Encoding` header.

### HTTP verb & protocol
`convert GET to POST`, `http1.0` - change method or protocol version.

### Hop‑by‑hop header gadgets
`connection`, `options`, `doublewrapped`, `bodysplit` - tamper with headers that affect proxy behaviour.

### Case & encoding gadgets
`multiCase`, `UPPERCASE`, `accentTE` - change casing or character encoding.

### Origin and query gadgets (cache busters)
Random path/query params, `Referer`/`Via` headers - force separate cache entries.

### Line‑break & wrapping
`linewrapped1`, `doublewrapped`, `badsetupCR`, `badsetupLF`, `0dspam` - inject extra CRLF or unusual line breaks.

### H2 downgrade gadgets
`h2colon`, `h2scheme`, `h2space`, `h2path`, `h2method`, `h2prefix` - manipulate HTTP/2 pseudo‑headers and spacing.
