# Computer Networks Comprehensive Viva Guide — PhishGuard AI

This document prepares you for technical viva questions on the Computer Networks principles implemented in **PhishGuard AI**.

---

### Q1: What is the Client-Server Architecture in this project?
**Answer:**  
PhishGuard AI implements a classic client-server model over HTTP/HTTPS:
- **Client (Frontend):** A Single Page Application (SPA) built with React and TypeScript running in the client's web browser. It collects user input (target URLs), validates format, and makes asynchronous HTTP requests using the `fetch` API.
- **Server (Backend):** A FastAPI Python web application listening on TCP port 8000. It processes requests, executes the ML model inference, performs socket DNS lookups, updates event history, and returns structured JSON responses.

---

### Q2: How does DNS resolution work and why was it separated from AI inference?
**Answer:**  
- **How DNS works:** Domain Name System (DNS) is an application-layer protocol (typically operating over UDP port 53) that maps human-readable domain names (e.g., `google.com`) to numeric IP addresses (e.g., `142.250.190.46`). In PhishGuard AI, the server executes `socket.getaddrinfo()`, requesting A records (IPv4) and AAAA records (IPv6) with a bounded timeout (3.0s).
- **Why separated:** Security and latency! 
  1. Relying on live DNS queries during ML classification introduces 100ms+ network latency and fails when checking newly minted or offline phishing domains.
  2. Visiting or connecting to unknown suspicious hosts creates Severe Server-Side Request Forgery (SSRF) and drive-by malware risks. Thus, PhishGuard AI inspects lexical features offline and uses DNS strictly as an optional diagnostic tool.

---

### Q3: What is the difference between TCP and UDP in this application?
**Answer:**  
- **TCP (Transmission Control Protocol):** Connection-oriented protocol providing reliable, ordered, and error-checked byte stream delivery via a 3-way handshake (SYN, SYN-ACK, ACK). All REST API communications and HTTP responses in PhishGuard AI run over TCP.
- **UDP (User Datagram Protocol):** Connectionless, lightweight transport protocol without handshake or delivery guarantees. DNS lookups triggered by the backend typically utilize UDP port 53 for rapid resolution.

---

### Q4: How is Request-Response Latency measured?
**Answer:**  
PhishGuard AI implements custom HTTP middleware in FastAPI:
1. When a client request arrives, high-resolution time ($T_0$) is stamped.
2. The endpoint handler executes (extracting features, running XGBoost inference).
3. Right before returning the HTTP response, the finish time ($T_1$) is recorded.
4. Duration $\Delta T = (T_1 - T_0) \times 1000$ ms is calculated, stamped onto the response header (`X-Response-Time-Ms`), and stored in the network engine to calculate running averages and medians.

---

### Q5: How does the Simulated Firewall work?
**Answer:**  
A network firewall filters incoming and outgoing network traffic based on predefined security rules.  
In PhishGuard AI, the firewall operates at the application/domain layer in memory:
- Administrators can define blocking rules for malicious domains.
- When any URL is submitted for inspection, the firewall engine checks whether the hostname matches the blocklist.
- If matched, the traffic is flagged as intercepted, hits counters are incremented, and an audit trail event is logged.  
- *Crucially, it is simulated in software memory so it never damages the host operating system's kernel routing table or packet filter.*

---

### Q6: Can HTTPS alone prove a website is legitimate?
**Answer:**  
**No! Absolutely not.**  
HTTPS encrypts the communication channel between the client and server using TLS (Transport Layer Security), preventing eavesdropping and tampering. However, free SSL certificates (e.g., Let's Encrypt) are easily obtained by phishers. Over 80% of modern phishing websites serve traffic over HTTPS to deceive users into seeing a security padlock.
