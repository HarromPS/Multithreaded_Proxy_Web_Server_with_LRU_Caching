# 🔐 Multithreaded Secure Proxy Web Server with LRU Caching

A system-level C++ project that implements a multithreaded proxy server capable of handling both HTTP and HTTPS traffic (via CONNECT method), equipped with OpenSSL-based MITM functionality, request logging, caching, and thread-safe concurrency control.

Credit-
Siddharth Sengupta : https://github.com/sid-sg/Multithreaded-Secure-FTP-Client-Server/tree/main
Lovepreet Singh : https://github.com/AlphaDecodeX/MultiThreadedProxyServerClient

---
Youtube Video Presentation
[![Multithreaded Secure Proxy Web Server with LRU Caching](https://github.com/user-attachments/assets/60c3f5a1-790c-48ed-ac90-cf72428d4e37)](https://youtu.be/7TCtKU5FkFc)

Flow Diagram
![Multithreaded Proxy Web Server with LRU Caching](https://github.com/user-attachments/assets/5400c144-796b-4d90-89c3-e0a65957a5b4)

## 🚀 Features

- 🔄 **Handles HTTP and HTTPS (via CONNECT)**
- 🧵 **Multithreaded architecture** using `pthread`
- 🔐 **OpenSSL-based SSL/TLS handling** for MITM inspection
- 🧠 **LRU Cache** (custom-built using HashMap + Doubly Linked List)
- 🧹 **Anonymity by stripping headers** (User-Agent, Referer, etc.)
- 🧾 **Thread-safe request logging** with timestamps and IPs
- 🛡️ **Mutexes & Semaphores** to ensure safe access to shared data

---

## ⚙️ Technologies Used

- **C++**
- **Linux System Calls**
- **Socket Programming**
- **POSIX Threads (`pthread`)**
- **OpenSSL**
- **Mutex & Semaphores**
- **LRU Cache (manual implementation)**

---

## 🛠️ Setup Instructions

```bash
# Clone the repository
git clone https://github.com/HarromPS/Multithreaded_Proxy_Web_Server_with_LRU_Caching/
cd proxy-server

# Install OpenSSL if not present
sudo apt install libssl-dev

# generate keys 
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Build the project
cd https_openssl / cd OpenSSL_TLS
cd server 
make

# run server
./server <PORT>

cd client
make

# run client 
./client localhost <PORT>
````

---

## 📌 How It Works

1. Accepts incoming client connections on specified port
2. Parses HTTP methods (`GET`, `POST`, `CONNECT`)
3. For HTTPS, creates a TCP tunnel and uses OpenSSL for SSL termination
4. Uses mutex/semaphores to control access to cache and logs
5. Logs each request with client IP, method, URL, timestamp, and cache status

---

## 📊 Sample Log Output

```
[2025-05-01 11:32:18 AM] | IP: 127.0.0.1 | Method: GET | URL: www.google.com | Cache Status: HIT
[2025-05-01 11:32:25 AM] | IP: 127.0.0.1 | Method: CONNECT | URL: www.facebook.com | SSL: Handshake Success
```

---

## 🔮 Future Enhancements

* [ ] Support for request body parsing (e.g., full `POST`)
* [ ] Gzip/Deflate compression handling
* [ ] Rate limiting based on client IP
* [ ] Machine Learning based content classification
* [ ] Web dashboard for real-time monitoring

---
