# Accelerating Web Application

The goal is to help applications following the architecture shown below.

```
[Client] <- (1) -> [Web Server] <- (2) -> [Bussiness Logic (3)] <-+--> [Database (4)]
                                                                  \
                                                                   +-> [Key Value Store (5)]

(1) HTTP/1.1, HTTP/2, HTTP/3 + HTTPs
(2) WSGI, FastCGI, HTTP/1.1
(3) JSON  (Python, PHP, Go, ...)
(4) Postgres
(5) Memcached
```
