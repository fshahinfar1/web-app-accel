# Web Server Accelerator

My attempt to accelerate a web server using eBPF.

The accelerator logic is written for `BPF_GEN`

# Plan

I want to support following actions (check list indicates what I have implemented)

1. [ ] A Parser
    * [ ] HTTP/1.1
    * [ ] HTTP/2
2. [ ] TLS termination
3. [ ] Header modifications
    * [ ] URL rewrite
    * [ ] Add Header
    * [ ] Update Header
4. [ ] Proxy Pass
5. [ ] Response caching
6. [ ] Serving files

