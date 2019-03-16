# torgetter
**Concurrent HTTP requests over a pool of replaceable Tor proxies**

This creates a pool of N tor clients that run simultaneously, and can be used to make concurrent proxied requests from multiple IP addresses. This can be useful for bypassing IP-based rate limits, or for making large numbers of requests without being noticeable as coming from a single IP.

It abuses the Tor protocol in several ways, namely 

* deliberately using short Tor circuits to increase speed while breaking "anonymity"
* manually selecting exit nodes and ensuring that we are not reusing an exit after we dispose of it
* deliberately limiting to geographically close exit nodes to favor speed over "anonymity"

Dependencies: `requests[socks]`, `selenium`, `pysocks`, `stem`, `tldextract`

Usage: 

    import TorClientPool
    import TorGetter
    urls = ['http://en.wikipedia.org'] * 10
    pool = TorClientPool.TorClientPool(5)
    getter = TorGetter.RequestsTorGetter(urls, pool)
    results = getter.fetchConcurrent(10)
    

