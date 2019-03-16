# torgetter
**Concurrent HTTP requests over a pool of replaceable Tor proxies**

This creates a pool of N tor clients that run simultaneously, and can be used to make concurrent proxied requests from multiple IP addresses. This can be useful for bypassing IP-based rate limits, or for making large numbers of requests without being noticeable as coming from a single IP. Because the connections are over the Tor network, it is relatively slow, but if you aren't in a huge rush and need to make a large number of requests that appear to be coming from hundreds of different IP addresses, this might work for you ...

It abuses the Tor protocol in several ways, namely:

* deliberately using short Tor circuits to increase speed while breaking "anonymity"
* manually selecting exit nodes and ensuring that we are not reusing an exit after we dispose of it
* deliberately limiting to geographically close exit nodes to favor speed over "anonymity"

The Tor network has over 2000 exit nodes, so this gives you quite a large pool of proxy IPs to work with.

Obviously, the decision to use this software would be frowned upon by many in the Tor community and would be seen as "not what the network was intended for". So I'm releasing this for educational purposes only, and want people to be aware that you're probably going to get angry faces from Tor developers if you ask for support modifying the code here ;)

Dependencies: `requests[socks]`, `selenium`, `pysocks`, `stem`, `tldextract`

Usage example: 

    import TorClientPool
    import TorGetter
    urls = ['http://en.wikipedia.org'] * 10
    pool = TorClientPool.TorClientPool(5)
    getter = TorGetter.RequestsTorGetter(urls, pool)
    results = getter.fetchConcurrent(10)
    

