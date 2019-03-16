# torgetter
**Concurrent HTTP requests over a pool of replaceable Tor proxies**

Dependencies: `requests[socks]`, `selenium`, `pysocks`, `stem`, `tldextract`

Usage: 

    import TorClientPool
    import TorGetter
    urls = ['http://en.wikipedia.org'] * 10
    pool = TorClientPool.TorClientPool(5)
    getter = TorGetter.RequestsTorGetter(urls, pool)
    results = getter.fetchConcurrent(10)
    
    
