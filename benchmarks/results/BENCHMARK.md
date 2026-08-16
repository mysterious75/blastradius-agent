# BlastRadius Benchmark

Generated: `2026-08-16T11:14:34Z`  
Corpus: `D:\vora\New folder\mycli\blastradius-agent\benchmarks\corpus`  
Verify (sandbox PoC): `True`  
Min confidence: `0.7`  
Elapsed: `0.75s`

| Target | Expected | Reported | Hits | Precision | Recall | F1 | Proven |
|---|---|---|---|---|---|---|---|
| flask-cmd-injection | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| flask-crlf | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| flask-deserialization | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| flask-sqli | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| flask-traversal | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| flask-xss | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| hardcoded-secrets | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 0/1 |
| jinja-ssti | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 0/1 |
| lxml-xxe | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 0/1 |
| requests-ssrf | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| **Total** | **10** | **10** | **10** | **1.000** | **1.000** | **1.000** | **7/10** |
