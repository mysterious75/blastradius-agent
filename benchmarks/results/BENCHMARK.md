# BlastRadius Benchmark

Generated: `2026-08-16T10:20:33Z`  
Corpus: `D:\vora\New folder\mycli\blastradius-agent\benchmarks\corpus`  
Verify (sandbox PoC): `True`  
Min confidence: `0.7`  
Elapsed: `0.57s`

| Target | Expected | Reported | Hits | Precision | Recall | F1 | Proven |
|---|---|---|---|---|---|---|---|
| flask-deserialization | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| flask-sqli | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| flask-xss | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| hardcoded-secrets | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 0/1 |
| jinja-ssti | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 0/1 |
| lxml-xxe | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 0/1 |
| requests-ssrf | 1 | 1 | 1 | 1.000 | 1.000 | 1.000 | 1/1 |
| **Total** | **7** | **7** | **7** | **1.000** | **1.000** | **1.000** | **4/7** |
