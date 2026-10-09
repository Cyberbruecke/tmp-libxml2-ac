# Seeds

One corpus per sink, as the campaign used them:

| directory | sink | documents |
|---|---|---|
| `c1_b` | C14N1D3, exclusive | 165 |
| `c2_b` | C14N1D3, inclusive | 169 |
| `c3_b` | XPlode | 164 |
| `c5_b` | FlAttr | 164 |
| `c7_b` | Wreckoncile | 171 |

The documents come from libxml2's own regression suite: 96% of each set is
byte-identical to a file under `test/` in the pinned libxml2 revision (SVG
samples, XML specification examples and similar). The most expensive seed
reaches 11,191 sink operations (Wreckoncile), against the 8,000,000 the
operation criterion requires.

The XPlode harness reads an XPath expression on the first line and the document
after it. Every `c3_b` seed uses `//*`.
