# Auden public-page check — local prototype

Check what one public page says about one buyer question. No AI model, API key, paid service, telemetry or visibility score. Contains the standalone checker and synthetic tests only.

## Run

Python 3.11 or newer, standard library only. From this directory:

```sh
python3 -m acheck https://example.com/ 'What is this domain for?' --output ./my-review
```

Choose a new output directory. Open `report.html`, or use `report.json` and `report.txt`. The report separates fetched observations, simple word overlap and things not tested. A shared term is not proof that the page answers the question correctly. “Not found in fetched content” never means absent from the entire website.

## Boundaries

- One HTML page, plus robots checks for each destination; no recursive crawl, JS, login, cookies or linked assets.
- Public HTTPS DNS hostname, port 443. Query strings and fragments are rejected, as are credentials, suspicious credential paths, IP literals and non-public DNS answers. These deliberately strict checks can reject legitimate public URLs.
- Every connection resolves and validates all addresses, then connects to a validated numeric IP with the original hostname for TLS verification. Redirects re-enter validation and robots checks.
- Three redirects total, 128 KiB on the wire, 512 KiB decoded per response, 20-second isolated process deadline. Only UTF-8 HTML and identity/gzip/deflate supported.
- Robots failures stop the page fetch. Cross-origin robots redirects and positive pacing policies stop this one-shot checker. Robots results apply only to `AudenPageCheck`, not Google or AI crawlers.
- HTML text extraction cannot evaluate external CSS or JavaScript. Explicitly hidden containers and executable content are excluded. Malformed HTML can be incomplete; the report is not a browser rendering.
- Reports quote short excerpts, not complete pages. Matching term IDs are evidence pointers, not semantic validation.
- URLs/questions may be visible in your local shell history. Use public, non-sensitive inputs only. The URL goes to its destination server; the question stays local. No service receives the question.

## Tests

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q acheck tests
python3 demo.py
```

Tests use synthetic HTML and mocked transport/DNS. `demo.py` generates a synthetic review without networking. The ordinary CLI has also been tested against example.com; that fetched output is outside this prospective release directory.

## License and scope

MIT licensed; see [LICENSE](LICENSE). This repository contains only the standalone Python checker, synthetic tests and demo generator. It does not include research datasets, client records, website deployment files or a ChatGPT integration.

This is a local command-line prototype, not a hosted service or an AI visibility score. Before public hosting, add a separately reviewed deployment architecture, abuse/rate limits and operational monitoring. Do not expose this CLI as an unauthenticated web endpoint.
