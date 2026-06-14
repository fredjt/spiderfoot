# B902 Fix Review Findings

Reviewed commit `de5fdece` (fix(lint): resolve B902 blind except Exception violations) across 188 files with 9 independent review angles.

**15 findings confirmed** (out of 22 deduplicated issues; cap enforced).

---

## 1. sflib.py:851 — `resolveHost()` misses `socket.herror` and `socket.timeout`

**Severity:** Critical — 60+ module callers expect empty list return, not an exception.

**What happened:** `except Exception` was narrowed to `except socket.gaierror`. But `socket.gethostbyname_ex()` can raise three sibling exception types: `socket.gaierror` (address-related), `socket.herror` (host-related), and `socket.timeout`. Only `gaierror` is caught.

**Fix:** `except (socket.gaierror, socket.herror, socket.timeout)`

---

## 2. sflib.py:881 — `resolveReverse()` misses `socket.herror` and `socket.timeout`

**Severity:** Critical — same contract violation as #1, 6 module callers affected.

**What happened:** `except Exception` was narrowed to `except socket.gaierror`. But `socket.gethostbyaddr()` can also raise `socket.herror` and `socket.timeout`.

**Fix:** `except (socket.gaierror, socket.herror, socket.timeout)`

---

## 3. modules/sfp_intelx.py:256 — Dict key access raises `KeyError`, not `IndexError`

**Severity:** High — API responses missing expected keys crash the module.

**What happened:** Try block accesses `rec['bucket']`, `rec['keyvalues'][0]['value']`, `rec['name']`, `rec['systemid']` — all raise `KeyError` on missing keys. Except clause only catches `IndexError`.

**Fix:** `except (IndexError, KeyError)`

---

## 4. modules/sfp_intelx.py:291 — Dict key access raises `KeyError`, not `IndexError`

**Severity:** High — same pattern as #3, different try block.

**What happened:** Try block accesses `rec['selectorvalueh']`, `rec['selectortype']` — raises `KeyError` on missing keys. Except clause only catches `IndexError`.

**Fix:** `except (IndexError, KeyError)`

---

## 5. modules/sfp_tool_dnstwist.py:170 — Subprocess + event handling caught by JSON-only handler

**Severity:** High — try block spans `subprocess.run()`, `SpiderFootEvent()` construction, and `notifyListeners()`, but except only catches `(json.JSONDecodeError, TypeError)`.

**What happened:** `subprocess.run()` raises `FileNotFoundError`/`OSError` when binary not found. `SpiderFootEvent()` can raise `ValueError`. `notifyListeners()` can raise `RuntimeError`. None are caught.

**Fix:** Add `OSError` and `ValueError` to the except tuple, or keep `# noqa: B902`.

---

## 6. modules/sfp_tool_nmap.py:190 — Tuple unpacking raises `ValueError`, not `IndexError`

**Severity:** High — `junk, opsys = line.split(': ')` raises `ValueError` when split produces wrong element count.

**What happened:** Nmap output line without `: ` separator causes `ValueError` during tuple unpacking. Except clause only catches `IndexError`.

**Fix:** `except (IndexError, ValueError)`

---

## 7. modules/sfp_tool_nmap.py:183 — Outer except narrowed to `IndexError` but try has `SpiderFootEvent`/`notifyListeners`

**Severity:** High — same pattern as #5. Outer try block includes `SpiderFootEvent()` and `notifyListeners()` which can raise `ValueError`/`RuntimeError`.

**Fix:** Add `ValueError` to the except tuple, or keep `# noqa: B902`.

---

## 8. modules/sfp_tool_pythonwhois.py:124 — `json.loads()` caught by `OSError` handler

**Severity:** High — the try block contains `jsonmod.loads(content)` which raises `json.JSONDecodeError`, but except only catches `OSError`.

**What happened:** Malformed whois output from the tool produces invalid JSON. `json.JSONDecodeError` propagates uncaught.

**Fix:** `except (OSError, json.JSONDecodeError, TypeError)`

---

## 9. modules/sfp_tool_testsslsh.py:202 — File I/O caught by JSON-only handler

**Severity:** Medium — try block includes `open()` and `f.read()` which raise `OSError`, but except only catches `(json.JSONDecodeError, TypeError)`.

**What happened:** Output file cannot be opened or read (permissions, disk error, missing directory). `OSError` propagates uncaught.

**Fix:** `except (json.JSONDecodeError, TypeError, OSError)`

---

## 10. modules/sfp_tool_cmseek.py:147 — File I/O caught by JSON-only handler

**Severity:** Medium — same pattern as #9. Try block includes `io.open()` and `f.read()` but except only catches `(json.JSONDecodeError, TypeError)`.

**Fix:** `except (json.JSONDecodeError, TypeError, OSError)`

---

## 11. modules/sfp_dnsdumpster.py:76 — `ValueError` + `AttributeError` not caught

**Severity:** Medium — try block includes `k, v = cookie.split('=', 1)` (raises `ValueError` on missing `=`) and `html.find().attrs` (raises `AttributeError` when `find()` returns `None`). Except only catches `IndexError`.

**Fix:** `except (IndexError, ValueError, AttributeError)`

---

## 12. modules/sfp_tool_retirejs.py:170 — Dict access + `shutil.rmtree()` caught by JSON-only handler

**Severity:** Medium — try block includes `item['results']`, `result['vulnerabilities']`, `vuln['identifiers']` (all `KeyError`) and `shutil.rmtree()` (`OSError`/`FileNotFoundError`). Except only catches `(json.JSONDecodeError, TypeError)`.

**Fix:** `except (json.JSONDecodeError, TypeError, KeyError, OSError)`

---

## 13. modules/sfp_cleanbrowsing.py:89,105,120 — `dns.resolver.NoNameservers` not in exception tuple

**Severity:** Medium — all 10 DNS resolver modules use the same tuple `(dns.exception.Timeout, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.name.EmptyLabel)`. Missing `dns.resolver.NoNameservers`, a sibling exception raised when no nameserver is reachable.

**What happened:** All DNS servers unreachable → `NoNameservers` propagates uncaught.

**Fix:** Add `dns.resolver.NoNameservers` to the exception tuple in all 10 DNS modules:
- sfp_adguard_dns.py:77
- sfp_cleanbrowsing.py:89,105,120
- sfp_cloudflaredns.py:82
- sfp_comodo.py
- sfp_dns_for_family.py
- sfp_opendns.py
- sfp_opennic.py
- sfp_quad9.py
- sfp_tldsearch.py
- sfp_yandexdns.py

---

## 14. modules/sfp_hosting.py:78 — Tuple unpacking raises `ValueError`, not `IndexError`

**Severity:** Medium — `[start, end, title, url] = line.split(',')` raises `ValueError` when split produces wrong element count. Except only catches `IndexError`.

**Fix:** `except (IndexError, ValueError)`

---

## 15. modules/sfp_customfeed.py:165 — `KeyError` + `re.error` not caught

**Severity:** Medium — try block accesses `malchecks[check]['regex']` (raises `KeyError`), calls `re.match()` (raises `re.error`), and accesses `data['content']` (raises `KeyError`). Except only catches `IndexError`.

**Fix:** `except (IndexError, KeyError, re.error)`

---

## Notable non-bug findings

### Dead-code `IndexError` in helpers.py (lines 372, 400, 428)

The `except IndexError` on `w.strip().lower().split('/')[0]` is dead code — `str.split()` always returns at least one element, so `[0]` never raises `IndexError`. This means `IOError`/`FileNotFoundError` from `resources.open_text()` would propagate uncaught. However, these are bundled data files with `errors='ignore'` on open, so the risk is very low. Not included in the top-15 due to low severity.

### Missing `TypeError` on several `json.loads()` catches

Several modules use `except json.JSONDecodeError:` without `TypeError` (sfp_snov.py, sfp_webserver.py, sfp_cookie.py, sfp_strangeheaders.py, sfwebui.py:1264, sfp_github.py:229, sfp_maltiverse.py:118). `json.loads(None)` raises `TypeError`. These are lower severity than the 15 above because the `res['content']` key is typically always present on HTTP 200 responses.

### Maintainability: 131 duplicate JSON patterns, 10 duplicate DNS tuples

The `(json.JSONDecodeError, TypeError)` pattern appears 131 times across modules. The DNS exception tuple appears in 10 modules. A shared helper in `sflib.py` or a module base class constant would reduce future maintenance burden. Not a bug — just a note for the next refactor.
