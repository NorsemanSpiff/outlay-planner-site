"""Check an OAuth Client ID Metadata Document against the pinned constants.

Usage: python check_client_metadata.py [path]   (default: oauth/client.json)

The expected document, member by member. Changing the document means
changing these constants in the same reviewed diff. Prints one PASS or
FAIL line per check and exits 1 if any check failed. Never raises on a
bad input: every failure is a FAIL line.
"""
import json
import os
import stat
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else "oauth/client.json"
CLIENT_ID = "https://norsemanspiff.github.io/planning-grid-site/oauth/client.json"
CLIENT_NAME = "Planning Grid"
REDIRECT_URIS = ["https://aldonbbgfcjhggiepdaempkffbkgkhhh.chromiumapp.org/"]
GRANT_TYPES = ["authorization_code", "refresh_token"]
RESPONSE_TYPES = ["code"]
MEMBERS = {"client_id", "client_name", "redirect_uris", "grant_types",
           "response_types", "token_endpoint_auth_method"}
MAX_BYTES = 5000  # the stricter reading of "5KB"
failures = []


def check(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        failures.append(label)
    return ok


def finish():
    if failures:
        print(f"\n{len(failures)} check(s) failed")
        sys.exit(1)
    print("\nall checks passed")
    sys.exit(0)


def no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key " + repr(keys))
    return dict(pairs)


def reject_constant(name):
    raise ValueError("non-standard JSON constant " + name)


# The file itself: a regular file, not a link, readable, and small. The
# path is looked up once with lstat, then opened without following links
# and checked again on the open descriptor, so nothing can be swapped in
# between the check and the read.
try:
    st = os.lstat(PATH)
except OSError as exc:
    check(False, f"{PATH} exists and is readable: {exc.strerror or exc}")
    finish()
if not check(not stat.S_ISLNK(st.st_mode), f"{PATH} is not a symbolic link"):
    finish()
if not check(stat.S_ISREG(st.st_mode), f"{PATH} is a regular file"):
    finish()
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
try:
    fd = os.open(PATH, flags)
except OSError as exc:
    check(False, f"{PATH} could be opened: {exc.strerror or exc}")
    finish()
try:
    if not check(stat.S_ISREG(os.fstat(fd).st_mode), f"{PATH} is still a regular file once opened"):
        finish()
    raw = os.read(fd, MAX_BYTES + 1)
except OSError as exc:
    check(False, f"{PATH} could be read: {exc.strerror or exc}")
    finish()
finally:
    os.close(fd)
if len(raw) > MAX_BYTES:
    check(False, f"size is over {MAX_BYTES} bytes (read stopped at {MAX_BYTES + 1})")
    finish()
check(True, f"size {len(raw)} bytes is at most {MAX_BYTES}")
check(not raw.startswith(b"\xef\xbb\xbf"), "style: no byte order mark")
check(b"\r" not in raw, "style: no carriage returns")
check(raw.endswith(b"}\n"), "style: ends with a closing brace and one newline")

doc = {}
try:
    parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates,
                        parse_constant=reject_constant)
    check(isinstance(parsed, dict), "top level is a JSON object")
    if isinstance(parsed, dict):
        doc = parsed
except Exception as exc:
    check(False, f"strict JSON parse: {exc}")

check(set(doc) == MEMBERS, f"exactly the expected members (found {sorted(doc)})")
check(doc.get("client_id") == CLIENT_ID, "client_id is string-equal to the document URL")
check(doc.get("client_name") == CLIENT_NAME, f"client_name is {CLIENT_NAME!r}")
check(doc.get("redirect_uris") == REDIRECT_URIS, "redirect_uris is exactly the pinned extension redirect URL")
check(doc.get("token_endpoint_auth_method") == "none", "token_endpoint_auth_method is none")
check(doc.get("grant_types") == GRANT_TYPES, "grant_types is exactly authorization_code and refresh_token")
check(doc.get("response_types") == RESPONSE_TYPES, "response_types is exactly [code]")

text = raw.decode("utf-8", "replace").lower()
check(all(w not in text for w in ("secret", "jwk", "private", "begin ")),
      "no secret, key or key-material wording anywhere in the body")

finish()
