#!/bin/sh
#
# Fail if a derived Defiant prefix collides with a reserved role or with
# another derived prefix, or if a dependency is not on an earlier line.
#
# Backend name "tor" derives GDEFSTOR (GDEFS + TOR) and is refused.
# Backend names "foo-bar" and "foobar" both derive GDEFSFOOBAR (the hyphen
# is dropped) and the second is refused.
# The real libraries.txt must pass. A copy with defiant-storage-tor appended
# must fail. A copy with defiant-storage-foo-bar appended must pass (the
# control for the collision plant), and one with defiant-storage-foobar
# added after it must fail, naming both libraries.
#
# Usage: check-prefix.sh <libraries.txt>

set -eu

FILE="${1:?usage: check-prefix.sh <libraries.txt>}"

if [ ! -f "$FILE" ]; then
  printf 'check-prefix: %s does not exist; this gate is measuring nothing\n' \
    "$FILE" >&2
  exit 1
fi

check_file() {
  python3 - "$1" <<'PY'
import sys

path = sys.argv[1]
reserved_roles = ["CORE", "WEB", "DESK", "TEST", "BRWS", "STOR"]
reserved = set("GDEF" + role for role in reserved_roles)
lines = []
with open(path) as fh:
    for raw in fh:
        text = raw.split("#", 1)[0].strip()
        if not text:
            continue
        parts = text.split()
        if len(parts) < 4:
            sys.stderr.write("check-prefix: short line: %s\n" % text)
            sys.exit(1)
        name, _url, _branch, deps = parts[0], parts[1], parts[2], parts[3]
        lines.append((name, deps))

def alnum_upper(name):
    return "".join(ch.upper() for ch in name if ch.isalnum())

def name_ok(name):
    if not name or not name[0].isalpha():
        return False
    return all(ch.islower() or ch.isdigit() or ch == "-" for ch in name)

def derive(lib):
    fixed = {
        "defiant-core": "GDEFCORE",
        "defiant-web": "GDEFWEB",
        "defiant-desktop": "GDEFDESK",
        "defiant-test": "GDEFTEST",
        "defiant-browser": "GDEFBRWS",
        "defiant-storage": "GDEFSTOR",
    }
    if lib in fixed:
        return fixed[lib], None
    for prefix, kind in (
        ("defiant-storage-", "GDEFS"),
        ("defiant-module-", "GDEFM"),
        ("defiant-web-", "GDEFX"),
    ):
        if lib.startswith(prefix):
            rest = lib[len(prefix):]
            if not name_ok(rest):
                return None, "bad name %s" % rest
            return kind + alnum_upper(rest), rest
    if lib.startswith("defiant-"):
        return None, "unrecognised Defiant library %s" % lib
    return None, None

seen = {}
names = []
fail = 0
for index, (name, deps) in enumerate(lines):
    names.append(name)
    prefix, rest = derive(name)
    if rest is not None and prefix is None:
        sys.stderr.write("check-prefix: %s\n" % rest)
        fail = 1
        continue
    if prefix is not None:
        # First-party roles own their reserved prefix. A derived prefix that
        # lands on one, or on a prefix already taken, is the collision.
        owned = name in (
            "defiant-core", "defiant-web", "defiant-desktop", "defiant-test",
            "defiant-browser", "defiant-storage")
        if prefix in seen or (not owned and prefix in reserved):
            other = seen.get(prefix, "a reserved role")
            sys.stderr.write(
                "check-prefix: %s derives %s, which is %s\n"
                % (name, prefix, other))
            fail = 1
        else:
            seen[prefix] = name
    if deps == "-":
        continue
    for dep in deps.split(","):
        optional = dep.startswith("?")
        if optional:
            dep = dep[1:]
        if dep == "" or optional:
            continue
        if dep not in names[:index]:
            sys.stderr.write(
                "check-prefix: %s depends on %s, which is not on an earlier line\n"
                % (name, dep))
            fail = 1
if fail:
    sys.exit(1)
print("check-prefix: %d libraries, derived prefixes distinct" % len(lines))
PY
}

if ! check_file "$FILE"; then
  exit 1
fi

plant=$(mktemp)
err=$(mktemp)
trap 'rm -f "$plant" "$err"' EXIT
cp "$FILE" "$plant"
printf '%s\n' \
  'defiant-storage-tor https://example.invalid master defiant-storage' \
  >> "$plant"
if check_file "$plant" 2>"$err"; then
  printf 'check-prefix: backend name tor was accepted\n' >&2
  exit 1
fi
if ! grep -q 'defiant-storage-tor derives GDEFSTOR, which is defiant-storage' "$err"; then
  printf 'check-prefix: the tor plant failed, but not for the reserved prefix:\n' >&2
  cat "$err" >&2
  exit 1
fi
printf 'check-prefix: planted backend tor (derived GDEFSTOR) was refused\n'

# Two derived prefixes colliding. The control first: foo-bar alone is a
# legitimate library, so the refusal below can only be the collision.
cp "$FILE" "$plant"
printf '%s\n' \
  'defiant-storage-foo-bar https://example.invalid master defiant-storage' \
  >> "$plant"
if ! check_file "$plant" >/dev/null 2>"$err"; then
  printf 'check-prefix: the control (defiant-storage-foo-bar alone) was refused, so the collision plant below proves nothing:\n' >&2
  cat "$err" >&2
  exit 1
fi
printf '%s\n' \
  'defiant-storage-foobar https://example.invalid master defiant-storage' \
  >> "$plant"
if check_file "$plant" >/dev/null 2>"$err"; then
  printf 'check-prefix: defiant-storage-foo-bar and defiant-storage-foobar both derive GDEFSFOOBAR and were accepted\n' >&2
  exit 1
fi
if ! grep -q 'defiant-storage-foobar derives GDEFSFOOBAR, which is defiant-storage-foo-bar' "$err"; then
  printf 'check-prefix: the collision plant failed, but not for the collision:\n' >&2
  cat "$err" >&2
  exit 1
fi
printf 'check-prefix: planted foo-bar and foobar (both derive GDEFSFOOBAR) were refused\n'
