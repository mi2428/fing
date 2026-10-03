"""Exercise the real release shell with fail-closed command stubs, never Make."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / "Makefile").read_text()
script = source.split("define RELEASE_SCRIPT\n", 1)[1].split("\nendef\n", 1)[0].replace("$$", "$")
stubs = r'''
record() { printf '%s\n' "$*" >> "$EVENTS"; }
git() {
  record "git $*"
  case "$*" in
    'rev-parse --show-toplevel') printf '%s\n' "$SANDBOX" ;;
    '-C . rev-parse --is-inside-work-tree') return 0 ;;
    '-C . status --porcelain') [[ "$DIRTY" == 0 ]] || printf ' M synthetic\n' ;;
    '-C . status --short') return 0 ;;
    'ls-remote --tags origin refs/tags/v0.0.0')
      [[ "$REMOTE_TAG" == 0 ]] || printf '%s\trefs/tags/v0.0.0\n' "$RELEASE_OID" ;;
    'rev-parse -q --verify refs/tags/v0.0.0') [[ "$LOCAL_TAG" == 1 ]] ;;
    'rev-parse refs/tags/v0.0.0'|'rev-list -n 1 v0.0.0'|'rev-list -n 1 refs/tags/v0.0.0')
      printf '%s\n' "$RELEASE_OID" ;;
    'rev-parse HEAD'|'rev-list -n 1 HEAD') printf 'synthetic-head\n' ;;
    'show HEAD:Cargo.toml'|'show refs/tags/v0.0.0:Cargo.toml')
      printf 'name = "fing"\nversion = "%s"\n' "$VERSION" ;;
    'fetch origin refs/tags/v0.0.0:refs/tags/v0.0.0') LOCAL_TAG=1 ;;
    'tag v0.0.0') LOCAL_TAG=1 ;;
    'tag -d v0.0.0') LOCAL_TAG=0 ;;
    'push origin refs/tags/v0.0.0') return 0 ;;
    *) printf 'unexpected git command\n' >&2; exit 97 ;;
  esac
}
gh() {
  record "gh $*"
  case "$*" in
    'release view v0.0.0 --repo example/project') [[ "$EXISTING_RELEASE" == 1 ]] ;;
    'release create '*|'release upload '*) return 0 ;;
    *) printf 'unexpected gh command\n' >&2; exit 97 ;;
  esac
}
mock_make() {
  record "make $*"
  case "$*" in
    check) [[ "$GATE_FAIL" == 0 ]] ;;
    'dist TAG=v0.0.0 OS=darwin,linux ARCH=amd64,arm64') return 0 ;;
    *) printf 'unexpected make command\n' >&2; exit 97 ;;
  esac
}
# Only these read-only text filters can reach an external command.
sed() { /usr/bin/sed "$@"; }
head() { /usr/bin/head "$@"; }
shasum() { printf 'unexpected checksum call\n' >&2; exit 97; }
'''

with tempfile.TemporaryDirectory(prefix="fing-release-gate-", dir=os.environ.get("TMPDIR")) as directory:
    sandbox = Path(directory)
    (sandbox / "assets").mkdir()
    (sandbox / "assets" / "synthetic-artifact").write_text("synthetic artifact\n")
    events = sandbox / "events"
    env = {
        "PATH": str(sandbox / "no-executables"), "SANDBOX": str(sandbox), "EVENTS": str(events),
        "TMPDIR": str(sandbox), "APP": "fing", "TAG": "v0.0.0", "GIT_REMOTE": "origin",
        "GH_REPO": "example/project", "HOMEBREW_TAP": "0", "DISTDIR": "assets",
        "OS": "darwin,linux", "ARCH": "amd64,arm64", "RELEASE_MAKE": "mock_make",
        "LOCAL_TAG": "0", "REMOTE_TAG": "0", "RELEASE_OID": "synthetic-head",
        "GATE_FAIL": "0", "VERSION": "0.0.0", "DIRTY": "0", "EXISTING_RELEASE": "0",
    }
    cases = [
        ({"GATE_FAIL": "1"}, False),
        ({"LOCAL_TAG": "1", "GATE_FAIL": "1"}, False),
        ({"REMOTE_TAG": "1", "GATE_FAIL": "1"}, False),
        ({"LOCAL_TAG": "1", "RELEASE_OID": "synthetic-other"}, False),
        ({"VERSION": "0.0.1"}, False),
        ({"DIRTY": "1"}, False),
        ({}, True),
        ({"LOCAL_TAG": "1", "EXISTING_RELEASE": "1"}, True),
        ({"REMOTE_TAG": "1"}, True),
    ]
    for overrides, success in cases:
        events.write_text("")
        result = subprocess.run(["/bin/bash", "-c", stubs + script], cwd=sandbox,
                                env={**env, **overrides}, capture_output=True, text=True)
        commands = events.read_text().splitlines()
        assert (result.returncode == 0) == success, (overrides, result.stderr)
        publications = [c for c in commands if c.startswith(("git tag ", "git push ", "gh release create ", "gh release upload "))]
        if not success:
            assert not publications, publications
            assert not any(c.startswith("make dist ") for c in commands), commands
        else:
            assert "make check" in commands, commands
            gate = commands.index("make check")
            dist = next(i for i, c in enumerate(commands) if c.startswith("make dist "))
            push = commands.index("git push origin refs/tags/v0.0.0")
            publish = next(i for i, c in enumerate(commands) if c.startswith(("gh release create ", "gh release upload ")))
            assert gate < dist < push < publish, commands
            if "git tag v0.0.0" in commands:
                assert gate < commands.index("git tag v0.0.0") < dist, commands
print("Release gate regression OK (9 synthetic cases; real git/gh/Make unavailable)")
