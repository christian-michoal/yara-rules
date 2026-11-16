"""Compile every YARA rule file and check required metadata.

Exits non-zero if any file fails to compile on its own, if the full set
fails to compile together (for example a rule name collision), or if a
public rule is missing a required meta field.
"""
import pathlib
import re
import sys

import yara

ROOT = pathlib.Path(__file__).resolve().parent.parent / "rules"
REQUIRED_META = {"description", "author", "date", "reference", "platform", "confidence"}
RULE_RE = re.compile(r"^\s*((?:private|global)\s+)*rule\s+(\w+)", re.M)


def main() -> int:
    files = sorted(ROOT.rglob("*.yar")) + sorted(ROOT.rglob("*.yara"))
    if not files:
        print("No rule files found")
        return 1

    errors = []
    for path in files:
        rel = path.relative_to(ROOT.parent)
        try:
            compiled = yara.compile(filepath=str(path))
        except yara.Error as exc:
            errors.append(f"{rel}: {exc}")
            continue

        private = {
            m.group(2)
            for m in RULE_RE.finditer(path.read_text(encoding="utf-8"))
            if m.group(1) and "private" in m.group(1)
        }
        for rule in compiled:
            if rule.identifier in private:
                continue
            missing = REQUIRED_META - set(rule.meta)
            if missing:
                errors.append(f"{rel}: rule {rule.identifier} is missing meta {sorted(missing)}")
        print(f"ok  {rel}")

    try:
        yara.compile(filepaths={str(i): str(p) for i, p in enumerate(files)})
    except yara.Error as exc:
        errors.append(f"all rules together: {exc}")

    for err in errors:
        print(f"FAIL {err}")
    print(f"{len(files)} file(s), {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
