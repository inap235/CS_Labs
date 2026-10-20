"""Console version of Laboratory Work No. 4: every value can be typed or generated at random."""

import sys

from des import table_rows
from tasks import TASKS, TASKS_BY_NUMBER


def print_table(name):
    rows = table_rows(name)
    width = max(len(str(v)) for row in rows for v in row)
    print(f"\n  {name}:")
    for r, row in enumerate(rows):
        prefix = f"  row {r}: " if name.startswith("S") and name != "Shifts" else "    "
        print(prefix + " ".join(f"{v:>{width}}" for v in row))


def print_rows(rows):
    cols = list(rows[0])
    widths = {c: max(len(str(c)), *(len(str(r[c])) for r in rows)) for c in cols}
    print("    " + " | ".join(f"{c:<{widths[c]}}" for c in cols))
    print("    " + "-+-".join("-" * widths[c] for c in cols))
    for r in rows:
        print("    " + " | ".join(f"{str(r[c]):<{widths[c]}}" for c in cols))


def ask_inputs(task):
    raw = {}
    for fld in task.fields:
        while True:
            value = input(f"{fld.label}\n  [Enter = example value, r = random]: ")
            if value == "":
                value = fld.default
            elif value.strip().lower() == "r":
                value = fld.random()
            try:
                fld.parse(value)
            except ValueError as err:
                print(f"  Error: {err}\n")
                continue
            print(f"  -> {value if len(value) < 80 else value[:77] + '...'}")
            raw[fld.name] = value
            break
    return raw


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    print("DES - Laboratory Work No. 4 (task number = n mod 11)")
    for t in TASKS:
        print(f"  {t.number:<5} {t.title}")
    while True:
        choice = input("\nTask number (e.g. 2.6) or x to exit: ").strip()
        if choice.lower() == "x":
            break
        task = TASKS_BY_NUMBER.get(choice) or TASKS_BY_NUMBER.get(choice.capitalize())
        if not task:
            print("  Error: unknown task number.")
            continue
        print(f"\nTask {task.number}. {task.title}")
        raw = ask_inputs(task)
        try:
            steps = task.solve(**{f.name: f.parse(raw[f.name]) for f in task.fields})
        except ValueError as err:
            print(f"  Error: {err}")
            continue
        print("\nTables used:")
        for name in task.tables:
            print_table(name)
        print("\nSteps:")
        for n, step in enumerate(steps, start=1):
            print(f"\n{n}. {step.label}")
            if step.value:
                for line in step.value.splitlines():
                    print(f"    {line}")
            if step.rows:
                print_rows(step.rows)


if __name__ == "__main__":
    main()
