import xml.etree.ElementTree as ET
from collections import defaultdict

JACOCO_XML = "../../log4j-fuzz/jacoco-report-new/jacoco.xml"
TARGET_PACKAGE = "org/apache/logging/log4j/core"

def extract_uncovered_methods_by_submodule(xml_path, target_package):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    submodules = defaultdict(list)

    for package in root.findall("package"):
        pkg_name = package.get("name", "")
        if not pkg_name.startswith(target_package):
            continue

        for clazz in package.findall("class"):
            cls_name = clazz.get("name", "")
            source_file = clazz.get("sourcefilename", "")
            full_class_path = f"{pkg_name}.{cls_name}"
            submodule_name = pkg_name  # <- Group by submodule

            for method in clazz.findall("method"):
                method_name = method.get("name", "")
                descriptor = method.get("desc", "")
                line = method.get("line", "")

                instr_covered = instr_missed = line_total = 0
                branch_missed = 0

                for counter in method.findall("counter"):
                    if counter.get("type") == "INSTRUCTION":
                        instr_covered = int(counter.get("covered", "0"))
                        instr_missed = int(counter.get("missed", "0"))
                    elif counter.get("type") == "LINE":
                        line_total = int(counter.get("missed", "0")) + int(counter.get("covered", "0"))
                    elif counter.get("type") == "BRANCH":
                        branch_missed = int(counter.get("missed", "0"))

                if instr_covered == 0 and instr_missed > 0:
                    score = 3 * branch_missed + 2 * instr_missed + line_total
                    submodules[submodule_name].append({
                        "class": full_class_path,
                        "method": method_name,
                        "desc": descriptor,
                        "line": line,
                        "missed_instr": instr_missed,
                        "missed_branches": branch_missed,
                        "lines_total": line_total,
                        "score": score
                    })

    return submodules

def rank_submodules(submodules):
    ranking = []
    for submodule, methods in submodules.items():
        total_score = sum(m["score"] for m in methods)
        top_method_score = max(m["score"] for m in methods)
        ranking.append({
            "submodule": submodule,
            "methods": sorted(methods, key=lambda x: x["score"], reverse=True),
            "total_score": total_score,
            "top_method_score": top_method_score
        })

    return sorted(ranking, key=lambda r: r["total_score"], reverse=True)

# Main: output top 5 submodules
OUTPUT_FILE = "uncovered_report.txt"

if __name__ == "__main__":
    grouped = extract_uncovered_methods_by_submodule(JACOCO_XML, TARGET_PACKAGE)
    ranked = rank_submodules(grouped)

    with open(OUTPUT_FILE, "w") as f:
        f.write("\n=== Top 5 Uncovered Modules ===\n")
        for entry in ranked[:5]:
            f.write(f"\nSubmodule: {entry['submodule']}\n")
            f.write(f"  Total Score: {entry['total_score']} | Top Method Score: {entry['top_method_score']}\n")
            for m in entry["methods"][:3]:  # Show top 3 methods per submodule
                f.write(f"    → {m['class']}::{m['method']} (line {m['line']})\n")
                f.write(f"      Missed: {m['missed_instr']} | Branches: {m['missed_branches']} | Lines: {m['lines_total']} | Score: {m['score']}\n")

    print(f"\n Report written to {OUTPUT_FILE}")
