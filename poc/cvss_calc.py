# -*- coding: utf-8 -*-
"""CVSS v3.1 base-score recomputation for AS-2026-006 (FIRST spec formula).

python poc/cvss_calc.py
"""
import math


def roundup(x):
    return math.ceil(round(x, 5) * 10) / 10.0


AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
      "C": {"N": 0.85, "L": 0.68, "H": 0.50}}


def base(av, ac, pr, ui, s, c, i, a):
    expl = 8.22 * AV[av] * AC[ac] * PR[s][pr] * UI[ui]
    iss = 1 - (1 - CIA[c]) * (1 - CIA[i]) * (1 - CIA[a])
    if iss <= 0:
        return 0.0
    if s == "U":
        return roundup(min(6.42 * iss + expl, 10.0))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    return roundup(min(1.08 * (impact + expl), 10.0))


def band(x):
    return ("None" if x == 0 else "Low" if x < 4.0 else
            "Medium" if x < 7.0 else "High" if x < 9.0 else "Critical")


vectors = [
    ("only path/params controllable (base_url pinned to the official registry)",
     "N", "L", "L", "N", "U", "L", "L", "L"),
    ("RECOMMENDED: base_url controllable + Bearer token exfiltrated",
     "N", "L", "L", "N", "C", "H", "L", "L"),
    ("upper bound, unauthenticated caller (PR:N)",
     "N", "L", "N", "N", "C", "H", "L", "L"),
]

print("%-78s %-46s %6s  %s" % ("scenario", "vector", "score", "severity"))
print("-" * 140)
for name, *m in vectors:
    sc = base(*m)
    vec = "CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s" % tuple(m)
    print("%-78s %-46s %6.1f  %s" % (name[:78], vec, sc, band(sc)))

print()
print("Recommended rating for submission: 9.1 Critical")
print("  Rationale: SSRF and the exfiltration of the configured Registry token are")
print("  both measured effects (the receiving host logged `Authorization: Bearer`).")
print("  C:H because the deployment credential is disclosed in full; S:C because the")
print("  request leaves the component's scope and reaches an arbitrary host;")
print("  I:L/A:L because the attacker-chosen registry answers the hub browse/detail")
print("  API and can steer install templates, while a slow or dead mirror degrades")
print("  the hub. PR:L: reaching the hub routes needs a service account, not an admin.")
print("Use 6.3 Medium only if the deployment pins base_url to the official registry.")
