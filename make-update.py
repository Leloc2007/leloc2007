#!/usr/bin/env python3
"""Tạo update.json cho thư mục KidGuard (chạy mỗi khi ra bản mới)."""
import hashlib, json, re, sys, pathlib
root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'KidGuard')
files = ['controller/controller.ps1', 'controller/dashboard.html', 'agent/agent.ps1', 'agent/notify.ps1', 'agent/setup.ps1', 'agent/uninstall.ps1']
ver = re.search(r"^\$Version = '([\d.]+)'", (root / 'controller/controller.ps1').read_text('utf-8-sig'), re.M).group(1)
assert f"$Version = '{ver}'" in (root / 'agent/agent.ps1').read_text('utf-8-sig'), 'agent và controller khác phiên bản'
man = {'version': ver, 'files': [{'path': f, 'sha256': hashlib.sha256((root / f).read_bytes()).hexdigest()} for f in files]}
(root / 'update.json').write_text(json.dumps(man, indent=2) + '\n')
print('update.json ->', ver)
