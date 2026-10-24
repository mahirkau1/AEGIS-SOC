#!/usr/bin/env python3
"""Paket belge referanslarını ve Mermaid bloklarının temel bütünlüğünü inceler.

Mermaid CLI parserı DEĞİLDİR; mmdc mevcutsa ayrıca gerçek render testi yapılmalı.
"""
from pathlib import Path
import re
import csv

ROOT=Path(__file__).resolve().parents[1]
REQUIRED=['README.md','SECURITY.md','CONTRIBUTING.md','docs/MIMARI.md',
          'docs/VERI_AKISI.md','docs/DETECTION_ENGINEERING.md','docs/YAPAY_ZEKA_ANALIZI.md',
          'docs/VERITABANI.md','docs/API_REFERANSI.md','docs/KURULUM_VE_CALISTIRMA.md',
          'docs/GUVENLIK.md','docs/TESTLER.md','docs/KULLANIM_KILAVUZU.md',
          'docs/GELISTIRME_GECMISI.md','docs/PROJE_DURUMU.md','docs/YOL_HARITASI.md']
issues=[]
for name in REQUIRED:
    if not (ROOT/name).exists(): issues.append(f'Eksik dosya: {name}')
for path in ROOT.rglob('*.md'):
    content=path.read_text(encoding='utf-8')
    if content.count('```')%2: issues.append(f'Kapanmayan kod bloğu: {path.relative_to(ROOT)}')
    for link in re.findall(r'\]\(([^)]+)\)',content):
        if link.startswith(('https://','http://','#','mailto:')): continue
        target=(path.parent/link.split('#')[0]).resolve()
        if not target.exists(): issues.append(f'Bozuk bağlantı: {path.relative_to(ROOT)} -> {link}')
    blocks=re.findall(r'```mermaid\s*\n(.*?)\n```',content,re.S)
    for i,b in enumerate(blocks,1):
        if not b.strip().startswith(('flowchart','graph','sequenceDiagram','classDiagram','stateDiagram','erDiagram','gantt')):
            issues.append(f'Mermaid türü şüpheli: {path.name} #{i}')
        if b.count('[')!=b.count(']'):
            issues.append(f'Mermaid köşeli ayraç dengesiz: {path.name} #{i}')
        if b.count('{')!=b.count('}'):
            issues.append(f'Mermaid süslü ayraç dengesiz: {path.name} #{i}')
with (ROOT/'docs/assets/TEST_32_SENARYO_SABLONU.csv').open(encoding='utf-8-sig',newline='') as f:
    n=sum(1 for _ in csv.DictReader(f))
    if n!=32:issues.append(f'32 test şablonunda {n} satır var')
print('Belge bütünlüğü:', 'BAŞARILI' if not issues else 'HATALI')
for issue in issues: print(' -', issue)
raise SystemExit(1 if issues else 0)
