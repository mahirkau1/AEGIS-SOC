#!/usr/bin/env python3
"""AEGIS SOC yerel kod envanteri: salt-okunur, gizli değerleri dışa aktarmaz.

Çıktılar yalnızca dosya yolları (proje köküne göre), hash, fonksiyon/sınıf adları,
route adları, ve import yönleri içerir. Kaynak kod gövdesi, .env, .db, log, token,
request payload, kullanıcı adı veya ortam değişkeni değerleri rapora yazılmaz.
Örnek: python scripts/proje_envanteri.py --root 'C:\\...\\AD-OPNsense-SOC' --output .\\aegis_audit_output
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

IGNORE_DIRS={'.git','.venv','venv','__pycache__','.pytest_cache','node_modules','logs','secrets',
             '.idea','.vscode','.mypy_cache','.ruff_cache','aegis_audit_output','docs'}
IGNORE_SUFFIX={'.db','.sqlite','.sqlite3','.log','.pcap','.pcapng','.evtx','.etl','.key','.pem','.pfx','.p12','.pyc'}
IGNORE_FILENAME={'.env','.env.local','.env.production','.env.dev'}
MAX_BYTES=2_000_000


def ignored(path: Path, root: Path) -> bool:
    p=path.relative_to(root)
    if any(part in IGNORE_DIRS for part in p.parts[:-1]):
        return True
    if any(part.startswith('backup_') or part.startswith('backup-') for part in p.parts[:-1]):
        return True
    name=path.name.lower()
    if name in IGNORE_FILENAME or name.startswith('.env.') or name.endswith(tuple(IGNORE_SUFFIX)):
        return True
    if 'backup' in name or '_before_' in name or name.startswith('main_before'):
        return True
    return False


def file_hash(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        while block:=f.read(65536): h.update(block)
    return h.hexdigest()


def route_info(node: ast.AST, rel: str):
    routes=[]
    for dec in getattr(node,'decorator_list',[]):
        if not isinstance(dec,ast.Call) or not isinstance(dec.func,ast.Attribute): continue
        method=dec.func.attr.upper()
        if method not in {'GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'}: continue
        first=dec.args[0] if dec.args else None
        # Only literal route strings are included; no dynamic secrets or expressions.
        path=first.value if isinstance(first,ast.Constant) and isinstance(first.value,str) else '<dinamik>'
        routes.append({'method':method,'path':path,'handler':node.name,'module':rel,'line':node.lineno})
    return routes


def py_info(p: Path, rel: str) -> dict:
    result={'file':rel,'routes':[],'functions':[],'classes':[],'imports':[],'parse_status':'OK'}
    try:
        tree=ast.parse(p.read_text(encoding='utf-8-sig',errors='replace'))
    except (SyntaxError,UnicodeError,ValueError) as exc:
        result['parse_status']=type(exc).__name__
        return result
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            result['functions'].append(node.name)
            result['routes'].extend(route_info(node,rel))
        elif isinstance(node,ast.ClassDef): result['classes'].append(node.name)
        elif isinstance(node,ast.Import): result['imports'] += [n.name for n in node.names if n.name.startswith('app')]
        elif isinstance(node,ast.ImportFrom) and node.module and node.module.startswith('app'):
            result['imports'].append(node.module)
    return result


def main():
    ap=argparse.ArgumentParser(description='AEGIS SOC proje envanteri (kaynak kodu değiştirmez).')
    ap.add_argument('--root',required=True,type=Path,help='Gerçek proje kök dizini')
    ap.add_argument('--output',type=Path,default=Path('aegis_audit_output'),help='Rapor klasörü')
    args=ap.parse_args()
    root=args.root.resolve()
    if not root.is_dir() or not (root/'app').is_dir():
        ap.error('Geçerli repo kökü ve app/ klasörü bulunamadı.')
    out=args.output.resolve()
    if root==out or out==root/'app' or root/'app' in out.parents:
        ap.error('Rapor klasörünü uygulama kaynak kodu altında seçmeyin.')
    try:
        out.mkdir(parents=True,exist_ok=True)
    except OSError as e: ap.error(str(e))

    files=[]; py=[]; routes=[]; skipped=[]
    for p in sorted(root.rglob('*')):
        if not p.is_file() or ignored(p,root): continue
        rel=p.relative_to(root).as_posix()
        try:
            size=p.stat().st_size
            if size>MAX_BYTES:
                skipped.append({'file':rel,'reason':'boyut_siniri'})
                continue
            if p.suffix.lower() not in {'.py','.html','.css','.js','.toml','.txt','.md','.ps1','.bat','.yml','.yaml'}:
                continue
            meta={'path':rel,'bytes':size,'sha256':file_hash(p)}
            files.append(meta)
            if p.suffix.lower()=='.py':
                pinfo=py_info(p,rel)
                py.append(pinfo);routes.extend(pinfo['routes'])
        except (OSError,PermissionError):
            skipped.append({'file':rel,'reason':'okunamadi'})

    report={'generated_utc':datetime.now(timezone.utc).isoformat(),
            'note':'Gizli değerler, ham kod ve kişisel veriler rapora alınmaz. Yalnızca statik dosya metaverisi.',
            'file_count':len(files),'python_count':len(py),'route_count':len(routes),
            'files':files,'python_modules':py,'routes':routes,'skipped':skipped}
    (out/'envanter.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    md=['# AEGIS SOC Yerel Kod Envanteri','',
        'Bu rapor yalnızca statik dosya adları, özetler ve AST kod imzalarını içerir. Servis canlı testi değildir.','',
        f"- Dosya: **{len(files)}**",f"- Python: **{len(py)}**",f"- Route: **{len(routes)}**",'',
        '## API rotaları','', '| Metot | Yol | Fonksiyon | Kaynak |', '|---|---|---|---|']
    for r in routes:
        md.append(f"| {r['method']} | `{r['path'].replace('|','/')}` | `{r['handler']}` | `{r['module']}` |")
    md+=['','## Modül imzaları','']
    for m in py:
        md.append(f"### `{m['file']}`")
        md.append(f"- Parse durumu: `{m['parse_status']}`")
        md.append('- Fonksiyonlar: '+(', '.join(f'`{n}`' for n in m['functions']) or 'Yok'))
        md.append('- Sınıflar: '+(', '.join(f'`{n}`' for n in m['classes']) or 'Yok'))
        md.append('- App importları: '+(', '.join(f'`{n}`' for n in sorted(set(m['imports']))) or 'Yok'))
        md.append('')
    md+=['## İnceleme uyarısı','','Dosya varlığı çalışır entegrasyon anlamına gelmez. Unit, E2E ve canlı test zorunludur.']
    (out/'envanter.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
    print(f'Raporlar oluşturuldu: {out / "envanter.md"} ve {out / "envanter.json"}')
    print('Uygulama kaynak koduna değişiklik yapılmadı.')

if __name__=='__main__':
    main()
