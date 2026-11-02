from collections import defaultdict
from datetime import datetime
from app.parser import normalize
from app.event_time import occurred_at


# AEGIS-RISK-ENGINE-V2
def _aegis_risk_v2(src, dst, ports, alerts, blocks, lab):
    """Kanita dayali inceleme onceligi; saldiri basarisi puani degildir."""

    signatures = {
        str(p.get('signature') or '').upper()
        for p in alerts if p.get('signature')
    }

    context = (
        'known_lab_source'
        if src == '10.10.50.100'
        else 'unclassified'
    )

    if lab:
        context = 'explicit_lab_signature'

    # Beklenen NetBIOS broadcast trafigi
    if dst == '10.10.30.255' and set(ports) <= {138} and not alerts:
        return {
            'score': 8,
            'risk': 'low',
            'confidence': 'low',
            'factors': [
                'DC01 broadcast engellemesi; tek basina saldiri kaniti degil.'
            ],
            'lab_context': context
        }

    # ICMP imzalari tek basina yuksek risk olusturmaz
    if signatures and all('ICMP PING' in s for s in signatures):
        return {
            'score': 8,
            'risk': 'low',
            'confidence': 'low',
            'factors': [
                'Yalnizca ICMP ping imzalari; tekrarlar ayri saldiri sayilmadi.'
            ],
            'lab_context': context
        }

    if lab:
        return {
            'score': 10,
            'risk': 'low',
            'confidence': 'low',
            'factors': ['Acikca isaretlenmis laboratuvar test imzasi.'],
            'lab_context': context
        }

    if not alerts:
        score = min(29, 10 + min(blocks, 5) * 2)
        return {
            'score': score,
            'risk': 'low',
            'confidence': 'low',
            'factors': [
                'Firewall engellemesi; ek IDS veya uc nokta kaniti yok.'
            ],
            'lab_context': context
        }

    score = 18
    factors = [
        'Suricata imzasi eslesti; basarili istismar kanitlanmadi.'
    ]

    categories = []

    tests = [
        ('Tarama gostergesi', 14,
         lambda s: 'NIKTO' in s or 'ET SCAN' in s),

        ('SQL injection gostergesi', 22,
         lambda s: 'SQLI' in s or 'INFORMATION SCHEMA' in s),

        ('Supheli dosya yolu erisimi', 20,
         lambda s: '/ETC/PASSWD' in s or 'TRAVERSAL' in s),

        ('Exploit imzasi', 25,
         lambda s: 'EXPLOIT' in s),

        ('Shellcode imzasi', 25,
         lambda s: 'SHELLCODE' in s),

        ('Malware veya C2 imzasi', 25,
         lambda s: (
             'MALWARE' in s
             or ' CNC ' in s
             or ' C2 ' in s
         ))
    ]

    for name, weight, predicate in tests:
        if any(predicate(s) for s in signatures):
            categories.append((name, weight))

    # Ayni kategoride 20 tekrar, 20 farkli tehdit demek degil
    score += min(48, sum(weight for _, weight in categories))
    factors.extend(name for name, _ in categories)

    if dst == '10.10.30.10' and categories:
        score += 8
        factors.append('Hedef DC01: kritik Active Directory sistemi.')

    if len(ports) >= 4 and categories:
        score += 6
        factors.append('Birden fazla hedef port.')

    if len(categories) >= 3:
        score += 5
        factors.append('Birden fazla tespit kategorisi.')

    if not categories:
        factors.append('Ek risk gostergesi dogrulanmadi.')

    if context == 'known_lab_source':
        factors.append(
            'Kaynak Kali laboratuvar IP adresi; test kapsami dogrulanmali.'
        )

    # Basarili istismar / etki kaniti olmadan kritik puan verilmez
    score = min(score, 79)

    risk = (
        'high' if score >= 60
        else 'medium' if score >= 30
        else 'low'
    )

    confidence = 'medium' if len(categories) >= 2 else 'low'

    return {
        'score': score,
        'risk': risk,
        'confidence': confidence,
        'factors': factors,
        'lab_context': context
    }


# AEGIS-SMART-CORRELATION-V3
def _aegis_grouping_key(p, when):
    """Yalnizca bilinen NetBIOS broadcast gurultusunu gunluk grupla."""

    action = str(p.get('action') or '').upper()
    protocol = str(p.get('protocol') or '').upper()

    known_noise = (
        p.get('source') == 'FIREWALL'
        and p.get('src_ip') == '10.10.30.10'
        and p.get('dst_ip') == '10.10.30.255'
        and protocol == 'UDP'
        and str(p.get('dst_port') or '') == '138'
        and action in ('BLOCK', 'REJECT')
    )

    if known_noise:
        return ('noise_udp138_' + action, when.date().isoformat())

    return ('standard', int(when.timestamp()) // 300)


def build_incidents(events):
    groups=defaultdict(list)
    for e in events:
        p=e.get('parsed') or normalize(e)
        if not p.get('src_ip') or not p.get('dst_ip'):
            continue
        try:
            when=occurred_at(e)
            if when is None:
                continue
            kind,bucket=_aegis_grouping_key(p,when)
        except (ValueError, KeyError, TypeError):
            continue
        groups[(p['src_ip'],p['dst_ip'],kind,bucket)].append((e,p,when))
    result=[]
    for (src,dst,kind,bucket), rows in groups.items():
        alerts=[p for _,p,_ in rows if p['source']=='SURICATA' and p.get('signature')]
        fw=[p for _,p,_ in rows if p['source']=='FIREWALL']
        ports=sorted({int(p['dst_port']) for _,p,_ in rows if isinstance(p.get('dst_port'),int)})
        blocks=sum(p.get('action') in ('BLOCK','REJECT') for p in fw)
        lab=bool(alerts) and all(p.get('signature')=='KALI SECURITY TEST' for p in alerts)
        scan=len(ports)>=4 and len(alerts)>=3 and not lab
        scoring=_aegis_risk_v2(src,dst,ports,alerts,blocks,lab)
        if not alerts and not blocks:continue
        is_noise=kind.startswith('noise_udp138_')
        incident_id=(
            f'INC-NOISE-{bucket.replace("-", "")}-'
            f'{src.replace(".", "")}-{dst.replace(".", "")}-'
            f'{kind.rsplit("_", 1)[-1]}'
            if is_noise
            else f'INC-{bucket}-{src.replace(".", "")}-{dst.replace(".", "")}'
        )
        result.append({'id':incident_id,
            'title':'Laboratuvar Test Alarmı' if lab else ('Olası Ağ Servis Keşfi' if scan else ('IDS Alarm İncelemesi' if alerts else 'Firewall Engelleme İncelemesi')),
            'lab_test':lab,
            'noise_grouped':is_noise,
            'repeat_count':len(rows),
            'grouping_window':'calendar_day' if is_noise else '5_minutes',
            'evidence_count':len(rows),
            'evidence_sampled':len(rows)>30,
            'risk':scoring['risk'], 'confidence':scoring['confidence'],
            'risk_score':scoring['score'],
            'risk_factors':scoring['factors'],
            'lab_context':scoring['lab_context'],
            'scoring_version':'v2',
            'source_ip':src,'destination_ip':dst,
            'first_seen':min(x[2] for x in rows).isoformat(), 'last_seen':max(x[2] for x in rows).isoformat(),
            'ports':ports,'suricata_alerts':len(alerts),'firewall_events':len(fw),
            'firewall_blocks':blocks,'suricata_allowed':sum(p.get('action')=='allowed' for p in alerts),
            'signatures':sorted({p['signature'] for p in alerts if p.get('signature')}),
            'possible_mitre':'T1046 - Network Service Discovery' if scan else None,
            'limitations':['Port denemesi başarılı erişim kanıtı değildir.','Suricata allowed firewall PASS anlamına gelmez.',
                           'Korelasyon 5 dakikalık kaynak olay zamanı penceresine dayanır; zaman damgası yoksa alım zamanı kullanılır.'],
            'evidence':[{'source':p['source'],'time':e.get('event_time') or (occurred_at(e).isoformat() if occurred_at(e) else e['time']),'action':p.get('action'),
                         'port':p.get('dst_port'),'signature':p.get('signature')} for e,p,_ in rows[:30]]})
    return sorted(result,key=lambda x:x['last_seen'],reverse=True)
