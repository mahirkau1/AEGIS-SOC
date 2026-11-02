import json
import unittest
from app.parser import normalize
from app.sysmon_engine import parse_sysmon, build_process_tree
from app.sysmon_detection import detect_sysmon
from app.sysmon_intelligence import summarize


def ev(eid, fields=None, host='WIN01', guid='{a}', record=1):
    fields = fields or {}
    system = '<System><EventID>%s</EventID><EventRecordID>%s</EventRecordID><Computer>%s</Computer></System>' % (eid, record, host)
    data = ''.join('<Data Name="%s">%s</Data>' % (k, str(v).replace('&', '&amp;').replace('<', '&lt;')) for k,v in fields.items())
    xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">%s<EventData>%s</EventData></Event>' % (system, data)
    return {'source':'SYSMON','host':host, 'raw':json.dumps({'xml':xml,'timestamp':'2026-11-01T12:00:00+00:00'}), 'message':'Sysmon event'}


class ParserTests(unittest.TestCase):
    def test_process_event(self):
        p = normalize(ev(1,{'ProcessGuid':'{abc}', 'Image':r'C:\Windows\powershell.exe','ParentImage':r'C:\Word\WINWORD.EXE','CommandLine':'powershell.exe -NoProfile'}))
        self.assertEqual(p['event_id'], 1)
        self.assertEqual(p['record_id'], '1')
        self.assertEqual(p['detection']['rule'], 'SYSMON-OFFICE-SHELL')
    def test_not_sysmon(self):
        self.assertIsNone(parse_sysmon({'source':'AD','raw':'{}'}))
    def test_bad_xml(self):
        self.assertIsNone(parse_sysmon({'source':'SYSMON','raw':'{"xml":"<Event><bad"}'}))
    def test_no_xml(self):
        self.assertIsNone(parse_sysmon({'source':'SYSMON','raw':'{"event_id":1}'}))
    def test_empty_record(self):
        self.assertIsNone(parse_sysmon({'source':'SYSMON','raw':'[]'}))
    def test_network_detection(self):
        p=normalize(ev(3,{'DestinationIp':'8.8.8.8','DestinationPort':'4444'}))
        self.assertEqual(p['detection']['rule'],'SYSMON-UNUSUAL-OUTBOUND-PORT')
    def test_private_network_no_alert(self):
        self.assertNotIn('detection',normalize(ev(3,{'DestinationIp':'10.10.20.10','DestinationPort':'4444'})))
    def test_dns_suspicious(self):
        self.assertEqual(normalize(ev(22,{'QueryName':'x.onion'}))['detection']['rule'],'SYSMON-SUSPICIOUS-DNS')
    def test_dns_common(self):
        self.assertNotIn('detection',normalize(ev(22,{'QueryName':'microsoft.com'})))
    def test_event10_lsass_full_access(self):
        p=normalize(ev(10,{'SourceImage':r'C:\Temp\a.exe','TargetImage':r'C:\Windows\System32\lsass.exe','GrantedAccess':'0x1fffff'}))
        self.assertEqual(p['detection']['rule'],'SYSMON-LSASS-ACCESS')
    def test_event10_lsass_benign_access_mask(self):
        self.assertNotIn('detection',normalize(ev(10,{'SourceImage':r'C:\Temp\a.exe','TargetImage':r'C:\Windows\System32\lsass.exe','GrantedAccess':'0x1010'})))
    def test_event8_other_target_no_alert(self):
        self.assertNotIn('detection',normalize(ev(8,{'SourceImage':'a.exe','TargetImage':'notepad.exe'})))
    def test_event8_lsass(self):
        self.assertEqual(normalize(ev(8,{'SourceImage':'evil.exe','TargetImage':r'C:\Windows\lsass.exe'}))['detection']['rule'],'SYSMON-REMOTE-THREAD-LSASS')
    def test_event11_startup(self):
        self.assertEqual(normalize(ev(11,{'TargetFilename':r'C:\Users\burak\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk'}))['detection']['rule'],'SYSMON-STARTUP-FILE')
    def test_event11_normal(self):
        self.assertNotIn('detection',normalize(ev(11,{'TargetFilename':r'C:\Temp\abc.txt'})))
    def test_registry_run(self):
        self.assertEqual(normalize(ev(13,{'TargetObject':r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\test'}))['detection']['rule'],'SYSMON-AUTORUN-REGISTRY')
    def test_registry_other(self):
        self.assertNotIn('detection',normalize(ev(13,{'TargetObject':r'HKCU\Software\Microsoft\Windows\Explorer\test'})))
    def test_event25(self):
        self.assertEqual(normalize(ev(25,{}))['detection']['rule'],'SYSMON-PROCESS-TAMPERING')
    def test_no_alert_for_dll(self):
        self.assertNotIn('detection',normalize(ev(7,{})))
    def test_encoding_invalid_raw(self):
        self.assertNotIn('detection',normalize({'source':'SYSMON','raw':'not-json', 'severity':'info'}))
    def test_process_tree_host_isolation(self):
        a=ev(1,{'ProcessGuid':'{a}','Image':'parent.exe'},'WIN01')
        b=ev(1,{'ProcessGuid':'{b}','ParentProcessGuid':'{a}','Image':'child.exe'},'DC01')
        tree=build_process_tree([a,b]); self.assertEqual(tree['process_count'],2)
        self.assertFalse(next(p for p in tree['processes'] if p['id']=='{b}')['parent_found'])
    def test_process_tree_parent_case_insensitive(self):
        a=ev(1,{'ProcessGuid':'{ABC}','Image':'parent.exe'},'WIN01')
        b=ev(1,{'ProcessGuid':'{def}','ParentProcessGuid':'{abc}','Image':'child.exe'},'win01')
        tree=build_process_tree([a,b]); self.assertTrue(next(p for p in tree['processes'] if p['id']=='{def}')['parent_found'])
    def test_process_tree_parsed_without_raw(self):
        item={'source':'SYSMON','host':'WIN01','parsed':{'event_id':1, 'process_guid':'{a}', 'image':'x.exe'}}
        self.assertEqual(build_process_tree([item])['process_count'],1)
    def test_tree_counts_network_dns(self):
        e1=ev(3,{'ProcessGuid':'{a}','DestinationIp':'8.8.8.8'})
        e2=ev(22,{'ProcessGuid':'{a}','QueryName':'example.com'})
        tree=build_process_tree([e1,e2]); self.assertEqual((tree['network_count'],tree['dns_count']),(1,1))
    def test_summary_sample(self):
        e={'source':'SYSMON','host':'WIN01','parsed':{'event_id':1, 'image':'powershell.exe','detection':{'rule':'SYSMON-X'}}}
        out=summarize([e],100)
        self.assertEqual(out['sample_alert_events'],1);self.assertTrue(out['sample_truncated']);self.assertEqual(out['event_ids'][0]['id'],1)
    def test_summary_invalid(self):
        out=summarize([{'host':'WIN01','parsed':{}}],1)
        self.assertEqual(out['invalid_event_id'],1)
        self.assertEqual(out['sample_alert_events'],0)
    def test_event_id_1_not_detect_every_shell(self):
        self.assertIsNone(detect_sysmon({'event_id':1,'image':'cmd.exe','parent_image':'explorer.exe'}))
    def test_malformed_event_id(self):
        self.assertIsNone(detect_sysmon({'event_id':'not-number'}))

if __name__=='__main__': unittest.main()
