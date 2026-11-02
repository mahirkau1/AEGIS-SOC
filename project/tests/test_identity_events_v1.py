"""Offline fixture tests: no SOC DB, network, API restart, or login attempts."""
import copy
import json
import os
import unittest
from unittest.mock import patch

from app import identity_events, identity_bridge, win_security_intel


BASE_TIME = '2026-10-31T10:43:44.230490+00:00'


def win_event(eid=4624, user='ayse', record=101, fields=None, nested=True):
    data = {'event_id': eid, 'record_id': record, 'time': BASE_TIME}
    f = fields or {'TargetUserName': user, 'LogonType': '2',
                   'TargetLogonId': '0x123', 'IpAddress': '::ffff:10.10.20.100'}
    if nested:
        data['fields'] = f
    else:
        data.update({'user': user, 'logon_type': f['LogonType'],
                     'source_ip': f['IpAddress']})
    return {'source': 'WIN_SECURITY', 'host': 'WIN01',
            'time': '2026-10-31T13:43:45+03:00', 'raw': json.dumps(data)}


class NormalizerTests(unittest.TestCase):
    def test_nested_fields(self):
        out = identity_events.normalize(win_event())
        self.assertEqual((out['event_id'], out['user'], out['source_ip']),
                         (4624, 'ayse', '10.10.20.100'))
        self.assertEqual(out['event_time'], BASE_TIME)
        self.assertEqual(out['received_at'], '2026-10-31T10:43:45+00:00')
        self.assertEqual(out['logon_id'], '0x123')
        self.assertEqual(out['evidence_ref']['record_id'], '101')
        self.assertEqual(out['schema'], identity_events.SCHEMA)

    def test_windows_engine_agreement(self):
        e = win_event(fields={'TargetUserName': 'ELIF', 'LogonType': '7',
                              'TargetLogonId': '0xAAA', 'IpAddress': '10.10.20.100'})
        public = win_security_intel._event(e)
        common = identity_events.normalize(e)
        for field in ('event_id', 'host', 'user', 'actor', 'target_user',
                      'logon_id', 'logon_type', 'record_id'):
            self.assertEqual(common[field], public[field])
        self.assertEqual(common['source_ip'], public['source'])

    def test_flat_event_dedup_by_record_id(self):
        a = win_event(nested=False)
        b = copy.deepcopy(a)
        b['time'] = '2026-10-31T13:49:00+03:00'
        self.assertEqual(identity_events.normalize(a)['event_uid'],
                         identity_events.normalize(b)['event_uid'])
        self.assertEqual(len(identity_bridge._windows_normalized([a, b])), 1)

    def test_missing_record_id_and_time_are_partial(self):
        e = win_event()
        e['raw'] = json.dumps({'event_id': 4624, 'fields': {'TargetUserName': 'ayse'}})
        e.pop('time')
        out = identity_events.normalize(e)
        self.assertEqual(out['quality'], 'partial')
        self.assertIn('record_id_missing', out['warnings'])
        self.assertIn('event_time_missing', out['warnings'])

    def test_missing_user_not_misattributed(self):
        e = win_event(fields={'TargetUserName':'SYSTEM', 'LogonType':'2', 'IpAddress':'::1'})
        out = identity_events.normalize(e)
        self.assertEqual(out['user'], '')
        self.assertEqual(out['source_ip'], '')
        self.assertEqual(identity_bridge._windows_normalized([e]), [])

    def test_explicit_credentials_keep_actor_separate(self):
        e = win_event(eid=4648, fields={'SubjectUserName':'alice',
                         'TargetUserName':'bob', 'TargetLogonId':'0x22'})
        out = identity_events.normalize(e)
        self.assertEqual(out['user'], 'alice')
        self.assertEqual(out['actor'], 'alice')
        self.assertEqual(out['target_user'], 'bob')
        self.assertEqual(out['outcome'], 'observed')

    def test_ad_group_is_not_user(self):
        raw = {'event_id':4728, 'record_id':55,
               'fields':{'TargetUserName':'Domain Admins',
                         'TargetSid':'S-1-5-21-1-512',
                         'MemberSid':'S-1-5-21-1-1101',
                         'SubjectUserName':'admin'}}
        e = {'source':'AD', 'host':'DC01','event_time':BASE_TIME,'raw':json.dumps(raw)}
        out = identity_events.normalize(e)
        self.assertEqual(out['group'], 'Domain Admins')
        self.assertEqual(out['group_sid'], 'S-1-5-21-1-512')
        self.assertEqual(out['member_sid'], 'S-1-5-21-1-1101')
        self.assertEqual(out['actor'], 'admin')
        self.assertEqual(out['user'], '')

    def test_disallow_malformed_and_other_sources(self):
        self.assertIsNone(identity_events.normalize({'source':'SYSMON','raw':'{}'}))
        self.assertIsNone(identity_events.normalize({'source':'AD','raw':'bad json'}))
        self.assertIsNone(identity_events.normalize({'source':'AD','raw':json.dumps({'event_id':'oops'})}))

    def test_clock_skew_filter_unchanged(self):
        item = win_event(eid=4625, fields={'TargetUserName':'ayse',
                             'LogonType':'10','Status':'0xC0000133',
                             'IpAddress':'10.10.20.100'})
        self.assertEqual(identity_bridge._windows_normalized([item]), [])

    def test_shadow_does_not_modify_detection_inputs(self):
        nested = win_event()
        flat = win_event(record=102, user='elif', nested=False)
        with patch.object(identity_bridge, '_rows', return_value=iter([nested, flat])):
            with patch.dict(os.environ, {'AEGIS_IDENTITY_NORMALIZER_MODE':'shadow'}):
                result, stats = identity_bridge._windows_with_stats(limit=100)
        self.assertEqual(len(result), 1) # original only sees flat records
        self.assertEqual(stats['mode'], 'shadow')
        self.assertEqual(stats['legacy_events'], 1)
        self.assertEqual(stats['normalized_events'], 2)
        self.assertEqual(stats['new_only'], 1)
        self.assertEqual(stats['legacy_only'], 0)

    def test_original_windows_interface_is_list(self):
        nested = win_event()
        with patch.object(identity_bridge, '_rows', return_value=iter([nested])):
            with patch.dict(os.environ, {'AEGIS_IDENTITY_NORMALIZER_MODE':'shadow'}):
                self.assertIsInstance(identity_bridge._windows(), list)

    def test_explicit_enable_catches_nested_events(self):
        nested = win_event()
        with patch.object(identity_bridge, '_rows', return_value=iter([nested])):
            with patch.dict(os.environ, {'AEGIS_IDENTITY_NORMALIZER_MODE':'enabled'}):
                result, stats = identity_bridge._windows_with_stats()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['source'], '10.10.20.100')
        self.assertEqual(stats['mode'], 'enabled')

    def test_default_mode_is_shadow(self):
        nested = win_event()
        env = {k:v for k,v in os.environ.items() if k != 'AEGIS_IDENTITY_NORMALIZER_MODE'}
        with patch.object(identity_bridge, '_rows', return_value=iter([nested])):
            with patch.dict(os.environ, env, clear=True):
                result, stats = identity_bridge._windows_with_stats()
        self.assertEqual(result, [])
        self.assertEqual(stats['mode'], 'shadow')

    def test_mapped_ipv6_and_non_ip_source(self):
        e = win_event(fields={'TargetUserName':'ayse', 'LogonType':'2',
                                'IpAddress':'host01', 'WorkstationName':'LABWIN01'})
        out = identity_events.normalize(e)
        self.assertEqual(out['source_ip'], '')
        self.assertEqual(out['source_identity'], 'labwin01')
        self.assertEqual(identity_events.normalize(win_event())['source_ip'], '10.10.20.100')


if __name__ == '__main__':
    unittest.main()
