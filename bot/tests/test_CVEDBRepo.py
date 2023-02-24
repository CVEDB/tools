import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest

import CVEDB

class FakeIssue:

    def __init__(self):
        self.cvedb = "CAN-1900-1000001"
        self.id = 1
        self.json = {
            "vendor_name": "test vendor",
            "product_name": "test product",
            "product_version": "test version",
            "vulnerability_type": "test type",
            "affected_component": "test component",
            "attack_vector": "test vector",
            "impact": "test impact",
            "credit": "test credit",
            "references": [
                "http://example.com"
            ],
            "reporter": "joshbressers",
            "reporter_id": 1692786,
            "notes": "test note",
            "description": "test description"
        }

    def get_cvedb_json(self):
        return self.json

    def get_reporter(self):
        return "%s:%s" % (self.json['reporter'], self.json['reporter_id'])

    def get_cvedb_id(self):
        return self.cvedb

    def ugly_json(self):
        # I'm not even sorry
        return {'cvedb': {'vendor_name': 'test vendor', 'product_name': 'test product', 'product_version': 'test version', 'vulnerability_type': 'test type', 'affected_component': 'test component', 'attack_vector': 'test vector', 'impact': 'test impact', 'credit': 'test credit', 'references': ['http://example.com'], 'reporter': 'joshbressers', 'reporter_id': 1692786, 'notes': 'test note', 'description': 'test description'}, 'data_type': 'CVEDB', 'data_format': 'MITRE', 'data_version': '4.0', 'CVE_data_meta': {'ASSIGNER': 'cvedb', 'ID': 'CVEDB-1900-0001', 'STATE': 'PUBLIC'}, 'affects': {'vendor': {'vendor_data': [{'vendor_name': 'test vendor', 'product': {'product_data': [{'product_name': 'test product', 'version': {'version_data': [{'version_value': 'test version'}]}}]}}]}}, 'problemtype': {'problemtype_data': [{'description': [{'lang': 'eng', 'value': 'test type'}]}]}, 'references': {'reference_data': [{'url': 'http://example.com', 'refsource': 'MISC', 'name': 'http://example.com'}]}, 'description': {'description_data': [{'lang': 'eng', 'value': 'test description'}]}}
        # Maybe a little sorry

class TestCVEDBRepo(unittest.TestCase):

    def setUp(self):
        self.repo = CVEDB.CVEDBRepo("https://github.com/CVEDB/security-database.git", testing=True)

    def tearDown(self):
        self.repo.close()

    def testApprovedUser(self):
        self.assertTrue(self.repo.approved_user("joshbressers:1692786"))
        self.assertFalse(self.repo.approved_user("baduser"))

    def testAddCVEDB(self):
        # This test is really weak
        fake_issue = FakeIssue()
        the_id = self.repo.add_cvedb(fake_issue)
        self.assertTrue(the_id.startswith('CVEDB'))

    def testCanToCVEDB(self):
        fake_issue = FakeIssue()
        fake_issue.json["reporter"] = "bad_user"
        the_id = self.repo.add_cvedb(fake_issue)
        fake_issue.cvedb = the_id
        the_id = self.repo.can_to_cvedb(fake_issue)
        self.assertEqual(the_id[3:], fake_issue.cvedb[3:])

    def testPush(self):
        # Probably never test this one unless we setup a demo repo
        pass

    def testNextCVEDBPath(self):
        # We really need a clean repo
        the_id = self.repo.get_next_cvedb_path()
        self.assertTrue(the_id[0].startswith('CAN'))
        the_id = self.repo.get_next_cvedb_path(approved_user = True)
        self.assertTrue(the_id[0].startswith('CVEDB'))

    def testGetCVEDBJSON(self):
        self.maxDiff = None
        fake_issue = FakeIssue()
        the_data = self.repo.get_cvedb_json_format('CVEDB-1900-1000001', fake_issue.get_cvedb_json())
        for i in fake_issue.get_cvedb_json().keys():
            # Let's just check the keys
            self.assertTrue(i in the_data['CVEDB'])

    def testGetAllIDs(self):
        the_ids = self.repo.get_all_ids()
        # Because we use a real repo, this number will change, so let's
        # just look for some things we know exist
        self.assertTrue("CVEDB-2021-1000000" in the_ids)
        self.assertTrue("CVEDB-2021-1000010" in the_ids)
        self.assertTrue("CVEDB-2021-1000100" in the_ids)
        self.assertTrue("CVEDB-2021-1000400" in the_ids)

    def testGetID(self):
        fake_issue = FakeIssue()
        the_id = self.repo.add_cvedb(fake_issue)
        id_info = self.repo.get_id(the_id)
        self.assertEqual(id_info["OSV"]["id"], the_id)

    def testUpdateID(self):
        fake_issue = FakeIssue()
        the_id = self.repo.add_cvedb(fake_issue)
        id_info = self.repo.get_id(the_id)
        self.assertEqual(id_info["OSV"]["id"], the_id)
        id_info["OSV"]["id"] = "CVEDB-1801-01"
        self.repo.update_id(the_id, id_info)

        id_info = self.repo.get_id(the_id)
        self.assertEqual(id_info["OSV"]["id"], "CVEDB-1801-01")
