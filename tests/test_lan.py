from pathlib import Path
import tempfile
import unittest
from app import observe,normalize

class LanTests(unittest.TestCase):
    def test_lifecycle(self):
        with tempfile.TemporaryDirectory() as d:
            db=Path(d)/'lan.db';row={'ip':'192.168.1.2','mac':'00:11:22:33:44:55'}
            self.assertEqual(observe(db,[row])['events'][0]['event'],'NEW_DEVICE')
            self.assertFalse(observe(db,[])['events'])
            self.assertEqual(observe(db,[],True)['events'][0]['event'],'DISAPPEARED')
            self.assertEqual(observe(db,[row])['events'][0]['event'],'RETURNED')
    def test_bad_mac(self):
        with self.assertRaises(ValueError):normalize([{'ip':'1.1.1.1','mac':'bad'}])
