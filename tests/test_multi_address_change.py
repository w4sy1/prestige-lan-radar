from pathlib import Path
import tempfile
import unittest
from app import observe


class MultiAddressChangeTests(unittest.TestCase):
    def test_mac_change_on_secondary_address(self):
        with tempfile.TemporaryDirectory() as temporary:
            database=Path(temporary)/'lan.sqlite'
            observe(database,[{'mac':'02:00:00:00:00:01','ips':['192.168.1.2','192.168.1.20']}])
            result=observe(database,[{'mac':'02:00:00:00:00:02','ip':'192.168.1.20'}])
            self.assertIn('POSSIBLE_MAC_CHANGE',[event['event'] for event in result['events']])
            result=observe(database,[{'mac':'02:00:00:00:00:03','ip':'192.168.1.30'}])
            self.assertNotIn('POSSIBLE_MAC_CHANGE',[event['event'] for event in result['events']])
