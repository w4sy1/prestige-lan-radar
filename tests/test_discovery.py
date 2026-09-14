import unittest
from discovery import discover,enrich,targets


class DiscoveryTests(unittest.TestCase):
    def test_bounds_and_authorization(self):
        for value in ('0.0.0.0/0','10.0.0.0/8','8.8.8.0/24','::1/128','127.0.0.0/24'):
            with self.assertRaises(ValueError):targets(value)
        self.assertEqual(targets('192.168.1.0/30'),['192.168.1.1','192.168.1.2'])
        with self.assertRaises(ValueError):discover('192.168.1.0/30',False,lambda:[])

    def test_active_results_do_not_claim_complete(self):
        rows=[{'ip':'192.168.1.1','mac':'00:11:22:33:44:55'},{'ip':'192.168.1.2','mac':'00:11:22:33:44:66'}]
        result=discover('192.168.1.0/30',True,lambda:rows,{'001122':'Fixture'},probe=lambda address:address.endswith('.1'))
        self.assertEqual(len(result['rows']),1)
        self.assertEqual(result['rows'][0]['vendor'],'Fixture')
        self.assertFalse(result['complete'])

    def test_random_mac_does_not_invent_vendor(self):
        row=enrich([{'ip':'192.168.1.1','mac':'02:11:22:33:44:55'}],{'021122':'Wrong'})[0]
        self.assertNotEqual(row['vendor'],'Wrong')
