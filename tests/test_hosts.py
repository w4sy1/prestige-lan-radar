import unittest
from hosts import normalize


class HostTests(unittest.TestCase):
    def test_multiple_addresses_same_device(self):
        rows=normalize([{'mac':'00:11:22:33:44:55','ip':'192.168.1.10'},{'mac':'00:11:22:33:44:55','ip':'192.168.1.2'}])
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['ips'],['192.168.1.2','192.168.1.10'])

    def test_multicast_is_not_device(self):
        with self.assertRaises(ValueError):normalize([{'mac':'01:00:5e:00:00:01','ip':'224.0.0.1'}])

    def test_ipv4_ipv6_same_mac(self):
        row=normalize([{'mac':'00:11:22:33:44:55','ips':['2001:db8::1','192.168.1.2']}])[0]
        self.assertEqual(row['ip'],'192.168.1.2')
        self.assertEqual(len(row['ips']),2)
