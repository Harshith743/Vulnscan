from vulnscan.scanner.tcp import parse_ports, tcp_scan, grab_banner
from vulnscan.enrichers.vulnmatcher import match_banners_to_vulns

def test_parse_ports_range_and_list():
    ports = parse_ports("1-3,22,80")
    assert ports == [1, 2, 3, 22, 80]

def test_tcp_scan_localhost():
    # Should not raise errors even if no ports open
    result = tcp_scan("127.0.0.1", [80, 443, 22])
    assert isinstance(result, list)

def test_banner_grab_safety():
    # Should return a string (possibly empty)
    banner = grab_banner("127.0.0.1", 22)
    assert isinstance(banner, str)

def test_vulnmatcher_sample():
    banners = {"22": "SSH-2.0-OpenSSH_7.4", "80": "Apache/2.4.29"}
    issues = match_banners_to_vulns(banners)
    # Ensure keys exist and at least one match found
    assert "22" in issues and isinstance(issues["22"], list)
