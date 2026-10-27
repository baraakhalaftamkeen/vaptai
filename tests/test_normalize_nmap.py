"""nmap XML parsing: the old regex matched nothing against real nmap -oX output, so
open ports were silently dropped. These lock in that real XML now yields findings, that
closed/filtered ports are ignored, and that the plain-text fallback still works."""
from __future__ import annotations

from vapt_agents.normalize import normalize

_XML = """<?xml version="1.0"?>
<nmaprun>
<host><ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
  <service name="http" product="Microsoft IIS httpd" version="10.0"/></port>
<port protocol="tcp" portid="3389"><state state="open" reason="syn-ack"/>
  <service name="ms-wbt-server"/></port>
<port protocol="tcp" portid="445"><state state="filtered" reason="no-response"/>
  <service name="microsoft-ds"/></port>
</ports></host>
</nmaprun>"""


def _titles(obs):
    return [o.title for o in obs]


def test_nmap_xml_yields_open_ports_with_service_and_banner():
    obs = normalize("nmap_service_scan", [{"stdout": _XML}])
    ports = {o.detail["port"] for o in obs}
    assert ports == {"80", "3389"}                 # 445 is filtered -> excluded
    http = next(o for o in obs if o.detail["port"] == "80")
    assert http.detail["service"] == "http"
    assert "Microsoft IIS httpd" in http.title and "10.0" in http.title
    rdp = next(o for o in obs if o.detail["port"] == "3389")
    assert rdp.detail["service"] == "ms-wbt-server"


def test_nmap_closed_port_excluded():
    xml = ('<port protocol="tcp" portid="22"><state state="closed" reason="reset"/>'
           '<service name="ssh"/></port>')
    assert normalize("nmap_service_scan", [{"stdout": xml}]) == []


def test_nmap_plaintext_fallback_still_works():
    obs = normalize("nmap_service_scan", [{"stdout": "22/tcp open ssh\n443/tcp open https"}])
    assert sorted(o.detail["port"] for o in obs) == ["22", "443"]


def test_nmap_empty_output_is_safe():
    assert normalize("nmap_service_scan", [{"stdout": ""}]) == []
