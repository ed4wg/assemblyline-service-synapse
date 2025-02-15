from synapse.synapse import Synapse


def test_get_syn_form_for_ip_ipv4():
    ip = "192.168.1.1"
    result = Synapse._get_syn_form_for_ip(ip)
    assert result == "inet:ipv4"


def test_get_syn_form_for_ip_ipv6():
    ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7111"
    result = Synapse._get_syn_form_for_ip(ip)
    assert result == "inet:ipv6"

    ip = "2001:0db8::0011"
    result = Synapse._get_syn_form_for_ip(ip)
    assert result == "inet:ipv6"


def test_get_syn_form_for_ip_invalid():
    ip = "invalid_ip"
    result = Synapse._get_syn_form_for_ip(ip)
    assert result is None

    ip = ""
    result = Synapse._get_syn_form_for_ip(ip)
    assert result is None

    ip = None
    result = Synapse._get_syn_form_for_ip(ip)
    assert result is None


def test_get_syn_form_for_ip_ipv4_with_port():
    """validate that when the port is present, the form is not returned""" 
    ip = "192.168.1.1:8080"
    result = Synapse._get_syn_form_for_ip(ip)
    assert result is None


def test_get_syn_form_for_ip_ipv6_with_port():
    """validate that when the port is present, the form is not returned""" 
    # Note: have not not seen an al4 ip tag represented this way..
    ip = "[2001:0db8:85a3:0000:0000:8a2e:0370:7111]:8080"
    result = Synapse._get_syn_form_for_ip(ip)
    assert result is None
