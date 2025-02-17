from synapse.synapse_result_helper import SynapseResultHelper


def test_related_al4_tags():
    """validate the matching al4 tag type is returned"""
    al4_tags = {
        "network.static.ip": ["192.168.1.1"],
        "network.dynamic.ip": ["10.0.0.1"],
        "network.static.domain": ["example.com"],
    }
    syn_node_val = "192.168.1.1"
    related_tags = SynapseResultHelper._find_related_al4tag_types(al4_tags, syn_node_val)
    assert "network.static.ip" in related_tags
    assert "network.dynamic.ip" not in related_tags
    assert "network.static.domain" not in related_tags


def test_no_related_al4_tags():
    """validate no matching al4 tag type are returned"""
    al4_tags = {
        "network.static.ip": ["192.168.1.1"],
        "network.dynamic.ip": ["10.0.0.1"],
        "network.static.domain": ["example.com"],
    }
    syn_node_val = "192.168.1.2"
    related_tags = SynapseResultHelper._find_related_al4tag_types(al4_tags, syn_node_val)
    assert len(related_tags) == 0


def test_multiple_related_al4_tags():
    """validate when multiple tag types are found that all are returned"""
    al4_tags = {
        "network.static.ip": ["192.168.1.1"],
        "network.dynamic.ip": ["192.168.1.1"],
        "network.static.domain": ["example.com"],
    }
    syn_node_val = "192.168.1.1"
    related_tags = SynapseResultHelper._find_related_al4tag_types(al4_tags, syn_node_val)
    assert "network.static.ip" in related_tags
    assert "network.dynamic.ip" in related_tags
    assert "network.static.domain" not in related_tags


def test_empty_al4_tags():
    """validate no matches are found when no al4 tags are passed in"""
    al4_tags = {}
    syn_node_val = "192.168.1.1"
    related_tags = SynapseResultHelper._find_related_al4tag_types(al4_tags, syn_node_val)
    assert len(related_tags) == 0


def test_null_syn_node_val():
    """validate no matches are found when no synapse node value is passed in"""
    al4_tags = {
        "network.static.ip": ["192.168.1.1"],
        "network.dynamic.ip": ["192.168.1.1"],
        "network.static.domain": ["example.com"],
    }
    syn_node_val = None
    related_tags = SynapseResultHelper._find_related_al4tag_types(al4_tags, syn_node_val)
    assert len(related_tags) == 0
