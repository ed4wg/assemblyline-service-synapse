import pytest
from synapse.synapse import Synapse


@pytest.fixture
def synapse_instance():

    config = {
        "synapse_api_key": "api_key",
        "synapse_host": "localhost",
        "max_nodes_per_query": 50,
        "al4_tag_types": [
            "network.static.ip",
            "network.dynamic.ip",
            "network.static.domain",
            "network.dynamic.domain",
            "network.static.uri",
            "network.dynamic.uri",
            "network.email.address",
        ],
        "heur_map": {},  # expects to be overridden in each test
        "syntags_to_filter_node": ["filter.node.with.tag1", "filter2"],
        "syntag_prefixes_to_filter": ["filter.prefix1"],
    }

    return Synapse(config=config)


def test_build_syn_queries_single_chunk(synapse_instance):
    """validate the syn query is created as expected for basic set of ndefs and conditions"""

    synapse_instance.heur_map = {
        "1": {"match_any_syn_tag": ["tag1a", "tag1b"]},
        "2": {"match_all_syn_tags": [["tag2a", "tag2b"]]},
    }
    syn_ndefs = {("inet:ipv4", "192.168.1.1"), ("inet:fqdn", "example.com")}
    result = synapse_instance._build_syn_queries(syn_ndefs)
    expected = [
        'inet:fqdn="example.com" inet:ipv4="192.168.1.1" +(#tag1a or #tag1b or (#tag2a and #tag2b)) -(#filter.node.with.tag1 or #filter2)'
    ]
    assert result == expected


def test_build_syn_queries_multiple_chunks(synapse_instance):
    """validate the syn queries are created as expected when it is chunked"""

    synapse_instance.heur_map = {
        "1": {"match_any_syn_tag": ["tag1a", "tag1b"]},
        "2": {"match_all_syn_tags": [["tag2a", "tag2b"]]},
    }
    syn_ndefs = {
        ("inet:ipv4", "192.168.1.1"),
        ("inet:fqdn", "example.com"),
        ("inet:email", "test@foo.local"),
    }
    result = synapse_instance._build_syn_queries(syn_ndefs, chunk_size=2)
    expected = [
        'inet:email="test@foo.local" inet:fqdn="example.com" +(#tag1a or #tag1b or (#tag2a and #tag2b)) -(#filter.node.with.tag1 or #filter2)',
        'inet:ipv4="192.168.1.1" +(#tag1a or #tag1b or (#tag2a and #tag2b)) -(#filter.node.with.tag1 or #filter2)',
    ]
    assert result == expected


def test_build_syn_queries_when_no_node_filters(synapse_instance):
    """validate the syn query is created as expected when there are no node filters"""

    synapse_instance.heur_map = {
        "1": {"match_any_syn_tag": ["tag1a"]},
    }
    syn_ndefs = {("inet:ipv4", "192.168.1.1"), ("inet:fqdn", "example.com")}
    # remove the node filters
    synapse_instance.syntags_to_filter_node = []
    result = synapse_instance._build_syn_queries(syn_ndefs)
    expected = ['inet:fqdn="example.com" inet:ipv4="192.168.1.1" +(#tag1a)']
    assert result == expected


def test_build_syn_queries_for_complex_match_condition(synapse_instance):
    """validate the syn query is created as expected when there's a complex match condition"""

    synapse_instance.heur_map = {
        "1": {"match_any_syn_tag": ["tag1a", "tag1b"]},
        "2": {
            "match_all_syn_tags": [["and1a", "and1b"], ["and2a", "and2b"]],
            "match_any_syn_tag": ["tag3a", "tag3b"],
        },
    }
    syn_ndefs = {("inet:ipv4", "192.168.1.1"), ("inet:fqdn", "example.com")}
    result = synapse_instance._build_syn_queries(syn_ndefs)
    expected = [
        'inet:fqdn="example.com" inet:ipv4="192.168.1.1" +(#tag1a or #tag1b or #tag3a or #tag3b or (#and1a and #and1b) or (#and2a and #and2b)) -(#filter.node.with.tag1 or #filter2)'
    ]
    assert result == expected
