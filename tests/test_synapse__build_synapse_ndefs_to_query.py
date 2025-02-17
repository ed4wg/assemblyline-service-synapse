import logging

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
        "heur_map": {
            "1": {"match_any_syn_tag": ["tag1a", "tag1b"]},
            "2": {"match_all_syn_tags": [["tag2a", "tag2b"]]},
        },
        "syntags_to_filter_node": ["filter.node.with.tag1", "filter2"],
        "syntag_prefixes_to_filter": ["filter.prefix1"],
    }

    return Synapse(config=config)


def test_build_synapse_ndefs_to_query_ip(synapse_instance):
    al4_tags = {"network.static.ip": ["192.168.1.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7111"]}
    result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
    assert result == {
        ("inet:ipv4", "192.168.1.1"),
        ("inet:ipv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7111"),
    }

    # validate that when a port is present in an ipv4 tag, that it is stripped and still found
    al4_tags = {"network.static.ip": ["192.168.2.1:8080"]}
    result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
    assert result == {
        ("inet:ipv4", "192.168.2.1"),
    }


def test_build_synapse_ndefs_to_query_domain(synapse_instance):
    al4_tags = {"network.static.domain": ["example.com"]}
    result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
    assert result == {("inet:fqdn", "example.com")}


def test_build_synapse_ndefs_to_query_uri(synapse_instance):
    # URIs with brackets are OK. Synapse will parse the query correctly.
    al4_tags = {
        "network.static.uri": ["http://example.com", "http://foo.local/test?uid=[bracket]&test=1"]
    }
    result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
    assert result == {
        ("inet:url", "http://example.com"),
        ("inet:url", "http://foo.local/test?uid=[bracket]&test=1"),
    }


def test_build_synapse_ndefs_to_query_email(synapse_instance):
    al4_tags = {"network.email.address": ["user@example.com"]}
    result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
    assert result == {("inet:email", "user@example.com")}


def test_build_synapse_ndefs_to_query_with_invalid_al4tag_vals(synapse_instance, caplog):
    """validate various scenarios with invalid tag vals"""

    # invalid ip
    al4_tags = {"network.static.ip": ["invalid_ip", "192.168.1.1"]}
    with caplog.at_level(logging.ERROR):
        result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
        assert result == {
            ("inet:ipv4", "192.168.1.1"),
        }
        assert any("AL4 tag value failed parsing" in message for message in caplog.messages)

    # invalid domain
    al4_tags = {
        "network.dynamic.domain": ["invalid~dom.local", "another^invalid.local", "foo.local"]
    }
    with caplog.at_level(logging.ERROR):
        result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
        assert result == {
            ("inet:fqdn", "foo.local"),
        }
        assert any("AL4 tag value failed parsing" in message for message in caplog.messages)

    # invalid uri
    al4_tags = {"network.static.uri": ["https://foo.local/bar", "hxxp:invalid.local/hi"]}
    with caplog.at_level(logging.ERROR):
        result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
        assert result == {
            ("inet:url", "https://foo.local/bar"),
        }
        assert any("AL4 tag value failed parsing" in message for message in caplog.messages)

    # invalid email
    al4_tags = {"network.email.address": ["invalidemail", "test@foo.local"]}
    with caplog.at_level(logging.ERROR):
        result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
        assert result == {
            ("inet:email", "test@foo.local"),
        }
        assert any("AL4 tag value failed parsing" in message for message in caplog.messages)


def test_build_synapse_ndefs_to_query_no_al4tags(synapse_instance):
    """validate when NO al4 tags are passed in"""
    al4_tags = {}
    result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
    assert result == set()

    al4_tags = None
    result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
    assert result == set()


def test_build_synapse_ndefs_to_query_safelisted_tag(synapse_instance):
    """validate that anything in the safelist is filtered out"""
    al4_tags = {"network.static.ip": ["192.168.1.1", "10.0.0.1"]}
    synapse_instance.safelist = {"match": {"network.static.ip": ["192.168.1.1"]}}
    result = synapse_instance._build_synapse_ndefs_to_query(al4_tags)
    assert result == {("inet:ipv4", "10.0.0.1")}
