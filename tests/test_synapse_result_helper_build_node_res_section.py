import json
import logging

import pytest
from assemblyline_v4_service.common.helper import get_heuristics
from assemblyline_v4_service.common.result import ResultTableSection
from synapse.synapse_result_helper import SynapseResultHelper


@pytest.fixture
def synapse_result_helper():
    heur_map = {
        "1": {"match_any_syn_tag": ["tag1a", "tag1b"]},
        "2": {"match_all_syn_tags": [["tag.all1", "tag.all2"]]},
    }
    service_heuristics = get_heuristics()
    return SynapseResultHelper(heur_map, service_heuristics)


def test_build_node_res_section_with_matches(synapse_result_helper):
    """Validate the resultsection is created properly when there are matches"""
    pnode = (
        ("inet:fqdn", "foo.local"),
        {
            "props": {
                ".created": 1718652499667,
            },
            "tags": {"tag1a": [None, None], "tag": [None, None], "tag.lev2": [None, None]},
        },
    )
    al4_tags = {"network.static.domain": ["foo.local", "bar.local"], "attribution.family": ["fam1"]}
    res = synapse_result_helper.build_node_res_section(pnode, al4_tags)
    assert isinstance(res, ResultTableSection)
    assert res.title_text == "Synapse Node of Interest"
    assert len(res.subsections) == 0
    # print(res.body)
    assert json.loads(res.body) == [
        {
            "node": "inet:fqdn=foo.local",
            "created": "2024/06/17 19:28Z",
            "matching_tags": {"1": "tag1a"},
            "other_tags": {"1": "tag.lev2"},
        }
    ]
    assert res.heuristic.heur_id == 1
    assert res.tags == {
        "network.static.domain": ["foo.local"],
    }


def test_build_node_res_section_with_matches_and_filters(synapse_result_helper):
    """Validate the resultsection is created properly when there are tags to be filtered from the result"""
    pnode = (
        ("inet:fqdn", "foo.local"),
        {
            "props": {
                ".created": 1718652499667,
            },
            "tags": {"tag1a": [None, None], "tag": [None, None], "tag.lev2": [None, None]},
        },
    )
    al4_tags = {"network.static.domain": ["foo.local", "bar.local"], "attribution.family": ["fam1"]}

    # set the filter tags for this test
    synapse_result_helper.syntag_prefixes_to_filter = ["tag.lev2"]

    res = synapse_result_helper.build_node_res_section(pnode, al4_tags)

    assert isinstance(res, ResultTableSection)
    assert res.title_text == "Synapse Node of Interest"
    assert len(res.subsections) == 0
    # print(res.body)
    assert json.loads(res.body) == [
        {
            "node": "inet:fqdn=foo.local",
            "created": "2024/06/17 19:28Z",
            "matching_tags": {"1": "tag1a"},
            "other_tags": {},
        }
    ]
    assert res.heuristic.heur_id == 1
    assert res.tags == {
        "network.static.domain": ["foo.local"],
    }


def test_build_node_res_section_with_no_matching_heuristic(synapse_result_helper, caplog):
    """Validate a warning is logged when there is no heuristic found.

    Note: A heuristic should always be found unless there's a bug or edge case not accounted for.
    """
    pnode = (
        ("inet:fqdn", "foo.local"),
        {
            "props": {
                ".created": 1718652499667,
            },
            "tags": {"nomatch": [None, None]},
        },
    )
    al4_tags = {"network.static.domain": ["foo.local"]}

    with caplog.at_level(logging.WARNING):
        res = synapse_result_helper.build_node_res_section(pnode, al4_tags)

    assert isinstance(res, ResultTableSection)
    assert res.title_text == "Synapse Node of Interest"
    assert len(res.subsections) == 0
    # print(res.body)
    assert json.loads(res.body) == [
        {
            "node": "inet:fqdn=foo.local",
            "created": "2024/06/17 19:28Z",
            "matching_tags": {},
            "other_tags": {"1": "nomatch"},
        }
    ]
    assert res.heuristic is None
    assert res.tags == {
        "network.static.domain": ["foo.local"],
    }

    # Validate warning log
    assert any("No heuristic found for node" in message for message in caplog.messages)


def test_build_node_res_section_with_no_matching_al4tag(synapse_result_helper, caplog):
    """Validate a warning is logged when there is no matching al4 tag found.

    Note: A matching al4 tag should always be found unless there's a bug or edge case not accounted for.
    """
    pnode = (
        ("inet:fqdn", "foo.local"),
        {
            "props": {
                ".created": 1718652499667,
            },
            "tags": {"tag1b": [None, None]},
        },
    )
    al4_tags = {"network.static.domain": ["nomatch"]}

    with caplog.at_level(logging.WARNING):
        res = synapse_result_helper.build_node_res_section(pnode, al4_tags)

    assert isinstance(res, ResultTableSection)
    assert res.title_text == "Synapse Node of Interest"
    assert len(res.subsections) == 0
    # print(res.body)
    assert json.loads(res.body) == [
        {
            "node": "inet:fqdn=foo.local",
            "created": "2024/06/17 19:28Z",
            "matching_tags": {"1": "tag1b"},
            "other_tags": {},
        }
    ]
    assert res.heuristic.heur_id == 1
    assert res.tags == {}

    # Validate warning log
    assert any("No AL4 tags found for node" in message for message in caplog.messages)


def test_build_node_res_section_with_invalid_pnode_arg(synapse_result_helper):
    """Validate a ValueError is raised when the pnode arg is invalid"""
    al4_tags = {"network.static.domain": ["foo.local", "bar.local"]}

    # Test with null val
    pnode = None
    with pytest.raises(ValueError, match="Invalid Synapse pnode arg:"):
        synapse_result_helper.build_node_res_section(pnode, al4_tags)

    # test with empty tuple
    pnode = tuple()
    with pytest.raises(ValueError, match="Invalid Synapse pnode arg:"):
        synapse_result_helper.build_node_res_section(pnode, al4_tags)

    # test with non tuple
    pnode = "invalid"
    with pytest.raises(ValueError, match="Invalid Synapse pnode arg:"):
        synapse_result_helper.build_node_res_section(pnode, al4_tags)


def test_build_node_res_section_with_invalid_al4tags_arg(synapse_result_helper):
    """Validate a ValueError is raised when the al4_tags arg is invalid"""
    pnode = (
        ("inet:fqdn", "foo.local"),
        {
            "props": {
                ".created": 1718652499667,
            },
            "tags": {"tag1a": [None, None]},
        },
    )

    # Test with null val
    al4_tags = None
    with pytest.raises(ValueError, match="Invalid AL4 tags arg"):
        synapse_result_helper.build_node_res_section(pnode, al4_tags)

    # test with empty tuple
    al4_tags = {}
    with pytest.raises(ValueError, match="Invalid AL4 tags arg"):
        synapse_result_helper.build_node_res_section(pnode, al4_tags)

    # test with non tuple
    al4_tags = "invalid"
    with pytest.raises(ValueError, match="Invalid AL4 tags arg"):
        synapse_result_helper.build_node_res_section(pnode, al4_tags)


def test_build_node_res_section_does_not_display_tag_ival(synapse_result_helper):
    """Validate the resultsection does not display the tag ival"""
    pnode = (
        ("inet:fqdn", "foo.local"),
        {
            "props": {
                ".created": 1718652499667,
            },
            "tags": {
                "tag1a": [1730073600000, 1730419200000],
                "tag": [None, None],
                "tag.lev2": [None, None],
            },
        },
    )
    al4_tags = {"network.static.domain": ["foo.local", "bar.local"], "attribution.family": ["fam1"]}
    res = synapse_result_helper.build_node_res_section(pnode, al4_tags)

    # print(res.body)
    assert json.loads(res.body) == [
        {
            "node": "inet:fqdn=foo.local",
            "created": "2024/06/17 19:28Z",
            "matching_tags": {"1": "tag1a"},
            "other_tags": {"1": "tag.lev2"},
        }
    ]
