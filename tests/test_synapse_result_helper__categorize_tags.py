import pytest
from assemblyline_v4_service.common.helper import get_heuristics
from synapse.synapse_result_helper import SynapseResultHelper


@pytest.fixture
def helper_instance():
    heur_map = {
        "1": {"match_any_syn_tag": ["tag1a", "tag1b"]},
        "2": {"match_all_syn_tags": [["tag.all1", "tag.all2"]]},
    }
    service_heuristics = get_heuristics()
    return SynapseResultHelper(heur_map, service_heuristics)


def test_empty_tags(helper_instance):
    """validate when no tags are provided"""
    tags = []
    expected = {"match": [], "other": []}
    result = helper_instance._categorize_tags(tags)
    assert result == expected


def test_single_tag_match(helper_instance):
    """validate when there's a single match"""
    tags = [("tag1a", [None, None])]
    expected = {"match": [("tag1a", [None, None])], "other": []}
    result = helper_instance._categorize_tags(tags)
    assert result == expected


def test_multiple_matches_and_non_matches(helper_instance):
    """validate when there are multiple matches, and non-matches for both ANY and ALL match conditions"""
    tags = [
        ("tag.all1", [None, None]),
        ("tag.all2", [None, None]),
        ("tag1a", [None, None]),
        ("other1", [None, None]),
        ("other2", [None, None]),
    ]
    expected = expected = {
        "match": [
            ("tag.all1", [None, None]),
            ("tag.all2", [None, None]),
            ("tag1a", [None, None]),
        ],
        "other": [("other1", [None, None]), ("other2", [None, None])],
    }
    result = helper_instance._categorize_tags(tags)
    assert result == expected


def test_multiple_matches_are_not_duplicated(helper_instance):
    """validate there are no duplicates tags found in the match category when there are multiple
    conditions that match.

    In this setup, both heur 1 and 2 will match so make sure the "match" and "other" categories
    do not have duplicate tags.
    """
    helper_instance.heur_map = {
        "1": {"match_any_syn_tag": ["tag.all1"]},
        "2": {"match_all_syn_tags": [["tag.all1", "tag.all2"]]},
    }
    tags = [
        ("tag.all1", [None, None]),
        ("tag.all2", [None, None]),
        ("other1", [None, None]),
        ("other2", [None, None]),
    ]
    expected = expected = {
        "match": [
            ("tag.all1", [None, None]),
            ("tag.all2", [None, None]),
        ],
        "other": [("other1", [None, None]), ("other2", [None, None])],
    }
    result = helper_instance._categorize_tags(tags)
    assert result == expected


def test_tags_are_sorted(helper_instance):
    """validate tags in both the matches and other categories are sorted alphabetically"""

    helper_instance.heur_map = {
        "1": {"match_any_syn_tag": ["arep.atag1", "brep.tag1"]},
    }
    tags = [
        ("brep.tag1", [None, None]),
        ("arep.atag1", [None, None]),
        ("rep.btag.test", [None, None]),
        ("zrep.tag.test", [None, None]),
        ("arep.tag.test", [None, None]),
        ("rep.ztag.test", [None, None]),
        ("rep.atag.test", [None, None]),
        ("rep.tag.ztest", [None, None]),
        ("rep.tag.atest", [None, None]),
        ("other1", [None, None]),
        ("other2", [None, None]),
        ("0tag", [1713423947430, 1713423947450]),
        ("9tag", [1113423947430, 1113423947450]),
    ]
    expected = expected = {
        "match": [
            ("arep.atag1", [None, None]),
            ("brep.tag1", [None, None]),
        ],
        "other": [
            ("0tag", [1713423947430, 1713423947450]),
            ("9tag", [1113423947430, 1113423947450]),
            ("arep.tag.test", [None, None]),
            ("other1", [None, None]),
            ("other2", [None, None]),
            ("rep.atag.test", [None, None]),
            ("rep.btag.test", [None, None]),
            ("rep.tag.atest", [None, None]),
            ("rep.tag.ztest", [None, None]),
            ("rep.ztag.test", [None, None]),
            ("zrep.tag.test", [None, None]),
        ],
    }
    result = helper_instance._categorize_tags(tags)
    assert result == expected
