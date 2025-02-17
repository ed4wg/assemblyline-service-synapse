import pytest
from assemblyline_v4_service.common.helper import get_heuristics
from synapse.synapse_result_helper import SynapseResultHelper


@pytest.fixture
def helper_instance():
    heur_map = {
        "1": {"match_any_syn_tag": ["tag1a", "tag1b"]},
        "2": {"match_all_syn_tags": [["tag2a", "tag2b"]]},
        "3": {"match_all_syn_tags": [["tag3a", "tag3b"], ["tag3c", "tag3d"]]},
        "4": {
            "match_any_syn_tag": ["tag4.a", "tag4.b"],
            "match_all_syn_tags": [
                ["tag4.c", "tag4.d"],
            ],
        },
    }
    service_heuristics = get_heuristics()
    return SynapseResultHelper(heur_map, service_heuristics)


def test_no_tags_match(helper_instance):
    """validate no heur is selected when there is not a tag match"""
    syn_node_tags = [("nomatch1", [None, None]), ("nomatch2", [None, None])]
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic is None


def test_no_tags_specified(helper_instance):
    """validate no heur is selected when there are no syntags specified"""
    syn_node_tags = []
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic is None


def test_match_any_syn_tag(helper_instance):
    """validate that heur 1 is selected for this tag combo"""
    syn_node_tags = [("tag1a", [None, None]), ("nomatch1", [None, None])]
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic.heur_id == "1"


def test_match_all_syn_tags(helper_instance):
    """validate heur 2 is selected for this tag combo"""
    syn_node_tags = [("tag2a", [None, None]), ("tag2b", [None, None])]
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic.heur_id == "2"

    syn_node_tags = [("tag3c", [None, None]), ("tag3d", [None, None])]
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic.heur_id == "3"


def test_match_any_and_all_syn_tags(helper_instance):
    """Test where multiple configuration conditions exist: both ANY and ALL conditions"""
    syn_node_tags = [
        ("tag4.a", [None, None]),
    ]
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic.heur_id == "4"

    syn_node_tags = [
        ("tag4.c", [None, None]),
        ("tag4.d", [None, None]),
    ]
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic.heur_id == "4"

    syn_node_tags = [
        ("tag4.a", [None, None]),
        ("tag4.c", [None, None]),
        ("tag4.d", [None, None]),
    ]
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic.heur_id == "4"

    syn_node_tags = [
        ("tag4.c", [None, None]),
    ]
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic is None


def test_highest_scoring_heuristic(helper_instance):
    """validate when there are multiple matches that the highest scoring heur is selected"""
    syn_node_tags = [
        ("tag1a", [None, None]),
        ("tag2a", [None, None]),
        ("tag2b", [None, None]),
        ("tag4.a", [None, None]),
    ]
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic.heur_id == "4"

    # change up the order and make sure it still works
    syn_node_tags = [
        ("tag4.c", [None, None]),
        ("tag4.d", [None, None]),
        ("tag1a", [None, None]),
        ("tag1b", [None, None]),
    ]
    heuristic = helper_instance._get_heuristic_from_tags(syn_node_tags)
    assert heuristic.heur_id == "4"


def test_when_no_heuristics_mapped():
    """validate when no heuristics are mapped in the config, that none are selected"""
    heur_map = {}
    service_heuristics = get_heuristics()
    helper = SynapseResultHelper(heur_map, service_heuristics)

    syn_node_tags = [
        ("tag1a", [None, None]),
    ]
    heuristic = helper._get_heuristic_from_tags(syn_node_tags)
    assert heuristic is None


def test_raises_valueerror_for_invalid_heur_mapping():
    """Validate a ValueError exception is raised when the heuristic mapping is invalid"""
    # There is no heuristic with the ID of "90"
    heur_map = {
        "90": {"match_any_syn_tag": ["tag1"]},
    }
    service_heuristics = get_heuristics()
    helper = SynapseResultHelper(heur_map, service_heuristics)

    syn_node_tags = [
        ("tag1", [None, None]),
    ]
    with pytest.raises(
        ValueError,
        match="Invalid configuration. The heuristic defined in the configuration is not found in the available list of heuristics.",
    ):
        helper._get_heuristic_from_tags(syn_node_tags)
