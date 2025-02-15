import pytest

from synapse.synapse_result_helper import SynapseResultHelper


@pytest.fixture
def helper_instance():
    heur_map = {}
    syntag_prefixes_to_filter = ["filter1", "filter.sub2"]
    service_heuristics = {}
    return SynapseResultHelper(heur_map, service_heuristics, syntag_prefixes_to_filter)


def test_no_tags_to_filter(helper_instance):
    """validate that no tags are filtered"""
    syn_tags = [("tag1", [None, None]), ("tag2", [None, None])]
    filtered_tags = helper_instance._filter_tags(syn_tags)
    assert filtered_tags == syn_tags


def test_some_tags_to_filter(helper_instance):
    """validate that only the tags that match the filter are removed"""
    syn_tags = [("filter1", [None, None]), ("tag2", [None, None])]
    filtered_tags = helper_instance._filter_tags(syn_tags)
    # print("filtered_tags: ", filtered_tags)
    assert filtered_tags == [("tag2", [None, None])]


def test_all_tags_to_filter(helper_instance):
    """validate that all tags are removed"""
    syn_tags = [("filter1", [None, None]), ("filter.sub2", [None, None])]
    filtered_tags = helper_instance._filter_tags(syn_tags)
    assert filtered_tags == []


def test_empty_tags_list(helper_instance):
    """validate when no tags are passed in"""
    syn_tags = []
    filtered_tags = helper_instance._filter_tags(syn_tags)
    assert filtered_tags == []


def test_no_filter_tags(helper_instance):
    """validate when no filter tags are configured"""
    syn_tags = []

    helper_instance.syntag_prefixes_to_filter = []
    syn_tags = [("tag1", [None, None]), ("tag2", [None, None])]
    filtered_tags = helper_instance._filter_tags(syn_tags)
    assert filtered_tags == syn_tags
