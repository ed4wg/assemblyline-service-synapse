from synapse.synapse_result_helper import MatchConditionType, SynapseResultHelper


def test_no_tags_matching():
    cond_tags = ["tag1", "tag2"]
    syn_node_tags = [("tag3", [None, None]), ("tag4", [None, None])]
    is_match, matches = SynapseResultHelper._find_tag_matches(
        MatchConditionType.ANY, cond_tags, syn_node_tags
    )
    assert not is_match
    assert matches == {}


def test_some_tags_matching_any():
    """validate some tags match in an ANY condition match"""
    cond_tags = ["tag1", "tag2"]
    syn_node_tags = [("tag1", [None, None]), ("tag3", [None, None])]
    is_match, matches = SynapseResultHelper._find_tag_matches(
        MatchConditionType.ANY, cond_tags, syn_node_tags
    )
    assert is_match
    assert len(matches) == 1
    assert matches["tag1"] == [("tag1", [None, None])]


def test_all_tags_matching_any():
    """validate all tags match in an ANY condition match"""
    cond_tags = ["tag.1", "tag.2"]
    syn_node_tags = [("tag.1", [None, None]), ("tag.2", [None, None])]
    is_match, matches = SynapseResultHelper._find_tag_matches(
        MatchConditionType.ANY, cond_tags, syn_node_tags
    )
    assert is_match
    assert len(matches) == 2
    assert matches["tag.1"] == [("tag.1", [None, None])]
    assert matches["tag.2"] == [("tag.2", [None, None])]


def test_all_tags_matching_all():
    """validate all tags match in an ALL condition match"""
    cond_tags = ["tag1", "tag2"]
    syn_node_tags = [("tag1", [None, None]), ("tag2", [None, None]), ("tag3", [None, None])]
    is_match, matches = SynapseResultHelper._find_tag_matches(
        MatchConditionType.ALL, cond_tags, syn_node_tags
    )
    assert is_match
    assert len(matches) == 2
    assert matches["tag1"] == [("tag1", [None, None])]
    assert matches["tag2"] == [("tag2", [None, None])]


def test_no_tags_matching_all():
    """validate NO tags match in an ALL condition match"""
    cond_tags = ["tag1", "tag2"]
    syn_node_tags = [("tag4", [None, None]), ("tag5", [None, None])]
    is_match, matches = SynapseResultHelper._find_tag_matches(
        MatchConditionType.ALL, cond_tags, syn_node_tags
    )
    assert not is_match
    assert len(matches) == 0


def test_partial_tags_matching_all():
    """Validate in a partial match of an ALL condition match, there should be NO matches returned"""

    cond_tags = ["tag1", "tag2"]
    syn_node_tags = [("tag1", [None, None]), ("tag5", [None, None])]
    is_match, matches = SynapseResultHelper._find_tag_matches(
        MatchConditionType.ALL, cond_tags, syn_node_tags
    )
    assert not is_match
    assert len(matches) == 0


def test_no_cond_tags():
    """validate when no condition tags present that there are no matches."""
    cond_tags = []
    syn_node_tags = [("tag4", [None, None])]
    is_match, matches = SynapseResultHelper._find_tag_matches(
        MatchConditionType.ANY, cond_tags, syn_node_tags
    )
    assert not is_match
    assert (len(matches)) == 0

    cond_tags = None
    syn_node_tags = [("tag4", [None, None])]
    is_match, matches = SynapseResultHelper._find_tag_matches(
        MatchConditionType.ANY, cond_tags, syn_node_tags
    )
    assert not is_match
    assert (len(matches)) == 0


def test_no_syntags():
    """validate when no syntags are present there are no matches."""
    cond_tags = ["tag1", "tag2"]
    syn_node_tags = []
    is_match, matches = SynapseResultHelper._find_tag_matches(
        MatchConditionType.ANY, cond_tags, syn_node_tags
    )
    assert not is_match
    assert (len(matches)) == 0

    cond_tags = ["tag1", "tag2"]
    syn_node_tags = None
    is_match, matches = SynapseResultHelper._find_tag_matches(
        MatchConditionType.ANY, cond_tags, syn_node_tags
    )
    assert not is_match
    assert (len(matches)) == 0
