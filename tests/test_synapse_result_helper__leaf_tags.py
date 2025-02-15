from synapse.synapse_result_helper import SynapseResultHelper


def test_only_leaf_tags_returned():
    """validate that only the leaf tags are returned."""

    # Test only expected tags are returned
    syn_tagsd = {
        "tag": [None, None],
        "tag.lev2": [None, None],
        "tag.lev2.lev3": [None, None],
        "root": [None, None],
        "root.lev2": [None, None],
        "root2": [None, None],
        "root2.lev2": [None, None],
        "root2.lev2.lev3": [None, None],
        "root2.lev2.lev3.lev4": [None, None],
    }
    leaf_tags = SynapseResultHelper._leaf_tags(syn_tagsd)
    assert len(leaf_tags) == 3
    assert ("tag.lev2.lev3", [None, None]) in leaf_tags
    assert ("root.lev2", [None, None]) in leaf_tags
    assert ("root2.lev2.lev3.lev4", [None, None]) in leaf_tags


def test_empty_list_returned():
    """validate that an empty list is returned if no tags sent."""

    # validate empty list returned when empty dict passed in
    syn_tagsd = {}
    leaf_tags = SynapseResultHelper._leaf_tags(syn_tagsd)
    assert len(leaf_tags) == 0

    # validate emmpty list returned when None passed in
    syn_tagsd = None
    leaf_tags = SynapseResultHelper._leaf_tags(syn_tagsd)
    assert len(leaf_tags) == 0
