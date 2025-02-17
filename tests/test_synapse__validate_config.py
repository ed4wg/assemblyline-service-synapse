import pytest
from synapse.synapse import InvalidConfigurationException, Synapse


@pytest.fixture
def synapse_instance():

    config = {
        "synapse_api_key": "api_key",
        "synapse_host": "localhost",
        "max_nodes_per_query": 50,
        "al4_tag_types": ["network.static.ip", "network.static.domain"],
        "heur_map": {
            "1": {"match_any_syn_tag": ["tag1a", "tag1b"]},
            "2": {"match_all_syn_tags": [["tag2a", "tag2b"]]},
        },
        "syntags_to_filter_node": ["filter.node.with.tag1", "filter2"],
        "syntag_prefixes_to_filter": ["filter.prefix1"],
    }

    return Synapse(config=config)


def test_validate_config_all_proper(synapse_instance):
    assert synapse_instance._validate_config()


def test_validate_config_missing_synapse_api_key(synapse_instance):
    del synapse_instance.config["synapse_api_key"]
    with pytest.raises(
        InvalidConfigurationException, match="synapse_api_key is required in the configuration"
    ):
        synapse_instance._validate_config()


def test_validate_config_missing_synapse_host(synapse_instance):
    del synapse_instance.config["synapse_host"]
    with pytest.raises(
        InvalidConfigurationException, match="synapse_host is required in the configuration"
    ):
        synapse_instance._validate_config()


def test_validate_config_missing_max_nodes(synapse_instance):
    del synapse_instance.config["max_nodes_per_query"]
    assert synapse_instance.max_nodes_per_query == 50


def test_validate_config_al4_tag_types(synapse_instance):
    del synapse_instance.config["al4_tag_types"]
    with pytest.raises(
        InvalidConfigurationException,
        match="al4_tag_types is required in the configuration and must be a list of AL4 tag types",
    ):
        synapse_instance._validate_config()


def test_validate_config_invalid_al4_tag_types(synapse_instance):
    synapse_instance.config["al4_tag_types"].append("invalid")
    with pytest.raises(
        InvalidConfigurationException,
        match="al4_tag_types must be a list and in the list of supported AL4 tag types",
    ):
        synapse_instance._validate_config()

    synapse_instance.config["al4_tag_types"] = "invalid"
    with pytest.raises(
        InvalidConfigurationException,
        match="al4_tag_types must be a list and in the list of supported AL4 tag types",
    ):
        synapse_instance._validate_config()


def test_validate_config_missing_heur_map(synapse_instance):
    del synapse_instance.config["heur_map"]
    with pytest.raises(
        InvalidConfigurationException, match="heur_map is required in the configuration"
    ):
        synapse_instance._validate_config()


def test_validate_config_invalid_heur_map(synapse_instance):
    synapse_instance.config["heur_map"] = "invalid"
    with pytest.raises(InvalidConfigurationException, match="heur_map must be a dict"):
        synapse_instance._validate_config()


def test_validate_config_invalid_heur_map_keys(synapse_instance):
    synapse_instance.config["heur_map"] = {"invalid": {}}
    with pytest.raises(
        InvalidConfigurationException,
        match="heur_map keys must be numeric",
    ):
        synapse_instance._validate_config()

    synapse_instance.config["heur_map"] = {"99": {}}
    with pytest.raises(
        InvalidConfigurationException,
        match="heur_map keys must be heuristic ids represented in the service defined heuristics",
    ):
        synapse_instance._validate_config()


def test_validate_config_invalid_heur_map_conditions(synapse_instance):
    # no conditions for a given heuristic
    synapse_instance.config["heur_map"] = {"1": {}}
    with pytest.raises(
        InvalidConfigurationException,
        match="heur_map heuristic must have at least one condition",
    ):
        synapse_instance._validate_config()

    # incorrect condition key for a given heuristic
    synapse_instance.config["heur_map"] = {"1": {"invalid": ["tag1"]}}
    with pytest.raises(
        InvalidConfigurationException,
        match="heur_map heuristic conditions must have a key of match_any_syn_tag and/or match_all_syn_tags",
    ):
        synapse_instance._validate_config()

    # one correct, and one incorrect condition key
    synapse_instance.config["heur_map"] = {
        "1": {"match_any_syn_tag": ["tag1"], "invalid": ["tag2"]}
    }
    with pytest.raises(
        InvalidConfigurationException,
        match="heur_map heuristic conditions must have a key of match_any_syn_tag and/or match_all_syn_tags",
    ):
        synapse_instance._validate_config()

    # the match_all_syn_tags key must be a list of lists
    synapse_instance.config["heur_map"] = {"1": {"match_all_syn_tags": ["not-a-list-of-lists"]}}
    with pytest.raises(
        InvalidConfigurationException,
        match="heur_map heuristic conditions match_all_syn_tags must be a list of lists",
    ):
        synapse_instance._validate_config()

    # the match_any_syn_tag key must be a list of strings
    synapse_instance.config["heur_map"] = {"1": {"match_any_syn_tag": "not-a-list"}}
    with pytest.raises(
        InvalidConfigurationException,
        match="heur_map heuristic conditions match_any_syn_tag must be a list of strings",
    ):
        synapse_instance._validate_config()


def test_validate_config_invalid_syntags_to_filter_node(synapse_instance):
    synapse_instance.config["syntags_to_filter_node"] = "invalid"
    with pytest.raises(
        InvalidConfigurationException,
        match="syntags_to_filter_node must be a list of Synapse tag filters",
    ):
        synapse_instance._validate_config()

    synapse_instance.config["syntags_to_filter_node"] = ["test", 5]
    with pytest.raises(
        InvalidConfigurationException,
        match="syntags_to_filter_node must be a list of Synapse tag filters",
    ):
        synapse_instance._validate_config()


def test_validate_config_invalid_syntag_prefixes_to_filter(synapse_instance):
    synapse_instance.config["syntag_prefixes_to_filter"] = "invalid"
    with pytest.raises(
        InvalidConfigurationException,
        match="syntag_prefixes_to_filter must be a list of Synapse tag prefixes",
    ):
        synapse_instance._validate_config()

    synapse_instance.config["syntag_prefixes_to_filter"] = ["test", 5]
    with pytest.raises(
        InvalidConfigurationException,
        match="syntag_prefixes_to_filter must be a list of Synapse tag prefixes",
    ):
        synapse_instance._validate_config()
