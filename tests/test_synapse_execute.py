import json
from unittest.mock import MagicMock

import pytest
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import ResultTableSection
from synapse.synapse import Synapse


@pytest.fixture
def synapse_instance():
    config = {
        "heur_map": {
            "1": {
                "match_any_syn_tag": ["tag1", "tag2"],
                "match_all_syn_tags": [["tag3", "tag4"]],
            },
            "2": {"match_any_syn_tag": ["tag5"]},
        },
        "syntags_to_filter_node": ["filter1", "filter2"],
        "syntag_prefixes_to_filter": ["prefix1", "prefix2"],
    }
    return Synapse(config=config)


def test_execute_for_flow_finding_synapse_results(synapse_instance):
    """validate results are created properly when there are matches"""
    request = MagicMock(spec=ServiceRequest)
    request.task = MagicMock()
    request.task.tags = {
        "network.static.ip": ["192.168.1.1"],
        "network.static.domain": ["foo.local"],
    }

    synapse_instance._synapse_lookup = MagicMock(
        return_value=[
            (
                ("inet:ipv4", "192.168.1.1"),
                {
                    "props": {
                        ".created": 1718652499667,
                    },
                    "tags": {"tag1": [None, None]},
                },
            ),
            (
                ("inet:fqdn", "foo.local"),
                {
                    "props": {
                        ".created": 1718652499667,
                    },
                    "tags": {"tag5": [None, None], "othertag": [None, None]},
                },
            ),
        ]
    )

    synapse_instance.execute(request)

    assert len(request.result.sections) == 2

    #
    # Validate section/node 1 details
    res = request.result.sections[0]

    assert isinstance(res, ResultTableSection)
    assert res.title_text == "Synapse Node of Interest"
    assert len(res.subsections) == 0
    # print(res.body)
    assert json.loads(res.body) == [
        {
            "node": "inet:ipv4=192.168.1.1",
            "created": "2024/06/17 19:28Z",
            "matching_tags": {"1": "tag1"},
            "other_tags": {},
        }
    ]
    assert res.heuristic.heur_id == 1
    assert res.tags == {
        "network.static.ip": ["192.168.1.1"],
    }

    #
    # Validate section/node 2 details
    res = request.result.sections[1]

    assert isinstance(res, ResultTableSection)
    assert res.title_text == "Synapse Node of Interest"
    assert len(res.subsections) == 0
    # print(res.body)
    assert json.loads(res.body) == [
        {
            "node": "inet:fqdn=foo.local",
            "created": "2024/06/17 19:28Z",
            "matching_tags": {"1": "tag5"},
            "other_tags": {"1": "othertag"},
        }
    ]
    assert res.heuristic.heur_id == 2
    assert res.tags == {
        "network.static.domain": ["foo.local"],
    }


def test_execute_for_when_no_results(synapse_instance):
    """validate results are empty when there are no matches found"""
    request = MagicMock(spec=ServiceRequest)
    request.task = MagicMock()
    request.task.tags = {
        "network.static.ip": ["192.168.1.1"],
        "network.static.domain": ["foo.local"],
    }

    synapse_instance._synapse_lookup = MagicMock(return_value=[])

    synapse_instance.execute(request)

    assert len(request.result.sections) == 0
