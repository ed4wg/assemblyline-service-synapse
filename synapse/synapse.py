"""Synapse AL4 Service."""

import json
import re
from collections.abc import Iterator
from typing import Any

import requests
from assemblyline.common import forge  # type: ignore
from assemblyline.odm.base import (
    IP,
    IPV4_ONLY_REGEX,
    IPV6_ONLY_REGEX,
    URI,
    Domain,
    Email,
)
from assemblyline_service_utilities.common.safelist_helper import is_tag_safelisted
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase  # type: ignore
from assemblyline_v4_service.common.helper import get_heuristics
from assemblyline_v4_service.common.request import ServiceRequest  # type: ignore
from assemblyline_v4_service.common.result import Result

from .synapse_result_helper import SynapseResultHelper

Classification = forge.get_classification()

SERVICE_NAME = "SYNAPSE"

RE_IPV6_ONLY_REGEX = re.compile(IPV6_ONLY_REGEX)
RE_IPV4_ONLY_REGEX = re.compile(IPV4_ONLY_REGEX)

# This is the full list of allowed tags that can be configured via the config.al4_tag_types
SUPPORTED_AL4_TAG_TYPES = [
    "network.static.ip",
    "network.dynamic.ip",
    "network.static.domain",
    "network.dynamic.domain",
    "network.static.uri",
    "network.dynamic.uri",
    "network.email.address",
]


class InvalidConfigurationException(Exception):
    """Exception class for an invalid service configuration."""


class Synapse(ServiceBase):
    """Synapse AL4 service."""

    def __init__(self, config: dict) -> None:
        """Configure service instance."""
        super().__init__(config)

        self.syn_api_key = self.config.get("synapse_api_key")
        self.syn_host = self.config.get("synapse_host")
        self.syn_view_iden = self.config.get("storm_opts", {}).get("synapse_view_iden")
        self.max_nodes_per_query = self.config.get("max_nodes_per_query", 50)
        self.heur_map: dict[str, dict[str, list[Any]]] = self.config.get("heur_map")
        self.syntags_to_filter_node: list[str] = self.config.get("syntags_to_filter_node")
        self.service_heuristics = get_heuristics()

        self.safelist = {}
        try:
            self.safelist = self.get_api_interface().get_safelist()
        except ServiceAPIError:
            self.log.exception(
                "Could not retrieve safelist from service: %s. Continuing without it.",
                self.service_attributes.name,
            )

    def start(self) -> None:
        """Invoke once as the service instance starts."""
        self._validate_config()

    def execute(self, request: ServiceRequest) -> None:
        """Execute for each file being analyzed.

        This will query Synapse based on all AL4 tags of interest configured for this service and
        generate a result section for each worthy result.

        Args:
            request (ServiceRequest): AL4 ServiceRequest object
        """
        self.log.info("Processing file: %s", request.sha256)
        request.result = Result()

        res_helper = SynapseResultHelper(
            heur_map=self.heur_map,
            service_heuristics=self.service_heuristics,
            syntag_prefixes_to_filter=self.config.get("syntag_prefixes_to_filter", []),
        )

        syn_ndefs = self._build_synapse_ndefs_to_query(request.task.tags)

        for pnode in self._synapse_lookup(syn_ndefs):

            if res := res_helper.build_node_res_section(pnode=pnode, al4_tags=request.task.tags):
                request.result.add_section(res)

    def _build_syn_queries(
        self, syn_ndefs: set[tuple[str, str]], chunk_size: int = 50
    ) -> list[str]:
        """Build Synapse a chunked list of Synapse queries based on Synapse node defs.

        Args:
            syn_ndefs (set[tuple[str, str]]): A set of synapse node defs.
                Each node def is a tuple (synapse-form, value)
            chunk_size (int, optional): Number of nodes to query with a single query.

        Returns:
            list[str]: list of Synapse Storm queries
        """
        match_all_syn_tag_sets: list[set] = []
        match_any_syn_tags = {
            tag_prefix
            for cond_cfg in self.heur_map.values()
            for tag_prefix in cond_cfg.get("match_any_syn_tag", [])
        }

        match_all_syn_tag_sets = [
            tag_prefix_list
            for cond_cfg in self.heur_map.values()
            for tag_prefix_list in cond_cfg.get("match_all_syn_tags", [])
        ]

        queries = []
        ndefs = sorted(syn_ndefs)  # Sort the set to ensure consistent order

        # create multiple queries based on the chunk size.
        # Synapse will error if you try to cram too many nodes in a single query. It should
        # definitely be under 1000 nodes per query.
        for chunk in [ndefs[x : x + chunk_size] for x in range(0, len(ndefs), chunk_size)]:
            query = " ".join(f'{syn_node_typ}="{ind}"' for syn_node_typ, ind in chunk)

            #
            # include nodes with these tag conditions
            if match_any_syn_tags or match_all_syn_tag_sets:
                query += " +("

                # syntags with OR conditions
                query += " or ".join(
                    f"#{syntag_prefix}" for syntag_prefix in sorted(match_any_syn_tags)
                )

                # syntags with AND conditions
                for tag_set in match_all_syn_tag_sets:
                    query += " or ("
                    query += " and ".join(f"#{syntag_prefix}" for syntag_prefix in tag_set)
                    query += ")"

                query += ")"

            #
            # remove nodes with these filter tags
            if self.syntags_to_filter_node:
                query += " -("
                query += " or ".join(
                    f"#{filter_tag}" for filter_tag in self.syntags_to_filter_node or []
                )
                query += ")"

            queries.append(query)

        self.log.debug("Synapse queries to execute: %s", queries)
        return queries

    def _build_synapse_ndefs_to_query(self, al4_tags: dict) -> set[tuple[str, str]]:
        """Build a set of Synapse node defs to query based on the AL4 tags.

        Args:
            al4_tags (dict): AL4 tags to build Synapse node defs for.
                {"network.static.domain": ["foo.local", "bar.local"],}

        Raises:
            InvalidConfigurationException: An al4 tag type was specified in the config that is not
            supported by this service.

        Returns:
            set[tuple[str, str]]: A set of Synapse node defs to query. set((form,value),)
        """
        # Note: When an AL4 tag is added to an AL4 result, the value must conform to the tag type.
        #  e.g. if you try to add an AL4 tag type of network.static.ip with a non-ip value, it will
        #  not be created. Therefore, these node defs should generally be Synapse friendly.
        #   <syn-form>=<al4-tag-value>
        # However, this will still run validation to prevent sending invalid values to Synapse.
        syn_ndefs: set[tuple[str, str]] = set()

        for al4_tag_type in self.config.get("al4_tag_types", []):
            for al4_tag_val in al4_tags.get(al4_tag_type, []) if al4_tags else []:

                # do not consider AL4 safelisted tags
                if is_tag_safelisted(al4_tag_val, [al4_tag_type], self.safelist):
                    continue

                try:
                    match al4_tag_type:
                        case "network.static.ip" | "network.dynamic.ip":
                            # strip port info if present for an ipv4 address
                            if ":" in al4_tag_val and len(al4_tag_val.split(".")) == 4:
                                al4_tag_val = al4_tag_val.split(":")[0]
                            val = IP().check(al4_tag_val)
                            syn_form = Synapse._get_syn_form_for_ip(val)
                            if not syn_form:
                                raise ValueError(
                                    f"Unable to determine Synapse form for IP address: {al4_tag_type} : {al4_tag_val}"
                                )
                            syn_ndefs.add((syn_form, val))

                        case "network.static.domain" | "network.dynamic.domain":
                            syn_ndefs.add(("inet:fqdn", Domain().check(al4_tag_val)))

                        case "network.static.uri" | "network.dynamic.uri":
                            syn_ndefs.add(("inet:url", URI().check(al4_tag_val)))

                        case "network.email.address":
                            syn_ndefs.add(("inet:email", Email().check(al4_tag_val)))

                        case _:
                            raise InvalidConfigurationException(
                                f"al4 tag type specified in configuration cannot be queried: {al4_tag_type}"
                            )
                except ValueError:
                    # log and continue on
                    self.log.error(
                        "AL4 tag value failed parsing: %s : %s", al4_tag_type, al4_tag_val
                    )

        return syn_ndefs

    def _synapse_lookup(self, syn_ndefs: set[tuple[str, str]]) -> Iterator[tuple[tuple, dict]]:
        """Call Synapse to query for the specified nodes.

        Args:
            syn_ndefs (set[tuple[str, str]]): A set of synapse node defs.
                Each node def is a tuple (synapse-form, value)

        Yields:
            Iterator[tuple[tuple, dict]]: Yields each synapse node in packed node form.
                (node_def_tuple, node_vals)
                (
                    ('inet:fqdn', 'foo.local'),
                    {
                        'iden': 'b2bcabf552c8f096dfb66959cfc025f1ea2c5e4b22e1998bd47674e1b9b45da1',
                        'tags': {'rep': [None, None], 'rep.vendorx': [None, None]},
                        'props': {'.created': 1718652499666, 'host': 'foo', 'domain': 'local', 'issuffix': 0, 'iszone': 1, 'zone': 'foo.local'},
                        'tagprops': {},
                        'nodedata': {},
                        'reprs': {'.created': '2024/06/17 19:28:19.666', 'issuffix': 'false', 'iszone': 'true'},
                        'tagpropreprs': {},
                        'path': {}
                    }
                )
        """
        headers = {
            "X-API-KEY": self.syn_api_key,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        url = f"https://{self.syn_host}/api/v1/storm"

        queries: list[str] = self._build_syn_queries(syn_ndefs, chunk_size=self.max_nodes_per_query)

        storm_opts = {
            "repr": True,
            "keepalive": 5,
            "readonly": True,  # enforce read-only
        }
        if self.syn_view_iden:
            storm_opts["view"] = self.syn_view_iden

        for query in queries:
            data = {"query": query, "opts": storm_opts, "stream": "jsonlines"}

            with requests.get(url, json=data, headers=headers, stream=True, timeout=30) as response:
                for line in response.iter_lines(decode_unicode=True):
                    if line:
                        mesg = json.loads(line)

                        if mesg[0] == "node":
                            # yield one packed node at a time
                            yield tuple([tuple(mesg[1][0]), mesg[1][1]])
                        elif mesg[0] == "err":
                            # Note on Synapse storm query/response behavior:
                            #  Take the following query with an invalid value on the second item
                            #    inet:fqdn=test.local inet:ipv4=::1 inet:fqdn=foo.local
                            #  the first node in the query will still be streamed back and
                            #  processed (inet:fqdn) prior to the error. Once Synapse encounters
                            #  the errant node=valu, the streaming will stop even if there are
                            #  other valid nodes being queried after the errant part of the
                            #  query.

                            # This is likely a bad form=value query due to an unexpected al4 tag
                            #  value or system configuration issue.
                            self.log.error(
                                "Storm Query errored. Node results likely dropped: error: %s, storm-query: %s",
                                mesg[1],
                                query,
                            )

    def _validate_config(self) -> bool:
        """Validate the service configuration.

        Raises:
            InvalidConfigurationException: raises for any invalid configuration found

        Returns:
            bool: Whether config is valid
        """
        if not self.config.get("synapse_api_key"):
            raise InvalidConfigurationException("synapse_api_key is required in the configuration")

        if not self.config.get("synapse_host"):
            raise InvalidConfigurationException("synapse_host is required in the configuration")

        #
        # al4_tag_types validation
        al4_tag_types_cfg = self.config.get("al4_tag_types")
        if not al4_tag_types_cfg:
            raise InvalidConfigurationException(
                "al4_tag_types is required in the configuration and must be a list of AL4 tag types."
            )
        ## must be a list and in the list of supported AL4 tag types
        if not isinstance(al4_tag_types_cfg, list) or not all(
            x in SUPPORTED_AL4_TAG_TYPES for x in al4_tag_types_cfg
        ):
            raise InvalidConfigurationException(
                f"al4_tag_types must be a list and in the list of supported AL4 tag types: {SUPPORTED_AL4_TAG_TYPES}"
            )

        #
        # heur_map validation
        heur_map = self.config.get("heur_map")
        if heur_map is None:
            raise InvalidConfigurationException("heur_map is required in the configuration")
        ##  must be a dict
        if not isinstance(heur_map, dict):
            raise InvalidConfigurationException("heur_map must be a dict")

        ## keys must be a number that can map to a heuristic id
        if not all(heur.isdigit() for heur in heur_map):
            raise InvalidConfigurationException("heur_map keys must be numeric")

        ## keys must be a heuristic id represented in the service heuristics
        if not all(int(heur) in self.service_heuristics for heur in heur_map):
            raise InvalidConfigurationException(
                "heur_map keys must be heuristic ids represented in the service defined heuristics"
            )

        for cond_cfg in heur_map.values():

            ##  must have at least one condition
            if not cond_cfg:
                raise InvalidConfigurationException(
                    "heur_map heuristic must have at least one condition"
                )

            ##  must have at least one condition and the keys match_any_syn_tag and/or match_all_syn_tags
            if not all(cond in ("match_any_syn_tag", "match_all_syn_tags") for cond in cond_cfg):
                raise InvalidConfigurationException(
                    "heur_map heuristic conditions must have a key of match_any_syn_tag and/or match_all_syn_tags"
                )

            ## the match_all_syn_tags key must be a list of lists
            cfg = cond_cfg.get("match_all_syn_tags")
            if cfg:
                if not isinstance(cfg, list) or not all(isinstance(x, list) for x in cfg):
                    raise InvalidConfigurationException(
                        "heur_map heuristic conditions match_all_syn_tags must be a list of lists"
                    )

            ## the match_any_syn_tag key must be a list of strings
            cfg = cond_cfg.get("match_any_syn_tag")
            if cfg:
                if not isinstance(cfg, list) or not all(isinstance(x, str) for x in cfg):
                    raise InvalidConfigurationException(
                        "heur_map heuristic conditions match_any_syn_tag must be a list of strings"
                    )

        #
        # syntags_to_filter_node validation
        syntags_to_filter_node = self.config.get("syntags_to_filter_node")
        if not isinstance(syntags_to_filter_node, list) or not all(
            isinstance(x, str) for x in syntags_to_filter_node
        ):
            raise InvalidConfigurationException(
                "syntags_to_filter_node must be a list of Synapse tag filters"
            )

        #
        # syntag_prefixes_to_filter validation
        syntag_prefixes_to_filter = self.config.get("syntag_prefixes_to_filter")
        if not isinstance(syntag_prefixes_to_filter, list) or not all(
            isinstance(x, str) for x in syntag_prefixes_to_filter
        ):
            raise InvalidConfigurationException(
                "syntag_prefixes_to_filter must be a list of Synapse tag prefixes"
            )

        return True

    @staticmethod
    def _get_syn_form_for_ip(ip: str) -> str | None:
        """Get the proper Synapse form for the given IP address.

        Args:
            ip (str): ipv4 or ipv6 address

        Returns:
            str | None: Synapse inet:ipv4|6 form.
        """
        if not ip:
            return None
        if RE_IPV4_ONLY_REGEX.match(ip):
            return "inet:ipv4"
        elif RE_IPV6_ONLY_REGEX.match(ip):
            return "inet:ipv6"
        else:
            return None
