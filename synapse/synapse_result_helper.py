"""Synapse Results Generation module."""

from datetime import datetime
from enum import Enum, auto
from logging import getLogger
from typing import Any

from assemblyline.common import log as al_log
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline_v4_service.common.result import (
    ResultTableSection,
    TableRow,
)

al_log.init_logging("service.synapse.synapse_result")
log = getLogger("assemblyline.service.synapse.synapse_result")


class MatchConditionType(Enum):
    """Enum to represent the match condition type."""

    ALL = auto()
    ANY = auto()


class SynapseResultHelper:
    """Class to create service results for Synapse."""

    def __init__(
        self,
        heur_map: dict[str, dict[str, list[Any]]],
        service_heuristics: dict[str | int, Heuristic],
        syntag_prefixes_to_filter: list[str] | None = None,
    ):
        """Initialize the SynapseResultHelper.

        Args:
            heur_map (dict[str, dict[str, list[Any]]], optional): heuristic id conditions config.
            syntag_prefixes_to_filter (list[str], optional): Synapse tags to filter from the result.
            service_heuristics (dict[str  |  int, Heuristic], optional): Service heuristics for this service.
        """
        self.heur_map = heur_map
        self.service_heuristics = service_heuristics
        self.syntag_prefixes_to_filter = (
            syntag_prefixes_to_filter if syntag_prefixes_to_filter else []
        )

    def build_node_res_section(
        self, pnode: tuple[tuple, dict], al4_tags: dict[str, list[str]]
    ) -> ResultTableSection | None:
        """Generate a ResultTableSection for the specified Synapse node.

        Args:
            pnode (tuple[tuple, dict]): A Synapse packed node tuple. (node_def_tuple, node_vals)
            al4_tags (dict[str, list[str]]): All AL4 tags associated with this service request.

        Raises:
            ValueError: For any invalid args passed in.

        Returns:
            ResultTableSection | None: A result object containing the relevant node information, tags, and
                heuristics.
        """
        if not pnode or not isinstance(pnode, tuple):
            raise ValueError(f"Invalid Synapse pnode arg: {pnode}")

        if not al4_tags or not isinstance(al4_tags, dict):
            # If getting to this point in the flow, there must be al4 tags involved, or the Synapse
            # node would not have been found to begin with..
            raise ValueError(f"Invalid AL4 tags arg: {al4_tags}")

        res = ResultTableSection("Synapse Node of Interest")

        ndef = pnode[0]
        nval = pnode[1]
        leaf_tags = SynapseResultHelper._leaf_tags(nval.get("tags", {}))
        syn_tags = self._filter_tags(leaf_tags)
        cat_syn_tags = self._categorize_tags(syn_tags)

        match_tagsd = {}
        cnt = 1
        for tag in cat_syn_tags["match"]:
            match_tagsd[cnt] = tag[0]
            cnt += 1

        other_tagsd = {}
        cnt = 1
        for tag in cat_syn_tags["other"]:
            other_tagsd[cnt] = tag[0]
            cnt += 1

        res.add_row(
            TableRow(
                node=f"{ndef[0]}={nval.get('repr', ndef[1])}",
                created=datetime.fromtimestamp(
                    int(nval.get("props", {}).get(".created", 0)) / 1000
                ).strftime("%Y/%m/%d %H:%MZ"),
                matching_tags=match_tagsd,
                other_tags=other_tagsd,
            )
        )

        if heur := self._get_heuristic_from_tags(syn_tags):
            res.set_heuristic(int(heur.heur_id))
        else:
            # This likely indicates a bug.
            # The storm query's responded with this node which met the filters in some way. Yet at
            # this point, there was no match to a heuristic. This should not happen.
            log.warning("No heuristic found for node: %s", ndef)

        if matching_al4_tag_types := SynapseResultHelper._find_related_al4tag_types(
            al4_tags, nval.get("repr", ndef[1])
        ):
            for al4_tag_type in matching_al4_tag_types:
                res.add_tag(al4_tag_type, nval.get("repr", ndef[1]))
        else:
            # This likely indicates a bug.
            # The storm query's responded with this node which met the filters in some way. Yet at
            # this point, there was no match to the AL4 tag type. This should not happen.
            log.warning("No AL4 tags found for node: %s", ndef)

        return res

    def _categorize_tags(self, syn_node_tags: list[tuple]) -> dict[str, list]:
        """Categorize Synapse tags into two different categories.

        This is based on whether the Synapse tag matched one of the configured conditions or is just
        another tag on the node not related to the match.

        Args:
            syn_node_tags (list[tuple]): List of Synapse tag tuples. (tag_name, [first_seen, last_seen])

        Returns:
            dict[str, list]: A dict of categorized synapse tags sorted alphabetically.
                match: Synapse tags that were actually matched against the conditions configuration
                other: All other Synapse tags on the associated node.

                e.g.
                {
                    "match": [("matched", [None, None])],
                    "other": [("non.match", [None, None])]
                }
        """
        categorized_tags: dict[str, list] = {
            "match": [],
            "other": [],
        }

        for cond_cfg in self.heur_map.values():

            if match_any_syn_tag_cfg := cond_cfg.get("match_any_syn_tag"):

                is_match, matches = SynapseResultHelper._find_tag_matches(
                    MatchConditionType.ANY, match_any_syn_tag_cfg, syn_node_tags
                )
                if is_match:
                    for syn_tags in matches.values():
                        categorized_tags["match"].extend(
                            [
                                syn_tag
                                for syn_tag in syn_tags
                                if syn_tag not in categorized_tags["match"]
                            ]
                        )

            if match_all_syn_tags_cfg := cond_cfg.get("match_all_syn_tags"):

                # must be done per AND condition since there might be multipe AND conditions listed
                for tag_prefix_list in match_all_syn_tags_cfg:

                    is_match, matches = SynapseResultHelper._find_tag_matches(
                        MatchConditionType.ALL,
                        tag_prefix_list,
                        syn_node_tags,
                    )

                    if is_match:
                        for syn_tags in matches.values():
                            categorized_tags["match"].extend(
                                [
                                    syn_tag
                                    for syn_tag in syn_tags
                                    if syn_tag not in categorized_tags["match"]
                                ]
                            )

        # sort the matches
        categorized_tags["match"] = sorted(categorized_tags["match"])

        # All other tags go into the "other" category
        categorized_tags["other"] = sorted(
            [
                syn_tag
                for syn_tag in syn_node_tags
                if syn_tag not in categorized_tags["match"]
                and syn_tag not in categorized_tags["other"]
            ]
        )

        return categorized_tags

    def _filter_tags(self, syn_tags: list[tuple]) -> list[tuple]:
        """Filter out all tags specified in the config.syntag_prefixes_to_filter.

        Args:
            syn_tags (list[tuple]): Synapse node tags to filter.

        Returns:
            list[tuple]: Filtered list of Synapse node tags.
        """
        return [
            tag
            for tag in syn_tags
            if not any(
                tag[0] == filter_tag or tag[0].startswith(filter_tag)
                for filter_tag in self.syntag_prefixes_to_filter
            )
        ]

    def _get_heuristic_from_tags(self, syn_node_tags: list[tuple]) -> Heuristic | None:
        """Get the highest scoring heuristic for the given Synapse node tags.

        Args:
            syn_node_tags (list[tuple]): List of Synapse node tag tuples.

        Raises:
            ValueError: Invalid configuration

        Returns:
            Heuristic | None: Highest scoring heuristic for the given Synapse node tags or None.
        """
        highest_scoring_heur_match: Heuristic | None = None

        def is_higher_score(existing_heur, heur_to_check):
            if not heur_to_check:
                raise ValueError(
                    "Invalid configuration. The heuristic defined in the configuration is not found in the available list of heuristics."
                )
            if not existing_heur or heur_to_check.score > existing_heur.score:
                return heur_to_check
            return existing_heur

        for heur_id, cond_cfg in self.heur_map.items():

            if match_any_syn_tag_cfg := cond_cfg.get("match_any_syn_tag", []):

                is_match, _ = SynapseResultHelper._find_tag_matches(
                    MatchConditionType.ANY, match_any_syn_tag_cfg, syn_node_tags
                )
                if is_match:
                    highest_scoring_heur_match = is_higher_score(
                        highest_scoring_heur_match, self.service_heuristics.get(int(heur_id))
                    )
                    continue

            if match_all_syn_tags_cfg := cond_cfg.get("match_all_syn_tags", []):

                for tag_prefix_list in match_all_syn_tags_cfg:

                    is_match, _ = SynapseResultHelper._find_tag_matches(
                        MatchConditionType.ALL,
                        tag_prefix_list,
                        syn_node_tags,
                    )

                    if is_match:
                        highest_scoring_heur_match = is_higher_score(
                            highest_scoring_heur_match, self.service_heuristics.get(int(heur_id))
                        )

        return highest_scoring_heur_match

    @staticmethod
    def _find_related_al4tag_types(al4_tags: dict, syn_node_val: str) -> set[str]:
        """Find any related AL4 tags and return the associated AL4 tag types.

        Args:
            al4_tags (dict): AL4 tags dict.
            syn_node_val (str): The Synapse node value.

        Returns:
            set[str]: Set of AL4 tag types. e.g. network.static.ip, network.dynamic.ip
        """
        return {
            al4_tag_type
            for al4_tag_type, al4_tag_list in al4_tags.items()
            if syn_node_val in al4_tag_list
        }

    @staticmethod
    def _find_tag_matches(
        match_cond_type: MatchConditionType, cond_tags: list[str], syn_node_tags: list[tuple]
    ) -> tuple[bool, dict]:
        """Determine if there is a match based on the conditions and Synapse node tags.

        The condition tags are matched as exact matches or as prefixes. e.g. If the condition tag is
        `rep.vendor`, then any Synapse tag that is either `rep.vendor` or `rep.vendor.**` will be
         considered a match.

        Args:
            match_cond_type (MatchConditionType): Whether ALL or ANY conditions are met.
            cond_tags (list[str]): The conditions tags to match against.
            syn_node_tags (list[tuple]): Synapse node tag tuples. (tag_name, [first_seen, last_seen])

        Returns:
            tuple[bool, dict]:
                bool - whether the match conditions where met based on the match_cond_type
                matches - keys=condition tag; values=matching synapse tags
        """
        matches: dict[str, list[tuple]] = {}

        for cond_tag in cond_tags or []:
            for syn_node_tag in syn_node_tags or []:
                tag_name = syn_node_tag[0]
                if tag_name.startswith(f"{cond_tag}.") or tag_name == cond_tag:
                    if not matches.get(cond_tag):
                        matches[cond_tag] = [syn_node_tag]
                    else:
                        matches[cond_tag].append(syn_node_tag)

        match_cond = False
        if match_cond_type is MatchConditionType.ALL:
            match_cond = all(cond in matches for cond in cond_tags or [])
            # If all of the conditions are not met for the ALL condition type, then remove
            #  the matches.
            if not match_cond:
                matches = {}
        elif match_cond_type is MatchConditionType.ANY:
            match_cond = any(cond in matches for cond in cond_tags or [])

        return (match_cond, matches)

    @staticmethod
    def _leaf_tags(syn_tagsd: dict[str, list]) -> list[tuple]:
        """Get the leaf tags from the Synapse tags dict.

        Note: This helper function was sourced from the Synapse source code and adapted.

        Args:
            syn_tagsd (dict[str, list]): tags dict from a Synapse packed node.
                {'rep': [None, None], 'rep.vendorx': [None, None]}

        Returns:
            list[tuple]: list of only the leaf tags. For the example arg, it would just return:
                [('rep.vendorx', [None, None]),]
        """
        retn: list[tuple] = []

        if not syn_tagsd:
            return retn

        # brute force rather than build a tree.  faster in small sets.
        for _, tag, valu in sorted([(len(t), t, v) for (t, v) in syn_tagsd.items()], reverse=True):

            look = tag + "."
            if any(r.startswith(look) for (r, _) in retn):
                continue

            retn.append((tag, valu))

        return retn
