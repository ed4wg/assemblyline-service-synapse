# assemblyline-service-synapse

An Assemblyline v4 post-processing service that takes the resulting AL4 tags for a given file and
queries your Vertex Synapse instance for additional context.

> [!NOTE]
> This service requires you to have access to a Synapse instance and requires further configuration. See the `Configuration` section.

## Execution

This service does NOT submit the file to Synapse. It takes the configured Assemblyline tag types
and translates those tag name-value pairs into a Synapse query. The Synapse query is further refined
by any filters defined in the configuration.

e.g. An Assemblyline tag of `network.static.domain: foo.local` will translate to the Synapse query:
`inet:fqdn="foo.local"`. See `al4_tag_types` section below.

Results are not shown in Assemblyline unless a heuristic was mapped based on the configured tag
conditions. i.e. You may have the node `foo.local` in Synapse, but it will only show up as a result
if it has Synapse tags that map to a condition matched in the heuristic mapping configuration.

Synapse is not queried for each node. A Storm query is generated and aggregates nodes so that it can
reduce the number of times the Synapse API is called. e.g. An Assemblyline result with 50 relevant
tags identified, would only query Synapse one time for all 50 nodes.

## Configuration

### Service Configuration

> [!IMPORTANT]
>
> You MUST configure the heuristic matching conditions in the `heur_map` for your specific environment. The `service_manifest.yml` has example configurations.

| Name                         | Description                                                                                       |
| ---------------------------- | ------------------------------------------------------------------------------------------------- |
| synapse_api_key              | Synapse API key.                                                                                  |
| synapse_host                 | Synapse host endpoint. e.g. synapse.local.                                                        |
| verify_cert                  | Configure TLS certificate verification when communicating with the Synapse API.                   |
| storm_opts.synapse_view_iden | Leaving this empty will use the `default` Synapse view. Otherwise, specify the desired view iden. |
| max_nodes_per_query          | The maximum number of nodes for a given Synapse query. Default is 50                              |
| al4_tag_types                | A list of Assemblyline tag types to consider when querying Synapse.                               |
| heur_map                     | A map defining how Synapse results tie back to Assemblyline heuristics.                           |
| syntags_to_filter_node       | A list of Synapse tags (or tag globs) that will prevent returning the Synapse node all together.  |
| syntag_prefix_to_filter      | A list of Synapse tag prefixes to filter out of the Assemblyline results.                         |

### Submission Parameters

There are no submission parameters.
