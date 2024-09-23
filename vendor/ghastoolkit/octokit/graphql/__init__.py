DEPENDENCY_GRAPH_STATUS = """\
{
    repository(owner: "$owner", name: "$repo") {
        hasVulnerabilityAlertsEnabled
    }
}
"""

DEPENDENCY_GRAPH_ALERTS = """\
{
    repository(owner: "$owner", name: "$repo") {
        vulnerabilityAlerts(first: 100, states: [OPEN], $cursor) {
            totalCount
            pageInfo {
                hasNextPage
                endCursor
            }
            edges {
                node {
                    number
                    state
                    createdAt
                    dismissReason
                    securityVulnerability {
                        package {
                            ecosystem
                            name
                        }
                    }
                    securityAdvisory {
                        ghsaId
                        severity
                        cwes(first: 100) {
                            edges {
                                node {
                                    cweId
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
"""

DEPENDENCY_GRAPH_INFO = """\
{
    repository(owner: "$owner", name: "$repo") {
        name
        licenseInfo {
            name
        }
        dependencyGraphManifests(first: 1, $manifests_cursor) {
            totalCount
            pageInfo {
                hasNextPage
                endCursor
            }
            edges {
                node {
                    filename
                    dependencies(first: $dependencies_first, $dependencies_cursor) {
                        totalCount
                        pageInfo {
                            hasNextPage
                            endCursor
                        }
                        edges {
                            node {
                                packageName
                                packageManager
                                requirements
                                repository {
                                    nameWithOwner
                                    isArchived
                                    isDisabled
                                    isEmpty
                                    isFork
                                    isSecurityPolicyEnabled
                                    isInOrganization
                                    licenseInfo {
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
"""


QUERIES = {
    "GetDependencyStatus": DEPENDENCY_GRAPH_STATUS,
    "GetDependencyAlerts": DEPENDENCY_GRAPH_ALERTS,
    "GetDependencyInfo": DEPENDENCY_GRAPH_INFO,
}
