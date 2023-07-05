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
        dependencyGraphManifests {
            totalCount
            pageInfo {
                hasNextPage
                endCursor
            }
            edges {
                node {
                    filename
                    dependencies {
                        edges {
                            node {
                                packageName
                                packageManager
                                requirements
                                repository {
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
    "GetDependencyAlerts": DEPENDENCY_GRAPH_ALERTS,
    "GetDependencyInfo": DEPENDENCY_GRAPH_INFO,
}
