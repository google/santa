---
title: Recommended Rollout Strategy
parent: Deployment
nav_order: 2
---

# Recommended Rollout Strategy 

We recommend the following strategy to rollout Santa to an existing fleet of machines. This approach can help avoid too much disruption during the process.

As part of this strategy, we recommend using a sync server with Santa. For a list of open-source sync servers, see the [Sync Servers](sync-servers.md) page. 

1. Configure the sync server to assign all clients to `MONITOR` mode and ensure that [event](../concepts/events.md) collection is working. See [Sync Server Provided Configuration](configuration.md#sync-server-provided-configuration) for a list of the configuration options.

1. Deploy to all hosts. Ideally, the deployment is a slow process over a reasonable period of time. That is, an incremental deployment to small groups of machines depending on your fleet size with enough time to monitor and manage the deployment. A slower deployment will allow you to catch incompatibilities early in the rollout before a full deployment is complete. 

1. Leave the client in [`MONITOR` mode](../concepts/mode.md) for a defined period of time to allow event collection to take place.

1. Analyze the incoming events uploaded by the client in order to determine which applications you need to allow list. 

1. Create allow rules as appropriate based on the previous analysis. See [Rules](../concepts/rules.md) for more explanation and examples of setting up rules.

1. Continue to analyze as you deploy the allow rules. The aim is to ensure that the number of incoming events is manageable.

1. Slowly move clients to `LOCKDOWN` mode. If possible, use the analysis to guide which hosts you move. For example, if a host is not uploading any block events, it's a good candidate for switching modes.

