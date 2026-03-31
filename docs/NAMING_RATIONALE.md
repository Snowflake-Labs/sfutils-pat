# snow-utils: Naming Rationale and Plugin Proposal

## Overview

This utility was built to reduce developer time spent on repetitive Snowflake setup and operations that usually require many CLI and SQL steps. `snow-utils` turns those multi-step workflows into task-focused commands so teams can complete common jobs faster and more consistently.

This document explains why the name `snow-utils` is justified, how it fits the Snowflake CLI model, and why the same plugin convention should be used going forward.

## Why the name is appropriate

- **It complements the Snowflake CLI, not replaces it.** The intent is to improve the developer experience for repeatable workflows on top of existing CLI capabilities.
- **It relies on `snow` under the hood.** The utility is an orchestration layer around Snowflake CLI flows, not an independent control plane.
- **It is a true utility layer.** Similar to the common "utils" pattern in software, it packages repeated operational sequences into reusable commands.

## Evidence from implementation

- **Repository:** [snow-utils](https://github.com/Snowflake-Labs/snow-utils)
- **`README.md`:** Documents Snowflake CLI as a prerequisite and shows task simplification where one operation may otherwise require many manual steps.
- **`common/src/snow_utils_common/snow_common.py`:** Central command execution model built around Snowflake CLI commands.
- **`common/src/snow_utils_common/check_setup.py`:** Validates Snowflake CLI presence and setup before task execution.
- **`src/snow_utils/extvolume.py`:** Implements external volume flows through orchestrated CLI/SQL operations.
- **`src/snow_utils/pat.py`:** Implements PAT-related flows as repeatable task commands.
- **`src/snow_utils/network.py`:** Implements network policy workflows as composed CLI/SQL operations.

## Reserved identifier context

Anything beginning with `snow` is treated as reserved in the Snowflake ecosystem. This proposal does not ask for an unrestricted exception. It asks for a governed convention where `snow-*` names are used only for CLI plugins that satisfy clear criteria and align with the Snowflake CLI extension model.

## Criteria for `snow-<plugin-name>`

Use `snow-<plugin-name>` when all criteria are met:

1. The tool is designed as a plugin extension to Snowflake CLI workflows.
2. The tool uses Snowflake CLI as its primary interface pattern for Snowflake task execution.
3. The user-facing invocation is aligned to `snow <plugin-name> <task>` (current or target UX).

`snow-utils` meets these criteria.

## Plugin naming rule proposal

Adopt `snow-<plugin-name>` as the naming convention for eligible plugins, with approval still case-by-case. This creates consistency without creating a free-for-all.

The Snowflake CLI is already open source, which already invites internal and community extension patterns. A governed plugin naming rule gives that ecosystem a clear structure instead of ad hoc naming.

This follows a proven precedent from Kubernetes CLI plugins: binaries named `kubectl-<name>` are invoked as `kubectl <name>`. The proposed Snowflake pattern is equivalent: `snow-<plugin-name>` invoked as `snow <plugin-name> <task>`.

## Why this pattern adds value

- **Clarity:** Makes it immediately obvious that the tool extends Snowflake CLI workflows.
- **Consistency:** Gives teams one recognizable naming and invocation model.
- **Modularity:** Encourages a plugin ecosystem rather than a monolithic CLI surface.
- **Developer choice:** Builders install and use only the plugins they need for their workflows.
- **Scalability:** Supports both internal and community contributions under explicit criteria.

## Optional ecosystem signal

[snow-utils-skills](https://github.com/Snowflake-Labs/snow-utils-skills) applies the same conceptual layer to Cortex Code Skills usage, showing this model can extend beyond a single repository and support broader developer workflows.

## Positioning

`snow-utils` is best positioned as a Snowflake CLI utility plugin proposal, not as a separate CLI replacement product.

## Explicit ask

- Approve the name **`snow-utils`** for this utility plugin.
- Approve **`snow-<plugin-name>`** as the governed naming convention for eligible plugins.
- Support the target invocation model **`snow <plugin-name> <task>`** for plugin-based task execution.
