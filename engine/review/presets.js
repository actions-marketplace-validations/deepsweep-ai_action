import { POLICY_SCHEMA_VERSION } from "./policy.js";
export const AUTONOMY_PRESETS = {
    automatic: {
        schemaVersion: POLICY_SCHEMA_VERSION,
        name: "autonomy: automatic",
        mode: "observe",
        defaultEffect: "observe",
        rules: [],
    },
    "prepare-only": {
        schemaVersion: POLICY_SCHEMA_VERSION,
        name: "autonomy: prepare-only",
        mode: "enforce",
        defaultEffect: "deny",
        rules: [],
    },
    "approval-required": {
        schemaVersion: POLICY_SCHEMA_VERSION,
        name: "autonomy: approval-required",
        mode: "enforce",
        defaultEffect: "require-approval",
        rules: [],
    },
    "dual-authorization": {
        schemaVersion: POLICY_SCHEMA_VERSION,
        name: "autonomy: dual-authorization",
        mode: "enforce",
        defaultEffect: "require-approval",
        rules: [
            {
                effect: "require-approval",
                principal: "*",
                action: "*",
                resource: "*",
                name: "dual-authorization",
                rationale: "every held call needs two distinct named approvers",
                approvals: 2,
            },
        ],
    },
    "human-only": {
        schemaVersion: POLICY_SCHEMA_VERSION,
        name: "autonomy: human-only",
        mode: "enforce",
        defaultEffect: "deny",
        rules: [],
    },
};
