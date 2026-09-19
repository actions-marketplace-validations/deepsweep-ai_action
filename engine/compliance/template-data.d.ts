/**
 * GENERATED MIRROR of contracts/templates/*.json (TEAM-ADR-038) — the compiled
 * engine needs no filesystem lookup for templates, and importing JSON from
 * outside src/ would drag contracts/ into the tsc root and break the dist
 * layout. tests/compliance/packet.test.ts asserts byte-equality with the JSON
 * source, so this file cannot drift; regenerate with:
 *   node scripts/gen-templates.mjs
 */
export declare const TEMPLATE_DATA: {
    readonly "article-50-transparency": {
        readonly templateId: "article-50-transparency";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "EU AI Act Article 50 transparency — agent-activity evidence annex";
        readonly regime: "Regulation (EU) 2024/1689, Article 50 (transparency obligations for providers and deployers of certain AI systems), applicable from 2 August 2026";
        readonly reviewStatus: "DRAFT — Article 50 duties concern disclosure TO natural persons and marking of synthetic content; this annex evidences WHICH agents acted, WHEN and under WHAT policy so those disclosures can be substantiated. It does not itself satisfy Article 50. Counsel review required.";
        readonly sections: readonly [{
            readonly id: "inventory";
            readonly heading: "Agents (principals) and tool surfaces active in the window";
            readonly evidence: readonly ["principals", "servers", "tools"];
        }, {
            readonly id: "governance";
            readonly heading: "Policy in force and decisions taken";
            readonly evidence: readonly ["rules", "decisions"];
        }, {
            readonly id: "timeline";
            readonly heading: "Action timeline";
            readonly evidence: readonly ["timeline"];
        }, {
            readonly id: "integrity";
            readonly heading: "Integrity of this record";
            readonly evidence: readonly ["treeHead", "chainIntact", "signatureCoverage", "verifyInstructions"];
        }];
    };
    readonly "exec-incident-packet": {
        readonly templateId: "exec-incident-packet";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "Executive-assistant incident packet — agent-activity evidence for the 24h / 72h / 15-day reporting clocks";
        readonly regime: "Cross-regime incident narrative for an executive-facing AI assistant governed by the EXEC-1 rule pack: NIS2 Art. 23(4)(a) early warning (24h) → GDPR Art. 33(1)/(3) personal-data-breach notification (72h) → EU AI Act Art. 73 serious-incident report (15 days). Each clock's own annex (incident-nis2-24h, incident-gdpr-72h, incident-aiact-15d) remains the regime-specific artifact; this packet is the incident's single evidence spine those annexes cite. Every citation here is draft-unverified until compliance/REG-VERIFY.md marks it verified.";
        readonly reviewStatus: "DRAFT — regulatory mapping requires counsel review before customer-visible use. Whether an assistant incident is a NIS2 'significant incident', a GDPR 'personal data breach' or an AI Act 'serious incident' is a legal determination the deploying organisation makes; this packet supplies the evidence, not the determination.";
        readonly sections: readonly [{
            readonly id: "clock";
            readonly heading: "Reporting clocks — time of awareness and the 24h / 72h / 15-day windows";
            readonly evidence: readonly ["window", "generatedAt"];
            readonly note: "The packet window opens at the customer's asserted time of awareness. All three clocks run from awareness; the packet states the window and lets each annex compute its deadline.";
        }, {
            readonly id: "principal";
            readonly heading: "Which assistant, acting for which principal, under which pack version";
            readonly evidence: readonly ["timeline.policy.decision.principalHash", "timeline.policy.decision.packs", "counts.principals"];
            readonly note: "The principal is a hash; the pack label carries pack id, version, bundle version and signing key id so an independent party can confirm which signed rules governed. Plaintext identity enters only as a hash-verified selective disclosure from the customer's own records.";
        }, {
            readonly id: "sequence";
            readonly heading: "What the assistant tried to do, in order — decisions, holds, denials, approvals";
            readonly evidence: readonly ["timeline", "counts.decisions", "counts.gatewayActions", "counts.approvalsGranted", "counts.approvalsConsumed", "counts.rulesFired"];
            readonly note: "Each tool call is a decision row (class labels + deciding rule) followed by the gateway's action (forwarded · blocked · held · approved) and, when forwarded, the result row. Untrusted-ingest classes on a read followed by a held or blocked external write show the injection-to-exfiltration chain without any content.";
        }, {
            readonly id: "threat-patterns";
            readonly heading: "Threat patterns implicated (P1–P9) and how each was treated";
            readonly evidence: readonly ["counts.rulesFired", "timeline.policy.decision.classes", "timeline.policy.decision.rule"];
            readonly note: "Rule names carry the pattern id (P1 external send, P2 mail rules, P3 finance, P4 calendar, P5 documents, P6 send-as/delegation, P7 untrusted ingest → external write, P8 tool drift, P9 cross-agent). A pattern that fired as deny or require-approval is a control that held at the moment of the event.";
        }, {
            readonly id: "disclosures";
            readonly heading: "Selective disclosures — what content the organisation chooses to reveal, verified against recorded digests";
            readonly evidence: readonly ["disclosures.verified", "disclosures.refused"];
            readonly note: "Recipients, subject lines, file names or amounts appear here ONLY if the organisation attaches them from its own vault and they reproduce the SHA-256 recorded at the time. A disclosure that does not reproduce is listed as refused and is never cited.";
        }, {
            readonly id: "human-oversight";
            readonly heading: "Oversight controls exercised — approvals, denials without approval path, tool re-pins";
            readonly evidence: readonly ["counts.approvalsGranted", "counts.approvalsConsumed", "timeline.approval.granted", "timeline.approval.consumed", "timeline.gateway.tool_repinned"];
            readonly note: "A held call cleared by an out-of-band approval step, and the exact-tuple retry that followed, is the oversight record. The entries prove the approval protocol ran and carry the approver name it was given; they do not authenticate that approver as a person. Denials with no approval path (mail rules, payee creation) show the control was absolute at the time.";
        }, {
            readonly id: "integrity";
            readonly heading: "How an independent party re-verifies this packet offline";
            readonly evidence: readonly ["integrity.chainIntact", "integrity.signatureCoverage", "integrity.signedTreeHead", "integrity.root", "integrity.verifyInstructions"];
            readonly note: "Hash chain intact, per-entry signature coverage, and the signed RFC 6962 tree head over the ledger. Verification needs the exported evidence bundle and the pinned public key — nothing from DeepSweep at run time.";
        }, {
            readonly id: "standing";
            readonly heading: "Standing of this document";
            readonly evidence: readonly ["standing", "template.reviewStatus"];
            readonly note: "Evidence supporting the deploying organisation's own compliance process; not a legal conclusion.";
        }];
    };
    readonly "incident-aiact-15d": {
        readonly templateId: "incident-aiact-15d";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "EU AI Act serious-incident report (15 days) — agent-activity evidence annex";
        readonly regime: "Regulation (EU) 2024/1689, Article 73(1)-(4): serious incident reporting not later than 15 days after awareness (Art. 73(2)) (2 days for widespread infringement / serious and irreversible disruption; 10 days for death); Article 73(6) investigation and record-keeping; Article 26(5) deployer duty to inform the provider";
        readonly reviewStatus: "DRAFT — regulatory mapping requires counsel review before customer-visible use. Whether the deploying organisation is a provider (Art. 25) is a legal determination the packet does not make.";
        readonly sections: readonly [{
            readonly id: "system";
            readonly heading: "AI system and deployment identification";
            readonly evidence: readonly ["principals", "servers", "tools"];
            readonly note: "Hashed identifiers; the customer maps hashes to names from its own inventory (or attaches disclosures).";
        }, {
            readonly id: "incident";
            readonly heading: "Description of the incident and the causal link to the AI system";
            readonly evidence: readonly ["timeline", "disclosures"];
        }, {
            readonly id: "measures";
            readonly heading: "Corrective measures and risk-mitigation already taken";
            readonly evidence: readonly ["blockedCalls", "heldCalls", "approvals", "denyRules"];
        }, {
            readonly id: "oversight";
            readonly heading: "Art. 14 human-oversight posture as deployed — holds, approvals, permitted retries";
            readonly evidence: readonly ["approvals"];
            readonly note: "denial → out-of-band approval → permitted retry entries evidence the oversight mechanism operating in the loop; the approver identity is recorded as supplied, not authenticated.";
        }, {
            readonly id: "integrity";
            readonly heading: "Integrity and reproducibility of this record";
            readonly evidence: readonly ["treeHead", "chainIntact", "signatureCoverage", "verifyInstructions"];
        }];
    };
    readonly "incident-gdpr-72h": {
        readonly templateId: "incident-gdpr-72h";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "GDPR personal-data-breach notification (72h) — agent-activity evidence annex";
        readonly regime: "Regulation (EU) 2016/679, Article 33(1) notification within 72 hours; Article 33(3) minimum content; Article 33(5) documentation duty";
        readonly reviewStatus: "DRAFT — regulatory mapping requires counsel review before customer-visible use";
        readonly sections: readonly [{
            readonly id: "nature";
            readonly heading: "Nature of the breach incl. categories and approximate number of data subjects and records (Art. 33(3)(a))";
            readonly evidence: readonly ["timeline", "disclosures"];
            readonly note: "Which tools an agent invoked, when, and under which decision — data categories/counts only from hash-verified disclosures.";
        }, {
            readonly id: "contact";
            readonly heading: "Data protection officer / contact point (Art. 33(3)(b))";
            readonly evidence: readonly [];
            readonly note: "Customer-supplied; not derivable from evidence.";
        }, {
            readonly id: "consequences";
            readonly heading: "Likely consequences (Art. 33(3)(c))";
            readonly evidence: readonly ["disclosures"];
            readonly note: "Customer assessment; the packet cites which verified disclosures support it.";
        }, {
            readonly id: "measures";
            readonly heading: "Measures taken or proposed, incl. mitigation (Art. 33(3)(d))";
            readonly evidence: readonly ["blockedCalls", "heldCalls", "approvals", "denyRules"];
            readonly note: "Policy denials, holds and human approvals are measures already in force at the moment of the event.";
        }, {
            readonly id: "documentation";
            readonly heading: "Documentation enabling the supervisory authority to verify compliance (Art. 33(5))";
            readonly evidence: readonly ["treeHead", "chainIntact", "signatureCoverage", "verifyInstructions"];
        }];
    };
    readonly "incident-hipaa-60d": {
        readonly templateId: "incident-hipaa-60d";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "HIPAA breach notification (60 days) — agent-activity evidence annex";
        readonly regime: "45 CFR §§ 164.400–414 (HIPAA Breach Notification Rule): § 164.404 individual notice without unreasonable delay and no later than 60 calendar days from discovery; § 164.404(c) content; § 164.406 media notice (500+ in a state); § 164.408 notice to the Secretary; § 164.410 business-associate notice to the covered entity within 60 days; § 164.402(2) risk-assessment factors; § 164.414(b) burden of proof on the covered entity";
        readonly reviewStatus: "DRAFT — regulatory mapping requires counsel review before customer-visible use";
        readonly sections: readonly [{
            readonly id: "discovery";
            readonly heading: "Date of discovery and the 60-day window (§ 164.404(a)(2), (b))";
            readonly evidence: readonly ["window", "generatedAt"];
            readonly note: "The 60 days run from the day the breach is known or should reasonably have been known. The packet's window start is the customer's asserted discovery time; the evidence bounds when agent activity in scope actually occurred.";
        }, {
            readonly id: "what-happened";
            readonly heading: "Brief description of what happened, incl. dates of the breach and of discovery (§ 164.404(c)(1)(A))";
            readonly evidence: readonly ["timeline", "disclosures"];
            readonly note: "Which tools an agent invoked, when, under which decision, and against which resources — from the hash-chained timeline; free-text description remains the customer's.";
        }, {
            readonly id: "phi-involved";
            readonly heading: "Types of unsecured PHI involved (§ 164.404(c)(1)(B))";
            readonly evidence: readonly ["disclosures.verified"];
            readonly note: "The evidence record is metadata-first and never stores PHI. Data categories come only from customer-verified disclosures whose hashes bind them to the recorded events; the record proves WHICH resources were touched, not their contents.";
        }, {
            readonly id: "risk-assessment";
            readonly heading: "Risk assessment: was PHI actually acquired or viewed (§ 164.402(2)(iii))";
            readonly evidence: readonly ["timeline", "blockedCalls", "heldCalls", "denyRules"];
            readonly note: "The factor that decides whether an impermissible use is a reportable breach. A tamper-evident record of what the agent saw, decided, and executed — including calls blocked or held BEFORE execution — is direct evidence on acquisition-or-viewing, and its absence is what forces worst-case assumptions.";
        }, {
            readonly id: "mitigation";
            readonly heading: "Steps taken to investigate, mitigate, and protect against further breaches (§ 164.404(c)(1)(D)–(E), § 164.402(2)(iv))";
            readonly evidence: readonly ["blockedCalls", "heldCalls", "approvals", "denyRules"];
            readonly note: "Policy denials, holds and out-of-band approvals in force at the moment of the event are mitigation already operating, not remediation promised.";
        }, {
            readonly id: "burden-of-proof";
            readonly heading: "Burden of proof: demonstrating notifications were made or that no breach occurred (§ 164.414(b))";
            readonly evidence: readonly ["treeHead", "chainIntact", "signatureCoverage", "verifyInstructions"];
            readonly note: "The covered entity carries the burden. An externally anchored, append-only record that a third party can verify offline is the demonstration instrument; a mutable log is an assertion.";
        }];
    };
    readonly "incident-nis2-24h": {
        readonly templateId: "incident-nis2-24h";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "NIS2 early warning (24h) — agent-activity evidence annex";
        readonly regime: "Directive (EU) 2022/2555 (NIS2), Article 23(4)(a) early warning within 24 hours of awareness";
        readonly reviewStatus: "DRAFT — regulatory mapping requires counsel review before customer-visible use";
        readonly sections: readonly [{
            readonly id: "awareness";
            readonly heading: "Time of awareness and reporting window";
            readonly evidence: readonly ["window", "generatedAt"];
            readonly note: "24h runs from awareness; the packet's window start is the customer's asserted awareness time.";
        }, {
            readonly id: "malicious";
            readonly heading: "Whether the incident is suspected to be caused by unlawful or malicious acts";
            readonly evidence: readonly ["blockedCalls", "heldCalls", "denyRules"];
            readonly note: "Denied/held tool calls and the rules that fired are indicators, not conclusions.";
        }, {
            readonly id: "crossBorder";
            readonly heading: "Possible cross-border impact";
            readonly evidence: readonly ["disclosures"];
            readonly note: "Populated only from customer-attached, hash-verified disclosures (e.g. which systems the tools reached).";
        }, {
            readonly id: "timeline";
            readonly heading: "Agent action timeline (what it saw, decided, executed)";
            readonly evidence: readonly ["timeline"];
        }, {
            readonly id: "integrity";
            readonly heading: "Integrity of this record";
            readonly evidence: readonly ["treeHead", "chainIntact", "signatureCoverage"];
        }];
    };
    readonly "incident-nydfs-72h": {
        readonly templateId: "incident-nydfs-72h";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "NYDFS Part 500 cybersecurity-event notice (72h) — agent-activity evidence annex";
        readonly regime: "23 NYCRR Part 500 (as amended 2023): § 500.17(a) notice to the Superintendent within 72 hours of determining a cybersecurity event occurred at the covered entity, an affiliate, or a third-party service provider; § 500.17(c) 24-hour ransom-payment notice; § 500.6 audit trail — records designed to reconstruct material financial transactions and detect and respond to events, retained per rule";
        readonly reviewStatus: "DRAFT — regulatory mapping requires counsel review before customer-visible use";
        readonly sections: readonly [{
            readonly id: "determination";
            readonly heading: "Time of determination and the 72-hour window (§ 500.17(a))";
            readonly evidence: readonly ["window", "generatedAt"];
            readonly note: "72h runs from the covered entity's DETERMINATION that a reportable event occurred; the packet's window start is the customer's asserted determination time. The 24-hour ransom-payment clock (§ 500.17(c)) is separate and shorter.";
        }, {
            readonly id: "event-description";
            readonly heading: "Description of the cybersecurity event for the DFS portal filing";
            readonly evidence: readonly ["timeline", "servers", "tools", "principals"];
            readonly note: "Which agent principals invoked which tools against which servers, in order, from the hash-chained timeline — the reconstruction § 500.6 exists to enable.";
        }, {
            readonly id: "audit-trail";
            readonly heading: "Audit-trail duty: records that reconstruct events (§ 500.6)";
            readonly evidence: readonly ["treeHead", "chainIntact", "signatureCoverage", "verifyInstructions"];
            readonly note: "§ 500.6 requires audit trails DESIGNED to reconstruct events. An append-only record with externally anchored heads and offline third-party verification is that design property, demonstrable to an examiner rather than asserted.";
        }, {
            readonly id: "controls-in-force";
            readonly heading: "Controls operating at the time of the event";
            readonly evidence: readonly ["blockedCalls", "heldCalls", "approvals", "denyRules", "rules"];
            readonly note: "Denials, holds and out-of-band approvals recorded in the same chain as the event are contemporaneous control evidence for the filing and the record behind the § 500.17(b) annual compliance filing.";
        }, {
            readonly id: "tpsp";
            readonly heading: "Events at third-party service providers (§ 500.17(a)(1)(iii))";
            readonly evidence: readonly ["servers", "disclosures"];
            readonly note: "The 2023 amendment makes TPSP events reportable. The inventory of MCP servers and external tool surfaces bounds which third-party surfaces an agent could reach; contents only via verified disclosures.";
        }];
    };
    readonly "incident-osfi-24h": {
        readonly templateId: "incident-osfi-24h";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "OSFI technology and cyber incident report (24h) — agent-activity evidence annex";
        readonly regime: "OSFI Technology and Cyber Security Incident Reporting Advisory (FRFIs): initial notification within 24 hours or as soon as possible after determining a reportable incident; ongoing updates until resolution; post-incident review. Guideline B-13 (Technology and Cyber Risk Management): incident management, and E-23 model-risk expectations where the agent is a model-driven system";
        readonly reviewStatus: "DRAFT — regulatory mapping requires counsel review before customer-visible use. OSFI's advisory is supervisory guidance; thresholds and timing language must be confirmed against the current advisory text before any customer use";
        readonly sections: readonly [{
            readonly id: "determination";
            readonly heading: "Time of determination and the 24-hour initial notification window";
            readonly evidence: readonly ["window", "generatedAt"];
            readonly note: "The clock runs from determining the incident is reportable; the packet's window start is the FRFI's asserted determination time.";
        }, {
            readonly id: "incident-description";
            readonly heading: "Initial report: what occurred, systems and services affected";
            readonly evidence: readonly ["timeline", "servers", "tools", "principals"];
            readonly note: "Agent principals, tools and servers involved, in order, from the hash-chained timeline — the factual spine of the initial report and every subsequent update.";
        }, {
            readonly id: "updates";
            readonly heading: "Ongoing updates until resolution";
            readonly evidence: readonly ["timeline", "window"];
            readonly note: "Each update can bind to a later tree head, so 'what changed since the last report' is a provable interval, not a narrative.";
        }, {
            readonly id: "controls";
            readonly heading: "Controls and containment in force (B-13 incident management)";
            readonly evidence: readonly ["blockedCalls", "heldCalls", "approvals", "denyRules"];
            readonly note: "Contemporaneous denials, holds and approvals recorded in-chain evidence the containment posture at the moment of the event.";
        }, {
            readonly id: "post-incident";
            readonly heading: "Post-incident review and supervisory follow-up";
            readonly evidence: readonly ["treeHead", "chainIntact", "signatureCoverage", "verifyInstructions"];
            readonly note: "An externally anchored, append-only record lets the post-incident review, internal audit, and OSFI verify the same history independently — including that nothing was rewritten between the initial report and the review.";
        }];
    };
    readonly "insurer-evidence-summary": {
        readonly templateId: "insurer-evidence-summary";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "Insurer evidence summary — executive-assistant governance evidence for D&O / cyber underwriting";
        readonly regime: "Underwriting evidence (not a regulatory filing): the coverage period, which signed rule pack governed the executive assistant, how many decisions fell into each class and threat pattern, which incidents have packets, and how the underwriter's own team can independently verify the record with the offline verifier. Any reference to a specific policy form or wording is the insurer's; this summary maps to none.";
        readonly reviewStatus: "DRAFT — wording requires counsel review before customer-visible use. This summary reports counts and verification facts; it does not rate risk, does not represent coverage, and does not state that any control was sufficient.";
        readonly sections: readonly [{
            readonly id: "period";
            readonly heading: "Coverage period this evidence spans";
            readonly evidence: readonly ["window", "generatedAt"];
            readonly note: "The packet window is the reporting period the organisation chose (a policy year, a quarter). Evidence outside it is not in this summary.";
        }, {
            readonly id: "pack";
            readonly heading: "Rule pack in force — id, semantic version, bundle version, signing key";
            readonly evidence: readonly ["timeline.policy.decision.packs"];
            readonly note: "Every decision row carries the label of the signed pack that governed it, so a change of pack version inside the period is visible row by row rather than asserted.";
        }, {
            readonly id: "mode";
            readonly heading: "Enforcement posture over the period — observe versus enforce";
            readonly evidence: readonly ["timeline.policy.decision.mode"];
            readonly note: "In observe mode decisions are computed and recorded but not acted on; in enforce mode holds and denials take effect. The mode is in every decision row, so the date the organisation graduated from observe to enforce is derivable, not claimed.";
        }, {
            readonly id: "decision-classes";
            readonly heading: "Decisions by taxonomy class and by threat pattern (P1–P9), with outcomes";
            readonly evidence: readonly ["counts.decisions", "counts.rulesFired", "timeline.policy.decision.classes", "timeline.policy.decision.outcome"];
            readonly note: "Derived from the timeline: how many mail sends were held, how many mail rules were denied, how many payments were held then approved, how many decisions rested on a heuristic classification versus a vendor-verified one, and how many tools were unknown to the pack (decided by the default). The evidence-summary helper recomputes these from the packet.";
        }, {
            readonly id: "human-oversight";
            readonly heading: "Oversight volume — holds issued, approvals granted, approvals consumed";
            readonly evidence: readonly ["counts.gatewayActions", "counts.approvalsGranted", "counts.approvalsConsumed"];
            readonly note: "Held minus consumed is the count of held actions that were declined or never approved.";
        }, {
            readonly id: "tool-integrity";
            readonly heading: "Tool-description integrity — pins, drift events, human re-pins";
            readonly evidence: readonly ["timeline.gateway.tool_pinned", "timeline.gateway.tool_drift", "timeline.gateway.tool_repinned"];
            readonly note: "A drift event is a tool that changed what it claimed to do after it was trusted; the breaker refused it until a human re-pinned. Zero drift events with zero pins means the breaker never saw a tools/list, which is itself a fact worth reading.";
        }, {
            readonly id: "incidents";
            readonly heading: "Incidents in the period, each with its evidence packet reference";
            readonly evidence: readonly ["disclosures.verified"];
            readonly note: "Customer-supplied list of incident packet ids (exec-incident-packet) generated in the period; the organisation attaches packet hashes as disclosures so the underwriter can match summary to packet.";
        }, {
            readonly id: "verification";
            readonly heading: "Independent verification — step by step";
            readonly evidence: readonly ["integrity.chainIntact", "integrity.signatureCoverage", "integrity.signedTreeHead", "integrity.root", "integrity.verifyInstructions"];
            readonly note: "1. Obtain the exported evidence bundle and the pinned public key (key id shown in the signed tree head) from the organisation. 2. Run the offline verify capability with the bundle and key: it recomputes the tree head over every record and checks the signature — no network, no DeepSweep service. 3. Confirm the tree head and root here match the bundle's. 4. Spot-check any decision row: recompute SHA-256 over an attached disclosure and compare to the recorded digest. 5. Re-derive the counts above from the timeline. A step that fails means the record was altered or is incomplete.";
        }, {
            readonly id: "standing";
            readonly heading: "Standing of this document";
            readonly evidence: readonly ["standing", "template.reviewStatus"];
            readonly note: "Evidence supporting the organisation's own statements to its insurer; not a statement that any control was sufficient, not a coverage representation.";
        }];
    };
    readonly "iso-42001": {
        readonly templateId: "iso-42001";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "ISO/IEC 42001:2023 — evidence mapping (Annex A controls)";
        readonly regime: "ISO/IEC 42001:2023 Annex A; control ids to be verified against the licensed standard text by the reviewer";
        readonly reviewStatus: "DRAFT — control ids require verification against the standard by the reviewer before customer-visible use";
        readonly sections: readonly [{
            readonly id: "a6";
            readonly heading: "A.6 AI system life cycle — operation and monitoring records";
            readonly evidence: readonly ["timeline", "decisions"];
        }, {
            readonly id: "a8";
            readonly heading: "A.8 Information for interested parties — incident and event records";
            readonly evidence: readonly ["blockedCalls", "heldCalls", "approvals"];
        }, {
            readonly id: "a9";
            readonly heading: "A.9 Use of AI systems — responsible-use policy and human oversight";
            readonly evidence: readonly ["rules", "approvals", "principals"];
        }, {
            readonly id: "integrity";
            readonly heading: "Records integrity (cl. 7.5 documented information)";
            readonly evidence: readonly ["treeHead", "chainIntact", "signatureCoverage"];
        }];
    };
    readonly "nist-ai-rmf": {
        readonly templateId: "nist-ai-rmf";
        readonly templateVersion: "0.1.0-draft";
        readonly title: "NIST AI RMF 1.0 — evidence mapping (GOVERN / MAP / MEASURE / MANAGE)";
        readonly regime: "NIST AI 100-1 (January 2023) core functions; subcategory ids to be verified against the current Playbook by the reviewer";
        readonly reviewStatus: "DRAFT — control ids require verification against the current NIST AI RMF Playbook before customer-visible use";
        readonly sections: readonly [{
            readonly id: "govern";
            readonly heading: "GOVERN — policies, processes and accountability are in place (GOVERN 1.x, 4.x)";
            readonly evidence: readonly ["rules", "principals"];
        }, {
            readonly id: "map";
            readonly heading: "MAP — context, capabilities and impacts are identified (MAP 1.x, 3.x)";
            readonly evidence: readonly ["servers", "tools"];
        }, {
            readonly id: "measure";
            readonly heading: "MEASURE — risks are tracked with appropriate methods (MEASURE 2.x)";
            readonly evidence: readonly ["decisions", "blockedCalls", "heldCalls"];
        }, {
            readonly id: "manage";
            readonly heading: "MANAGE — risks are prioritised, responded to and documented (MANAGE 2.x, 4.x)";
            readonly evidence: readonly ["approvals", "timeline", "treeHead"];
        }];
    };
};
