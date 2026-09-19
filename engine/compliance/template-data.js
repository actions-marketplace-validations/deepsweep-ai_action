/**
 * GENERATED MIRROR of contracts/templates/*.json (TEAM-ADR-038) — the compiled
 * engine needs no filesystem lookup for templates, and importing JSON from
 * outside src/ would drag contracts/ into the tsc root and break the dist
 * layout. tests/compliance/packet.test.ts asserts byte-equality with the JSON
 * source, so this file cannot drift; regenerate with:
 *   node scripts/gen-templates.mjs
 */
export const TEMPLATE_DATA = {
    "article-50-transparency": {
        "templateId": "article-50-transparency",
        "templateVersion": "0.1.0-draft",
        "title": "EU AI Act Article 50 transparency — agent-activity evidence annex",
        "regime": "Regulation (EU) 2024/1689, Article 50 (transparency obligations for providers and deployers of certain AI systems), applicable from 2 August 2026",
        "reviewStatus": "DRAFT — Article 50 duties concern disclosure TO natural persons and marking of synthetic content; this annex evidences WHICH agents acted, WHEN and under WHAT policy so those disclosures can be substantiated. It does not itself satisfy Article 50. Counsel review required.",
        "sections": [
            {
                "id": "inventory",
                "heading": "Agents (principals) and tool surfaces active in the window",
                "evidence": [
                    "principals",
                    "servers",
                    "tools"
                ]
            },
            {
                "id": "governance",
                "heading": "Policy in force and decisions taken",
                "evidence": [
                    "rules",
                    "decisions"
                ]
            },
            {
                "id": "timeline",
                "heading": "Action timeline",
                "evidence": [
                    "timeline"
                ]
            },
            {
                "id": "integrity",
                "heading": "Integrity of this record",
                "evidence": [
                    "treeHead",
                    "chainIntact",
                    "signatureCoverage",
                    "verifyInstructions"
                ]
            }
        ]
    },
    "exec-incident-packet": {
        "templateId": "exec-incident-packet",
        "templateVersion": "0.1.0-draft",
        "title": "Executive-assistant incident packet — agent-activity evidence for the 24h / 72h / 15-day reporting clocks",
        "regime": "Cross-regime incident narrative for an executive-facing AI assistant governed by the EXEC-1 rule pack: NIS2 Art. 23(4)(a) early warning (24h) → GDPR Art. 33(1)/(3) personal-data-breach notification (72h) → EU AI Act Art. 73 serious-incident report (15 days). Each clock's own annex (incident-nis2-24h, incident-gdpr-72h, incident-aiact-15d) remains the regime-specific artifact; this packet is the incident's single evidence spine those annexes cite. Every citation here is draft-unverified until compliance/REG-VERIFY.md marks it verified.",
        "reviewStatus": "DRAFT — regulatory mapping requires counsel review before customer-visible use. Whether an assistant incident is a NIS2 'significant incident', a GDPR 'personal data breach' or an AI Act 'serious incident' is a legal determination the deploying organisation makes; this packet supplies the evidence, not the determination.",
        "sections": [
            {
                "id": "clock",
                "heading": "Reporting clocks — time of awareness and the 24h / 72h / 15-day windows",
                "evidence": [
                    "window",
                    "generatedAt"
                ],
                "note": "The packet window opens at the customer's asserted time of awareness. All three clocks run from awareness; the packet states the window and lets each annex compute its deadline."
            },
            {
                "id": "principal",
                "heading": "Which assistant, acting for which principal, under which pack version",
                "evidence": [
                    "timeline.policy.decision.principalHash",
                    "timeline.policy.decision.packs",
                    "counts.principals"
                ],
                "note": "The principal is a hash; the pack label carries pack id, version, bundle version and signing key id so an independent party can confirm which signed rules governed. Plaintext identity enters only as a hash-verified selective disclosure from the customer's own records."
            },
            {
                "id": "sequence",
                "heading": "What the assistant tried to do, in order — decisions, holds, denials, approvals",
                "evidence": [
                    "timeline",
                    "counts.decisions",
                    "counts.gatewayActions",
                    "counts.approvalsGranted",
                    "counts.approvalsConsumed",
                    "counts.rulesFired"
                ],
                "note": "Each tool call is a decision row (class labels + deciding rule) followed by the gateway's action (forwarded · blocked · held · approved) and, when forwarded, the result row. Untrusted-ingest classes on a read followed by a held or blocked external write show the injection-to-exfiltration chain without any content."
            },
            {
                "id": "threat-patterns",
                "heading": "Threat patterns implicated (P1–P9) and how each was treated",
                "evidence": [
                    "counts.rulesFired",
                    "timeline.policy.decision.classes",
                    "timeline.policy.decision.rule"
                ],
                "note": "Rule names carry the pattern id (P1 external send, P2 mail rules, P3 finance, P4 calendar, P5 documents, P6 send-as/delegation, P7 untrusted ingest → external write, P8 tool drift, P9 cross-agent). A pattern that fired as deny or require-approval is a control that held at the moment of the event."
            },
            {
                "id": "disclosures",
                "heading": "Selective disclosures — what content the organisation chooses to reveal, verified against recorded digests",
                "evidence": [
                    "disclosures.verified",
                    "disclosures.refused"
                ],
                "note": "Recipients, subject lines, file names or amounts appear here ONLY if the organisation attaches them from its own vault and they reproduce the SHA-256 recorded at the time. A disclosure that does not reproduce is listed as refused and is never cited."
            },
            {
                "id": "human-oversight",
                "heading": "Oversight controls exercised — approvals, denials without approval path, tool re-pins",
                "evidence": [
                    "counts.approvalsGranted",
                    "counts.approvalsConsumed",
                    "timeline.approval.granted",
                    "timeline.approval.consumed",
                    "timeline.gateway.tool_repinned"
                ],
                "note": "A held call cleared by an out-of-band approval step, and the exact-tuple retry that followed, is the oversight record. The entries prove the approval protocol ran and carry the approver name it was given; they do not authenticate that approver as a person. Denials with no approval path (mail rules, payee creation) show the control was absolute at the time."
            },
            {
                "id": "integrity",
                "heading": "How an independent party re-verifies this packet offline",
                "evidence": [
                    "integrity.chainIntact",
                    "integrity.signatureCoverage",
                    "integrity.signedTreeHead",
                    "integrity.root",
                    "integrity.verifyInstructions"
                ],
                "note": "Hash chain intact, per-entry signature coverage, and the signed RFC 6962 tree head over the ledger. Verification needs the exported evidence bundle and the pinned public key — nothing from DeepSweep at run time."
            },
            {
                "id": "standing",
                "heading": "Standing of this document",
                "evidence": [
                    "standing",
                    "template.reviewStatus"
                ],
                "note": "Evidence supporting the deploying organisation's own compliance process; not a legal conclusion."
            }
        ]
    },
    "incident-aiact-15d": {
        "templateId": "incident-aiact-15d",
        "templateVersion": "0.1.0-draft",
        "title": "EU AI Act serious-incident report (15 days) — agent-activity evidence annex",
        "regime": "Regulation (EU) 2024/1689, Article 73(1)-(4): serious incident reporting not later than 15 days after awareness (Art. 73(2)) (2 days for widespread infringement / serious and irreversible disruption; 10 days for death); Article 73(6) investigation and record-keeping; Article 26(5) deployer duty to inform the provider",
        "reviewStatus": "DRAFT — regulatory mapping requires counsel review before customer-visible use. Whether the deploying organisation is a provider (Art. 25) is a legal determination the packet does not make.",
        "sections": [
            {
                "id": "system",
                "heading": "AI system and deployment identification",
                "evidence": [
                    "principals",
                    "servers",
                    "tools"
                ],
                "note": "Hashed identifiers; the customer maps hashes to names from its own inventory (or attaches disclosures)."
            },
            {
                "id": "incident",
                "heading": "Description of the incident and the causal link to the AI system",
                "evidence": [
                    "timeline",
                    "disclosures"
                ]
            },
            {
                "id": "measures",
                "heading": "Corrective measures and risk-mitigation already taken",
                "evidence": [
                    "blockedCalls",
                    "heldCalls",
                    "approvals",
                    "denyRules"
                ]
            },
            {
                "id": "oversight",
                "heading": "Art. 14 human-oversight posture as deployed — holds, approvals, permitted retries",
                "evidence": [
                    "approvals"
                ],
                "note": "denial → out-of-band approval → permitted retry entries evidence the oversight mechanism operating in the loop; the approver identity is recorded as supplied, not authenticated."
            },
            {
                "id": "integrity",
                "heading": "Integrity and reproducibility of this record",
                "evidence": [
                    "treeHead",
                    "chainIntact",
                    "signatureCoverage",
                    "verifyInstructions"
                ]
            }
        ]
    },
    "incident-gdpr-72h": {
        "templateId": "incident-gdpr-72h",
        "templateVersion": "0.1.0-draft",
        "title": "GDPR personal-data-breach notification (72h) — agent-activity evidence annex",
        "regime": "Regulation (EU) 2016/679, Article 33(1) notification within 72 hours; Article 33(3) minimum content; Article 33(5) documentation duty",
        "reviewStatus": "DRAFT — regulatory mapping requires counsel review before customer-visible use",
        "sections": [
            {
                "id": "nature",
                "heading": "Nature of the breach incl. categories and approximate number of data subjects and records (Art. 33(3)(a))",
                "evidence": [
                    "timeline",
                    "disclosures"
                ],
                "note": "Which tools an agent invoked, when, and under which decision — data categories/counts only from hash-verified disclosures."
            },
            {
                "id": "contact",
                "heading": "Data protection officer / contact point (Art. 33(3)(b))",
                "evidence": [],
                "note": "Customer-supplied; not derivable from evidence."
            },
            {
                "id": "consequences",
                "heading": "Likely consequences (Art. 33(3)(c))",
                "evidence": [
                    "disclosures"
                ],
                "note": "Customer assessment; the packet cites which verified disclosures support it."
            },
            {
                "id": "measures",
                "heading": "Measures taken or proposed, incl. mitigation (Art. 33(3)(d))",
                "evidence": [
                    "blockedCalls",
                    "heldCalls",
                    "approvals",
                    "denyRules"
                ],
                "note": "Policy denials, holds and human approvals are measures already in force at the moment of the event."
            },
            {
                "id": "documentation",
                "heading": "Documentation enabling the supervisory authority to verify compliance (Art. 33(5))",
                "evidence": [
                    "treeHead",
                    "chainIntact",
                    "signatureCoverage",
                    "verifyInstructions"
                ]
            }
        ]
    },
    "incident-hipaa-60d": {
        "templateId": "incident-hipaa-60d",
        "templateVersion": "0.1.0-draft",
        "title": "HIPAA breach notification (60 days) — agent-activity evidence annex",
        "regime": "45 CFR §§ 164.400–414 (HIPAA Breach Notification Rule): § 164.404 individual notice without unreasonable delay and no later than 60 calendar days from discovery; § 164.404(c) content; § 164.406 media notice (500+ in a state); § 164.408 notice to the Secretary; § 164.410 business-associate notice to the covered entity within 60 days; § 164.402(2) risk-assessment factors; § 164.414(b) burden of proof on the covered entity",
        "reviewStatus": "DRAFT — regulatory mapping requires counsel review before customer-visible use",
        "sections": [
            {
                "id": "discovery",
                "heading": "Date of discovery and the 60-day window (§ 164.404(a)(2), (b))",
                "evidence": [
                    "window",
                    "generatedAt"
                ],
                "note": "The 60 days run from the day the breach is known or should reasonably have been known. The packet's window start is the customer's asserted discovery time; the evidence bounds when agent activity in scope actually occurred."
            },
            {
                "id": "what-happened",
                "heading": "Brief description of what happened, incl. dates of the breach and of discovery (§ 164.404(c)(1)(A))",
                "evidence": [
                    "timeline",
                    "disclosures"
                ],
                "note": "Which tools an agent invoked, when, under which decision, and against which resources — from the hash-chained timeline; free-text description remains the customer's."
            },
            {
                "id": "phi-involved",
                "heading": "Types of unsecured PHI involved (§ 164.404(c)(1)(B))",
                "evidence": [
                    "disclosures.verified"
                ],
                "note": "The evidence record is metadata-first and never stores PHI. Data categories come only from customer-verified disclosures whose hashes bind them to the recorded events; the record proves WHICH resources were touched, not their contents."
            },
            {
                "id": "risk-assessment",
                "heading": "Risk assessment: was PHI actually acquired or viewed (§ 164.402(2)(iii))",
                "evidence": [
                    "timeline",
                    "blockedCalls",
                    "heldCalls",
                    "denyRules"
                ],
                "note": "The factor that decides whether an impermissible use is a reportable breach. A tamper-evident record of what the agent saw, decided, and executed — including calls blocked or held BEFORE execution — is direct evidence on acquisition-or-viewing, and its absence is what forces worst-case assumptions."
            },
            {
                "id": "mitigation",
                "heading": "Steps taken to investigate, mitigate, and protect against further breaches (§ 164.404(c)(1)(D)–(E), § 164.402(2)(iv))",
                "evidence": [
                    "blockedCalls",
                    "heldCalls",
                    "approvals",
                    "denyRules"
                ],
                "note": "Policy denials, holds and out-of-band approvals in force at the moment of the event are mitigation already operating, not remediation promised."
            },
            {
                "id": "burden-of-proof",
                "heading": "Burden of proof: demonstrating notifications were made or that no breach occurred (§ 164.414(b))",
                "evidence": [
                    "treeHead",
                    "chainIntact",
                    "signatureCoverage",
                    "verifyInstructions"
                ],
                "note": "The covered entity carries the burden. An externally anchored, append-only record that a third party can verify offline is the demonstration instrument; a mutable log is an assertion."
            }
        ]
    },
    "incident-nis2-24h": {
        "templateId": "incident-nis2-24h",
        "templateVersion": "0.1.0-draft",
        "title": "NIS2 early warning (24h) — agent-activity evidence annex",
        "regime": "Directive (EU) 2022/2555 (NIS2), Article 23(4)(a) early warning within 24 hours of awareness",
        "reviewStatus": "DRAFT — regulatory mapping requires counsel review before customer-visible use",
        "sections": [
            {
                "id": "awareness",
                "heading": "Time of awareness and reporting window",
                "evidence": [
                    "window",
                    "generatedAt"
                ],
                "note": "24h runs from awareness; the packet's window start is the customer's asserted awareness time."
            },
            {
                "id": "malicious",
                "heading": "Whether the incident is suspected to be caused by unlawful or malicious acts",
                "evidence": [
                    "blockedCalls",
                    "heldCalls",
                    "denyRules"
                ],
                "note": "Denied/held tool calls and the rules that fired are indicators, not conclusions."
            },
            {
                "id": "crossBorder",
                "heading": "Possible cross-border impact",
                "evidence": [
                    "disclosures"
                ],
                "note": "Populated only from customer-attached, hash-verified disclosures (e.g. which systems the tools reached)."
            },
            {
                "id": "timeline",
                "heading": "Agent action timeline (what it saw, decided, executed)",
                "evidence": [
                    "timeline"
                ]
            },
            {
                "id": "integrity",
                "heading": "Integrity of this record",
                "evidence": [
                    "treeHead",
                    "chainIntact",
                    "signatureCoverage"
                ]
            }
        ]
    },
    "incident-nydfs-72h": {
        "templateId": "incident-nydfs-72h",
        "templateVersion": "0.1.0-draft",
        "title": "NYDFS Part 500 cybersecurity-event notice (72h) — agent-activity evidence annex",
        "regime": "23 NYCRR Part 500 (as amended 2023): § 500.17(a) notice to the Superintendent within 72 hours of determining a cybersecurity event occurred at the covered entity, an affiliate, or a third-party service provider; § 500.17(c) 24-hour ransom-payment notice; § 500.6 audit trail — records designed to reconstruct material financial transactions and detect and respond to events, retained per rule",
        "reviewStatus": "DRAFT — regulatory mapping requires counsel review before customer-visible use",
        "sections": [
            {
                "id": "determination",
                "heading": "Time of determination and the 72-hour window (§ 500.17(a))",
                "evidence": [
                    "window",
                    "generatedAt"
                ],
                "note": "72h runs from the covered entity's DETERMINATION that a reportable event occurred; the packet's window start is the customer's asserted determination time. The 24-hour ransom-payment clock (§ 500.17(c)) is separate and shorter."
            },
            {
                "id": "event-description",
                "heading": "Description of the cybersecurity event for the DFS portal filing",
                "evidence": [
                    "timeline",
                    "servers",
                    "tools",
                    "principals"
                ],
                "note": "Which agent principals invoked which tools against which servers, in order, from the hash-chained timeline — the reconstruction § 500.6 exists to enable."
            },
            {
                "id": "audit-trail",
                "heading": "Audit-trail duty: records that reconstruct events (§ 500.6)",
                "evidence": [
                    "treeHead",
                    "chainIntact",
                    "signatureCoverage",
                    "verifyInstructions"
                ],
                "note": "§ 500.6 requires audit trails DESIGNED to reconstruct events. An append-only record with externally anchored heads and offline third-party verification is that design property, demonstrable to an examiner rather than asserted."
            },
            {
                "id": "controls-in-force",
                "heading": "Controls operating at the time of the event",
                "evidence": [
                    "blockedCalls",
                    "heldCalls",
                    "approvals",
                    "denyRules",
                    "rules"
                ],
                "note": "Denials, holds and out-of-band approvals recorded in the same chain as the event are contemporaneous control evidence for the filing and the record behind the § 500.17(b) annual compliance filing."
            },
            {
                "id": "tpsp",
                "heading": "Events at third-party service providers (§ 500.17(a)(1)(iii))",
                "evidence": [
                    "servers",
                    "disclosures"
                ],
                "note": "The 2023 amendment makes TPSP events reportable. The inventory of MCP servers and external tool surfaces bounds which third-party surfaces an agent could reach; contents only via verified disclosures."
            }
        ]
    },
    "incident-osfi-24h": {
        "templateId": "incident-osfi-24h",
        "templateVersion": "0.1.0-draft",
        "title": "OSFI technology and cyber incident report (24h) — agent-activity evidence annex",
        "regime": "OSFI Technology and Cyber Security Incident Reporting Advisory (FRFIs): initial notification within 24 hours or as soon as possible after determining a reportable incident; ongoing updates until resolution; post-incident review. Guideline B-13 (Technology and Cyber Risk Management): incident management, and E-23 model-risk expectations where the agent is a model-driven system",
        "reviewStatus": "DRAFT — regulatory mapping requires counsel review before customer-visible use. OSFI's advisory is supervisory guidance; thresholds and timing language must be confirmed against the current advisory text before any customer use",
        "sections": [
            {
                "id": "determination",
                "heading": "Time of determination and the 24-hour initial notification window",
                "evidence": [
                    "window",
                    "generatedAt"
                ],
                "note": "The clock runs from determining the incident is reportable; the packet's window start is the FRFI's asserted determination time."
            },
            {
                "id": "incident-description",
                "heading": "Initial report: what occurred, systems and services affected",
                "evidence": [
                    "timeline",
                    "servers",
                    "tools",
                    "principals"
                ],
                "note": "Agent principals, tools and servers involved, in order, from the hash-chained timeline — the factual spine of the initial report and every subsequent update."
            },
            {
                "id": "updates",
                "heading": "Ongoing updates until resolution",
                "evidence": [
                    "timeline",
                    "window"
                ],
                "note": "Each update can bind to a later tree head, so 'what changed since the last report' is a provable interval, not a narrative."
            },
            {
                "id": "controls",
                "heading": "Controls and containment in force (B-13 incident management)",
                "evidence": [
                    "blockedCalls",
                    "heldCalls",
                    "approvals",
                    "denyRules"
                ],
                "note": "Contemporaneous denials, holds and approvals recorded in-chain evidence the containment posture at the moment of the event."
            },
            {
                "id": "post-incident",
                "heading": "Post-incident review and supervisory follow-up",
                "evidence": [
                    "treeHead",
                    "chainIntact",
                    "signatureCoverage",
                    "verifyInstructions"
                ],
                "note": "An externally anchored, append-only record lets the post-incident review, internal audit, and OSFI verify the same history independently — including that nothing was rewritten between the initial report and the review."
            }
        ]
    },
    "insurer-evidence-summary": {
        "templateId": "insurer-evidence-summary",
        "templateVersion": "0.1.0-draft",
        "title": "Insurer evidence summary — executive-assistant governance evidence for D&O / cyber underwriting",
        "regime": "Underwriting evidence (not a regulatory filing): the coverage period, which signed rule pack governed the executive assistant, how many decisions fell into each class and threat pattern, which incidents have packets, and how the underwriter's own team can independently verify the record with the offline verifier. Any reference to a specific policy form or wording is the insurer's; this summary maps to none.",
        "reviewStatus": "DRAFT — wording requires counsel review before customer-visible use. This summary reports counts and verification facts; it does not rate risk, does not represent coverage, and does not state that any control was sufficient.",
        "sections": [
            {
                "id": "period",
                "heading": "Coverage period this evidence spans",
                "evidence": [
                    "window",
                    "generatedAt"
                ],
                "note": "The packet window is the reporting period the organisation chose (a policy year, a quarter). Evidence outside it is not in this summary."
            },
            {
                "id": "pack",
                "heading": "Rule pack in force — id, semantic version, bundle version, signing key",
                "evidence": [
                    "timeline.policy.decision.packs"
                ],
                "note": "Every decision row carries the label of the signed pack that governed it, so a change of pack version inside the period is visible row by row rather than asserted."
            },
            {
                "id": "mode",
                "heading": "Enforcement posture over the period — observe versus enforce",
                "evidence": [
                    "timeline.policy.decision.mode"
                ],
                "note": "In observe mode decisions are computed and recorded but not acted on; in enforce mode holds and denials take effect. The mode is in every decision row, so the date the organisation graduated from observe to enforce is derivable, not claimed."
            },
            {
                "id": "decision-classes",
                "heading": "Decisions by taxonomy class and by threat pattern (P1–P9), with outcomes",
                "evidence": [
                    "counts.decisions",
                    "counts.rulesFired",
                    "timeline.policy.decision.classes",
                    "timeline.policy.decision.outcome"
                ],
                "note": "Derived from the timeline: how many mail sends were held, how many mail rules were denied, how many payments were held then approved, how many decisions rested on a heuristic classification versus a vendor-verified one, and how many tools were unknown to the pack (decided by the default). The evidence-summary helper recomputes these from the packet."
            },
            {
                "id": "human-oversight",
                "heading": "Oversight volume — holds issued, approvals granted, approvals consumed",
                "evidence": [
                    "counts.gatewayActions",
                    "counts.approvalsGranted",
                    "counts.approvalsConsumed"
                ],
                "note": "Held minus consumed is the count of held actions that were declined or never approved."
            },
            {
                "id": "tool-integrity",
                "heading": "Tool-description integrity — pins, drift events, human re-pins",
                "evidence": [
                    "timeline.gateway.tool_pinned",
                    "timeline.gateway.tool_drift",
                    "timeline.gateway.tool_repinned"
                ],
                "note": "A drift event is a tool that changed what it claimed to do after it was trusted; the breaker refused it until a human re-pinned. Zero drift events with zero pins means the breaker never saw a tools/list, which is itself a fact worth reading."
            },
            {
                "id": "incidents",
                "heading": "Incidents in the period, each with its evidence packet reference",
                "evidence": [
                    "disclosures.verified"
                ],
                "note": "Customer-supplied list of incident packet ids (exec-incident-packet) generated in the period; the organisation attaches packet hashes as disclosures so the underwriter can match summary to packet."
            },
            {
                "id": "verification",
                "heading": "Independent verification — step by step",
                "evidence": [
                    "integrity.chainIntact",
                    "integrity.signatureCoverage",
                    "integrity.signedTreeHead",
                    "integrity.root",
                    "integrity.verifyInstructions"
                ],
                "note": "1. Obtain the exported evidence bundle and the pinned public key (key id shown in the signed tree head) from the organisation. 2. Run the offline verify capability with the bundle and key: it recomputes the tree head over every record and checks the signature — no network, no DeepSweep service. 3. Confirm the tree head and root here match the bundle's. 4. Spot-check any decision row: recompute SHA-256 over an attached disclosure and compare to the recorded digest. 5. Re-derive the counts above from the timeline. A step that fails means the record was altered or is incomplete."
            },
            {
                "id": "standing",
                "heading": "Standing of this document",
                "evidence": [
                    "standing",
                    "template.reviewStatus"
                ],
                "note": "Evidence supporting the organisation's own statements to its insurer; not a statement that any control was sufficient, not a coverage representation."
            }
        ]
    },
    "iso-42001": {
        "templateId": "iso-42001",
        "templateVersion": "0.1.0-draft",
        "title": "ISO/IEC 42001:2023 — evidence mapping (Annex A controls)",
        "regime": "ISO/IEC 42001:2023 Annex A; control ids to be verified against the licensed standard text by the reviewer",
        "reviewStatus": "DRAFT — control ids require verification against the standard by the reviewer before customer-visible use",
        "sections": [
            {
                "id": "a6",
                "heading": "A.6 AI system life cycle — operation and monitoring records",
                "evidence": [
                    "timeline",
                    "decisions"
                ]
            },
            {
                "id": "a8",
                "heading": "A.8 Information for interested parties — incident and event records",
                "evidence": [
                    "blockedCalls",
                    "heldCalls",
                    "approvals"
                ]
            },
            {
                "id": "a9",
                "heading": "A.9 Use of AI systems — responsible-use policy and human oversight",
                "evidence": [
                    "rules",
                    "approvals",
                    "principals"
                ]
            },
            {
                "id": "integrity",
                "heading": "Records integrity (cl. 7.5 documented information)",
                "evidence": [
                    "treeHead",
                    "chainIntact",
                    "signatureCoverage"
                ]
            }
        ]
    },
    "nist-ai-rmf": {
        "templateId": "nist-ai-rmf",
        "templateVersion": "0.1.0-draft",
        "title": "NIST AI RMF 1.0 — evidence mapping (GOVERN / MAP / MEASURE / MANAGE)",
        "regime": "NIST AI 100-1 (January 2023) core functions; subcategory ids to be verified against the current Playbook by the reviewer",
        "reviewStatus": "DRAFT — control ids require verification against the current NIST AI RMF Playbook before customer-visible use",
        "sections": [
            {
                "id": "govern",
                "heading": "GOVERN — policies, processes and accountability are in place (GOVERN 1.x, 4.x)",
                "evidence": [
                    "rules",
                    "principals"
                ]
            },
            {
                "id": "map",
                "heading": "MAP — context, capabilities and impacts are identified (MAP 1.x, 3.x)",
                "evidence": [
                    "servers",
                    "tools"
                ]
            },
            {
                "id": "measure",
                "heading": "MEASURE — risks are tracked with appropriate methods (MEASURE 2.x)",
                "evidence": [
                    "decisions",
                    "blockedCalls",
                    "heldCalls"
                ]
            },
            {
                "id": "manage",
                "heading": "MANAGE — risks are prioritised, responded to and documented (MANAGE 2.x, 4.x)",
                "evidence": [
                    "approvals",
                    "timeline",
                    "treeHead"
                ]
            }
        ]
    },
};
