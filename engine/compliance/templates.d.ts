export interface TemplateSection {
    readonly id: string;
    readonly heading: string;
    /** Which packet facts answer this section (see packet.ts). */
    readonly evidence: readonly string[];
    readonly note?: string;
}
export interface ComplianceTemplate {
    readonly templateId: string;
    readonly templateVersion: string;
    readonly title: string;
    readonly regime: string;
    readonly reviewStatus: string;
    readonly sections: readonly TemplateSection[];
}
export declare const TEMPLATE_IDS: readonly ["incident-nis2-24h", "incident-gdpr-72h", "incident-aiact-15d", "article-50-transparency", "nist-ai-rmf", "iso-42001", "exec-incident-packet", "insurer-evidence-summary", "incident-hipaa-60d", "incident-nydfs-72h", "incident-osfi-24h"];
export type TemplateId = (typeof TEMPLATE_IDS)[number];
export declare function isTemplateId(v: unknown): v is TemplateId;
export declare function loadTemplate(id: TemplateId): ComplianceTemplate;
