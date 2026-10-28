/**
 * TEAM-ADR-072: one inspection record per source, from what the detectors
 * stamped at their reads.
 *
 * A source observed more than once keeps its STRONGEST limitation: a parse
 * by one reader never hides another reader's refusal of the same file. A
 * source the legacy arrays name but no detector stamped is "unknown", never
 * assumed parsed (X-580: absence of a warning is not parsing evidence).
 */
import type { DetectorInspection } from "./detectors/detector.js";
import type { SourceInspection, SourceInspectionStatus } from "./types.js";
/** Strongest limitation first. Only the last two are positive evidence. */
export declare const INSPECTION_PRECEDENCE: readonly SourceInspectionStatus[];
/**
 * The statuses that are evidence a structured reader understood the whole
 * document. Anything else can never make a source comparable across reviews.
 */
export declare const COMPARABLE_INSPECTIONS: ReadonlySet<SourceInspectionStatus>;
export declare function mergeInspections(observed: ReadonlyArray<{
    detector: string;
    inspection: DetectorInspection;
}>, legacySources: readonly string[]): SourceInspection[];
