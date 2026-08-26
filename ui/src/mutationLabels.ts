import type {
  ComparisonLabel,
  ExperimentRole,
  KnownExperimentRole,
  MutationRecordStatus,
  PrecisionChangeLabel,
} from "./mutationApi";

export type FalsePositiveStatus = "clean" | "dirty" | "unmeasured";

const FAMILY_LABELS: Record<string, string> = {
  flow: "Flow",
  pcre: "PCRE",
  sticky_buffer: "Sticky buffer",
  destination_port: "Destination port",
  relative_constraint: "Relative constraint",
  buffer_size: "Buffer size",
  byte_test: "Byte test",
  content_modifier: "Content modifier",
  negated_content: "Negated content",
  content: "Content",
  baseline: "Baseline",
};

const FP_LABELS: Record<FalsePositiveStatus, string> = {
  clean: "Clean",
  dirty: "False positive",
  unmeasured: "Unmeasured",
};

const RECORD_STATUS_LABELS: Record<MutationRecordStatus, string> = {
  evaluated: "Evaluated",
  syntax_invalid: "Syntax validation failed",
  positive_recall_failed: "Positive recall gate failed",
  attacker_provider_failed: "Attacker provider failure",
  attacker_parse_failed: "Attacker response parse failure",
  attacker_empty_response: "Attacker returned an empty response",
  attacker_empty_prediction: "Attacker returned no CVE prediction",
};

const COMPARISON_LABELS: Record<ComparisonLabel, string> = {
  improved_obscurity: "improved obscurity",
  reinforced_obscurity: "reinforced obscurity",
  lost_obscurity: "lost obscurity",
  no_obscurity_change: "no obscurity change",
  unmeasured: "unmeasured",
};

const PRECISION_CHANGE_LABELS: Record<PrecisionChangeLabel, string> = {
  precision_only_cost: "Precision-only cost",
  no_precision_cost: "No precision cost",
  unmeasured: "Precision change unmeasured",
};

const EXPERIMENT_ROLE_LABELS: Record<KnownExperimentRole, string> = {
  primary: "Primary experiment",
  near_cve_confusion_control: "Near-CVE confusion control",
};

const ATTACKER_FAILURE_STATUSES = new Set<MutationRecordStatus>([
  "attacker_provider_failed",
  "attacker_parse_failed",
  "attacker_empty_response",
  "attacker_empty_prediction",
]);

const VALIDATION_GATE_STATUSES = new Set<MutationRecordStatus>([
  "syntax_invalid",
  "positive_recall_failed",
]);

function measuredRate(value: unknown): number | null {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return null;
  }
  return value;
}

export function formatFamilyLabel(component: string): string {
  const known = FAMILY_LABELS[component];
  if (known) {
    return known;
  }
  return component
    .split("_")
    .filter(Boolean)
    .map((part, index) => {
      const lower = part.toLowerCase();
      return index === 0
        ? lower.charAt(0).toUpperCase() + lower.slice(1)
        : lower;
    })
    .join(" ");
}

export function formatMutationLabel(value: string): string {
  const label = value
    .replace(/[_-]+/g, " ")
    .trim()
    .toLowerCase();
  return label
    ? label.charAt(0).toUpperCase() + label.slice(1)
    : "Unknown";
}

export function formatComparisonLabel(
  measure: "exact" | "effective",
  comparison: string | null | undefined,
): string {
  const measureLabel = measure === "exact" ? "Exact" : "Effective";
  const known = comparison
    ? COMPARISON_LABELS[comparison as ComparisonLabel]
    : undefined;
  const outcome = known
    ?? (comparison ? formatMutationLabel(comparison) : "unmeasured");
  return `${measureLabel} comparison: ${outcome}`;
}

export function formatExperimentRole(
  role: ExperimentRole | null | undefined,
): string {
  if (!role) {
    return "Experiment role unassigned";
  }
  return (
    EXPERIMENT_ROLE_LABELS[role as KnownExperimentRole]
    ?? formatMutationLabel(role)
  );
}

export function formatPrecisionChange(
  change: string | null | undefined,
): string {
  if (!change) {
    return PRECISION_CHANGE_LABELS.unmeasured;
  }
  return (
    PRECISION_CHANGE_LABELS[change as PrecisionChangeLabel]
    ?? formatMutationLabel(change)
  );
}

export function formatSourceBlockLabel(block: {
  candidate_id: string;
  join_status: "available" | "unavailable";
  component: string | null;
  operator: string | null;
}): string {
  if (
    block.join_status === "unavailable"
    || block.component === null
    || block.operator === null
  ) {
    return `Unavailable source block (${block.candidate_id})`;
  }
  return `${formatFamilyLabel(block.component)} / ${formatMutationLabel(block.operator)}`;
}

export function formatRate(value: number | null | undefined): string {
  return typeof value === "number" && !Number.isNaN(value)
    ? `${Math.round(value * 100)}%`
    : "Unmeasured";
}

export function formatRelationship(value: string | null | undefined): string {
  return value ? formatMutationLabel(value) : "Unavailable";
}

export function formatRecordStatus(status: MutationRecordStatus): string {
  return RECORD_STATUS_LABELS[status] ?? formatMutationLabel(String(status));
}

/** Join banner fragments without running two sentences together. */
export function asSentence(text: string): string {
  const trimmed = text.trim();
  return !trimmed || /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`;
}

export function isAttackerFailureStatus(status: MutationRecordStatus): boolean {
  return ATTACKER_FAILURE_STATUSES.has(status);
}

export function isValidationGateStatus(status: MutationRecordStatus): boolean {
  return VALIDATION_GATE_STATUSES.has(status);
}

const RECORD_STATUS_BANNERS: Record<MutationRecordStatus, string | null> = {
  evaluated: null,
  syntax_invalid:
    "The mutated rule failed syntax validation, so the attacker did not run.",
  positive_recall_failed:
    "The mutated rule failed the positive-recall gate, so the attacker did not run.",
  attacker_provider_failed: "The attacker ran, but the model provider failed.",
  attacker_parse_failed:
    "The attacker ran, but its response could not be parsed.",
  attacker_empty_response: "The attacker ran, but returned an empty response.",
  attacker_empty_prediction:
    "The attacker ran, but returned no CVE prediction.",
};

export function recordStatusBanner(status: MutationRecordStatus): string | null {
  return RECORD_STATUS_BANNERS[status] ?? null;
}

export function fpStatus(rate: number | null | undefined): FalsePositiveStatus {
  const measured = measuredRate(rate);
  if (measured === null) {
    return "unmeasured";
  }
  return measured === 0 ? "clean" : "dirty";
}

export function syntheticFpStatus(record: {
  negative_false_positive_rate: number | null | undefined;
}): FalsePositiveStatus {
  return fpStatus(record.negative_false_positive_rate);
}

export function benignFpStatus(record: {
  benign_false_positive_rate: number | null | undefined;
}): FalsePositiveStatus {
  return fpStatus(record.benign_false_positive_rate);
}

export function formatFpLabel(status: FalsePositiveStatus): string {
  return FP_LABELS[status] ?? FP_LABELS.unmeasured;
}
