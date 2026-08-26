import { ApiError } from "./api";

export type MutationDiagnostic = {
  file: string;
  line: number;
  error: string;
};

export type MutationRunSummary = {
  run_id: string;
  fixture_count: number;
  record_count: number;
  malformed_line_count: number;
  diagnostics: MutationDiagnostic[];
};

/** A run the server could not scan at all, reported instead of being listed. */
export type MutationRunOmission = {
  run_id: string;
  error: string;
};

export type MutationRunsResponse = {
  runs: MutationRunSummary[];
  /** Absent when the listing is served by a build older than run isolation. */
  omitted_run_count?: number;
  omitted_runs?: MutationRunOmission[];
};

export type MutationRunMetadata = {
  run_id: string;
  fixture_count: number;
  record_count: number;
  diagnostics: MutationDiagnostic[];
};

export type AnalysisCategory = "semantic" | "representation" | "performance";

export type RelationshipTier =
  | "exact_match"
  | "closely_related"
  | "same_ecosystem"
  | "unclassified";

export type ExplorerQuickFilter =
  | "all"
  | "emergent_miss"
  | "balanced_emergent_miss"
  | "unbalanced_emergent_miss"
  | "closely_related_guess";

export type MutationRecordStatus =
  | "evaluated"
  | "syntax_invalid"
  | "positive_recall_failed"
  | "attacker_provider_failed"
  | "attacker_parse_failed"
  | "attacker_empty_response"
  | "attacker_empty_prediction";

export type ComparisonLabel =
  | "improved_obscurity"
  | "reinforced_obscurity"
  | "lost_obscurity"
  | "no_obscurity_change"
  | "unmeasured";

export type PrecisionChangeLabel =
  | "precision_only_cost"
  | "no_precision_cost"
  | "unmeasured";

export type KnownExperimentRole =
  | "primary"
  | "near_cve_confusion_control";

/** Backend manifests accept any nonempty role string; known values remain suggested. */
export type ExperimentRole =
  | KnownExperimentRole
  | (string & Record<never, never>);

export type SourceJoinStatus = "complete" | "unavailable";

/** Persisted lightweight fields included in index entries from explorer.py. */
export type MutationRecordLightweightFields = {
  candidate_id: string;
  component: string;
  operator: string;
  params: Record<string, unknown>;
  description: string;
  revision: number;
  fingerprint: string;
  buffer: string | null;
  option_index: number | null;
  status: MutationRecordStatus;
  syntax_valid: boolean;
  syntax_error: string | null;
  positive_recall: number | null;
  negative_false_positive_rate: number | null;
  benign_corpus_available: boolean;
  benign_false_positive_rate: number | null;
  benign_aggregate: Record<string, unknown> | null;
  benign_cache_errors: string[];
  attacker_prediction: string | null;
  attacker_correct: boolean | null;
  attacker_error: string | null;
  target_cve: string;
  relationship_tier: RelationshipTier | null;
  meaningful_obscurity: boolean | null;
  mutation_category: AnalysisCategory;
  evaluated_at: string;
  /**
   * Provenance fields were added after the completed v2 experiment, so records
   * written by the earlier evaluator omit these keys entirely.
   */
  experiment_manifest_hash?: string | null;
  source_candidate_ids?: string[] | null;
  block_count?: number | null;
  /** Present only when the backend resolved combination-run provenance. */
  experiment_role?: ExperimentRole | null;
  included_components?: string[];
  included_operators?: string[];
  included_families?: string[];
  included_block_labels?: string[];
  exact_obscurity_comparison?: ComparisonLabel;
  effective_obscurity_comparison?: ComparisonLabel;
  source_join_status?: SourceJoinStatus;
  source_join_diagnostic_count?: number;
  precision_change?: PrecisionChangeLabel;
};

/** Derived flags added only by build_index_entry(). */
export type MutationRecordIndexDerivedFields = {
  fixture: string;
  baseline_exact: boolean;
  is_emergent_miss: boolean;
  is_balanced_emergent_miss: boolean;
  is_unbalanced_emergent_miss: boolean;
  is_closely_related_guess: boolean;
};

export type MutationRecordIndexEntry =
  MutationRecordLightweightFields & MutationRecordIndexDerivedFields;

export type MutationRecordsIndexResponse = MutationRunMetadata & {
  records: MutationRecordIndexEntry[];
};

export type AttackerDetailStatus =
  | "success"
  | "provider"
  | "parse"
  | "empty_response"
  | "empty_prediction"
  | "validation";

export type AttackerDetail = {
  status: AttackerDetailStatus;
  predicted_cve: string | null;
  reasoning: string | null;
  clues: string[];
  prompt: string | null;
  raw_response: string | null;
  error: string | null;
};

export type CombinationAttribution = "hit" | "miss" | "unmeasured";

export type CombinationBuildingBlockAttacker = {
  status: AttackerDetailStatus;
  predicted_cve: string | null;
  reasoning: string | null;
  clues: string[];
  error: string | null;
};

type CombinationBuildingBlockShared = {
  baseline_rule: string | null;
};

export type CombinationBuildingBlock =
  | (CombinationBuildingBlockShared & {
      candidate_id: string;
      join_status: "available";
      component: string;
      operator: string;
      description: string;
      buffer: string | null;
      params: Record<string, unknown>;
      mutation_category: AnalysisCategory;
      positive_recall: number | null;
      negative_false_positive_rate: number | null;
      benign_false_positive_rate: number | null;
      attacker: CombinationBuildingBlockAttacker;
      attacker_prediction: string | null;
      attacker_correct: boolean | null;
      relationship_tier: RelationshipTier | null;
      meaningful_obscurity: boolean | null;
      mutated_rule: string | null;
      exact_attribution: CombinationAttribution;
      effective_attribution: CombinationAttribution;
    })
  | (CombinationBuildingBlockShared & {
      candidate_id: string;
      join_status: "unavailable";
      component: null;
      operator: null;
      description: null;
      buffer: null;
      params: null;
      mutation_category: null;
      positive_recall: null;
      negative_false_positive_rate: null;
      benign_false_positive_rate: null;
      attacker: {
        status: "unavailable";
        predicted_cve: null;
        reasoning: null;
        clues: [];
        error: null;
      };
      attacker_prediction: null;
      attacker_correct: null;
      relationship_tier: null;
      meaningful_obscurity: null;
      mutated_rule: null;
      exact_attribution: "unmeasured";
      effective_attribution: "unmeasured";
    });

export type CombinationJoinDiagnostic = {
  source_candidate_id: string | null;
  error: string;
  file?: string;
  line?: number;
};

/** Lazy-load fields added by load_mutation_record_detail(). */
export type MutationRecordDetailFields = {
  fixture: string;
  target_cve: string;
  rule: string;
  baseline_rule: string | null;
  mutated_rule: string | null;
  case_results: Record<string, Record<string, unknown>>;
  benign_capture_results: Record<string, Record<string, unknown>>;
  attacker_exchange: Record<string, unknown> | null;
  case_groups: {
    positive: Record<string, unknown>[];
    negative: Record<string, unknown>[];
    benign: Record<string, unknown>[];
  };
  suite_reason: string | null;
  attacker: AttackerDetail;
  diagnostics: MutationDiagnostic[];
  /** Detail-only projections emitted for records in resolved combination runs. */
  building_blocks?: CombinationBuildingBlock[];
  join_diagnostics?: CombinationJoinDiagnostic[];
};

export type MutationRecordDetail =
  MutationRecordLightweightFields & MutationRecordDetailFields;

async function request<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new ApiError(
      payload?.detail ?? `Request failed (${response.status})`,
      response.status,
    );
  }
  return response.json() as Promise<T>;
}

export const mutationApi = {
  runs: () => request<MutationRunsResponse>("/api/mutations/runs"),
  run: (runId: string) =>
    request<MutationRunMetadata>(
      `/api/mutations/runs/${encodeURIComponent(runId)}`,
    ),
  records: (runId: string) =>
    request<MutationRecordsIndexResponse>(
      `/api/mutations/runs/${encodeURIComponent(runId)}/records`,
    ),
  record: (runId: string, candidateId: string) =>
    request<MutationRecordDetail>(
      `/api/mutations/runs/${encodeURIComponent(runId)}/records/${encodeURIComponent(candidateId)}`,
    ),
};
