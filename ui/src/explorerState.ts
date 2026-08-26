import type {
  MutationRunOmission,
  MutationRunSummary,
  MutationRunsResponse,
} from "./mutationApi";

export const DEFAULT_MUTATION_RUN_ID = "dataset-component-mutations-v2";

/**
 * The run list and the record index are separate requests that fail for
 * separate reasons, so their errors and retry keys are tracked separately: a
 * healthy run list must never erase a record failure the user is still looking
 * at, and retrying one request must not re-issue the other.
 *
 * `recordsRunId` names the run the currently held records belong to, which is
 * what lets the view stay in a loading state from the moment a run is picked
 * until that run's own index arrives.
 */
export type ExplorerLoadState = {
  runs: MutationRunSummary[];
  omittedRuns: MutationRunOmission[];
  omittedRunCount: number;
  selectedRunId: string | null;
  recordsRunId: string | null;
  runsError: string | null;
  recordsError: string | null;
};

export type ExplorerRetryState = {
  runsRetry: number;
  recordsRetry: number;
};

export function initialExplorerLoadState(): ExplorerLoadState {
  return {
    runs: [],
    omittedRuns: [],
    omittedRunCount: 0,
    selectedRunId: null,
    recordsRunId: null,
    runsError: null,
    recordsError: null,
  };
}

export function initialExplorerRetryState(): ExplorerRetryState {
  return { runsRetry: 0, recordsRetry: 0 };
}

export function chooseDefaultMutationRun(
  runs: MutationRunSummary[],
): string | null {
  return runs.find((run) => run.run_id === DEFAULT_MUTATION_RUN_ID)?.run_id
    ?? runs.find((run) => run.run_id.endsWith("-v2"))?.run_id
    ?? runs[0]?.run_id
    ?? null;
}

export function nextSelectedRun(
  current: string | null,
  runs: MutationRunSummary[],
): string | null {
  return current !== null && runs.some((run) => run.run_id === current)
    ? current
    : chooseDefaultMutationRun(runs);
}

export function explorerErrorMessage(
  reason: unknown,
  fallback: string,
): string {
  return reason instanceof Error && reason.message ? reason.message : fallback;
}

export function applyRunsLoaded(
  state: ExplorerLoadState,
  listing: MutationRunsResponse,
): ExplorerLoadState {
  const omittedRuns = listing.omitted_runs ?? [];
  return {
    ...state,
    runs: listing.runs,
    omittedRuns,
    omittedRunCount: listing.omitted_run_count ?? omittedRuns.length,
    selectedRunId: nextSelectedRun(state.selectedRunId, listing.runs),
    runsError: null,
  };
}

export function applyRunsFailed(
  state: ExplorerLoadState,
  reason: unknown,
): ExplorerLoadState {
  return {
    ...state,
    runsError: explorerErrorMessage(reason, "Unable to load mutation runs."),
  };
}

export function applyRecordsLoaded(
  state: ExplorerLoadState,
  runId: string,
): ExplorerLoadState {
  return { ...state, recordsRunId: runId, recordsError: null };
}

export function applyRecordsFailed(
  state: ExplorerLoadState,
  reason: unknown,
): ExplorerLoadState {
  return {
    ...state,
    recordsError: explorerErrorMessage(
      reason,
      "Unable to load mutation index.",
    ),
  };
}

export function selectExplorerRun(
  state: ExplorerLoadState,
  runId: string,
): ExplorerLoadState {
  return { ...state, selectedRunId: runId, recordsError: null };
}

/** Discard the held index so a refetch shows loading rather than stale rows. */
export function beginRecordsReload(
  state: ExplorerLoadState,
): ExplorerLoadState {
  return { ...state, recordsRunId: null, recordsError: null };
}

/**
 * True from the instant a run is selected until that run's index resolves or
 * fails, so the table is never briefly rendered with another run's rows or with
 * the empty-result copy of an index that has not been requested yet.
 */
export function isRecordIndexPending(state: ExplorerLoadState): boolean {
  if (state.selectedRunId === null || state.recordsError !== null) return false;
  return state.recordsRunId !== state.selectedRunId;
}

export function retryRuns(state: ExplorerRetryState): ExplorerRetryState {
  return { ...state, runsRetry: state.runsRetry + 1 };
}

export function retryRecords(state: ExplorerRetryState): ExplorerRetryState {
  return { ...state, recordsRetry: state.recordsRetry + 1 };
}
