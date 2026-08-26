import { useEffect, useMemo, useState } from "react";
import {
  mutationApi,
  type MutationRecordDetail,
  type MutationRecordIndexEntry,
  type MutationRunOmission,
  type MutationRunSummary,
} from "./mutationApi";
import {
  applyRecordsFailed,
  applyRecordsLoaded,
  applyRunsFailed,
  applyRunsLoaded,
  beginRecordsReload,
  initialExplorerLoadState,
  initialExplorerRetryState,
  isRecordIndexPending,
  retryRecords,
  retryRuns,
  selectExplorerRun,
} from "./explorerState";
import {
  filterRecords,
  groupByFamily,
  isCombinationRecord,
  type ExplorerFilters,
} from "./mutationExplorer";
import { MutationDetailPanel } from "./MutationDetailPanel";
import { MutationFilterBar } from "./MutationFilterBar";
import { MutationTable } from "./MutationTable";

export const DEFAULT_EXPLORER_FILTERS: ExplorerFilters = {
  quickFilter: "all",
  fixture: "all",
  component: "all",
  operator: "all",
  status: "all",
  category: "all",
  blockCount: "all",
  includedFamily: "all",
  experimentRole: "all",
  searchText: "",
};

export function resetRunScopedFilters(
  filters: ExplorerFilters,
): ExplorerFilters {
  return {
    ...DEFAULT_EXPLORER_FILTERS,
    searchText: filters.searchText,
  };
}

type MutationApiClient = typeof mutationApi;

export function loadMutationDetail(
  client: Pick<MutationApiClient, "record">,
  runId: string,
  candidateId: string,
): Promise<MutationRecordDetail> {
  return client.record(runId, candidateId);
}

export function createLatestDetailLoader(
  client: Pick<MutationApiClient, "record">,
  handlers: {
    onSuccess: (detail: MutationRecordDetail) => void;
    onError: (reason: unknown) => void;
  },
) {
  let requestId = 0;
  return {
    async load(runId: string, candidateId: string): Promise<void> {
      const activeRequestId = ++requestId;
      try {
        const response = await loadMutationDetail(client, runId, candidateId);
        if (activeRequestId === requestId) handlers.onSuccess(response);
      } catch (reason: unknown) {
        if (activeRequestId === requestId) handlers.onError(reason);
      }
    },
    cancel() {
      requestId += 1;
    },
  };
}

export type MutationExplorerViewProps = {
  runs: MutationRunSummary[];
  selectedRunId: string | null;
  records: MutationRecordIndexEntry[];
  filters: ExplorerFilters;
  selectedCandidateId: string | null;
  detail: MutationRecordDetail | null;
  runsLoading: boolean;
  recordsLoading: boolean;
  detailLoading: boolean;
  runsError: string | null;
  recordsError: string | null;
  detailError: string | null;
  diagnostics?: { file: string; line: number; error: string }[];
  omittedRunCount: number;
  omittedRuns: MutationRunOmission[];
  onRunChange: (runId: string) => void;
  onFiltersChange: (filters: ExplorerFilters) => void;
  onSelect: (record: MutationRecordIndexEntry) => void;
  onRetryRuns: () => void;
  onRetryRecords: () => void;
};

export function MutationExplorerView({
  runs,
  selectedRunId,
  records,
  filters,
  selectedCandidateId,
  detail,
  runsLoading,
  recordsLoading,
  detailLoading,
  runsError,
  recordsError,
  detailError,
  diagnostics = [],
  omittedRunCount,
  omittedRuns,
  onRunChange,
  onFiltersChange,
  onSelect,
  onRetryRuns,
  onRetryRecords,
}: MutationExplorerViewProps) {
  const filteredRecords = useMemo(
    () => filterRecords(records, filters),
    [records, filters],
  );
  const groups = useMemo(() => groupByFamily(filteredRecords), [filteredRecords]);
  const combinationMode = records.some(isCombinationRecord);
  return (
    <section className="mutation-explorer" aria-labelledby="mutation-explorer-title">
      <header className="explorer-header">
        <div>
          <p className="eyebrow">READ-ONLY EXPERIMENT RESULTS</p>
          {combinationMode ? (
            <>
              <h2 id="mutation-explorer-title">Combination Explorer</h2>
              <p className="muted">
                Compare combined detection and attribution outcomes with their ordered source mutations.
              </p>
            </>
          ) : (
            <>
              <h2 id="mutation-explorer-title">Deterministic IDS Rule Mutation Explorer</h2>
              <p className="muted">
                Compare detection quality and model attribution for one deterministic rule mutation at a time.
              </p>
            </>
          )}
        </div>
        <label className="run-picker">
          Experiment run
          <select
            value={selectedRunId ?? ""}
            onChange={(event) => onRunChange(event.target.value)}
            disabled={!runs.length}
          >
            {!runs.length && <option value="">No runs available</option>}
            {runs.map((run) => (
              <option key={run.run_id} value={run.run_id}>
                {run.run_id} ({run.record_count})
              </option>
            ))}
          </select>
        </label>
      </header>

      {runsError && (
        <div className="error explorer-error" role="alert">
          <span>{runsError}</span>
          <button type="button" onClick={onRetryRuns}>Retry runs</button>
        </div>
      )}
      {recordsError && (
        <div className="error explorer-error" role="alert">
          <span>{recordsError}</span>
          <button type="button" onClick={onRetryRecords}>Retry records</button>
        </div>
      )}
      {omittedRuns.length > 0 && (
        <details className="diagnostics run-omissions">
          <summary>
            {omittedRunCount} run{omittedRunCount === 1 ? "" : "s"} could not be read and {omittedRunCount === 1 ? "is" : "are"} not listed
          </summary>
          <ul className="omitted-runs">
            {omittedRuns.map((run) => (
              <li key={run.run_id}>
                <code>{run.run_id}</code>: {run.error}
              </li>
            ))}
          </ul>
        </details>
      )}
      {diagnostics.length > 0 && (
        <details className="diagnostics">
          <summary>
            {combinationMode
              ? `Combination run diagnostics (${diagnostics.length})`
              : `Skipped source lines and directories (${diagnostics.length})`}
          </summary>
          {combinationMode ? (
            <ul className="omitted-runs combination-run-diagnostics">
              {diagnostics.map((diagnostic, index) => (
                <li key={`${diagnostic.file}-${diagnostic.line}-${index}`}>
                  <code>{diagnostic.file}</code> · Line {diagnostic.line}: {diagnostic.error}
                </li>
              ))}
            </ul>
          ) : (
            <pre className="payload">{JSON.stringify(diagnostics, null, 2)}</pre>
          )}
        </details>
      )}
      {runsLoading || recordsLoading ? (
        <p className="explorer-loading" role="status">Loading mutation index…</p>
      ) : !recordsError && selectedRunId ? (
        <>
          <MutationFilterBar
            records={records}
            filters={filters}
            onChange={onFiltersChange}
          />
          <p className="result-count" aria-live="polite">
            Showing {filteredRecords.length} of {records.length} {combinationMode ? "combinations" : "mutations"}
          </p>
          <div className="explorer-layout">
            <section
              className="mutation-results"
              aria-label={combinationMode ? "Combination results" : "Mutation results"}
            >
              <MutationTable
                groups={groups}
                selectedCandidateId={selectedCandidateId}
                onSelect={onSelect}
                combinationMode={combinationMode}
              />
            </section>
            <section className="mutation-detail" aria-label="Selected mutation detail">
              {detailError && <p className="error" role="alert">{detailError}</p>}
              {detailLoading && <p className="explorer-loading" role="status">Loading mutation detail…</p>}
              {!detailLoading && detail && <MutationDetailPanel detail={detail} />}
              {!detailLoading && !detail && !detailError && (
                <p className="empty">
                  {combinationMode
                    ? "Select a combination row to load its combined outcome and source evidence."
                    : "Select a mutation row to load its full rule, PCAP, and model evidence."}
                </p>
              )}
            </section>
          </div>
        </>
      ) : !recordsError && !runsError ? (
        <p className="empty">
          Place a mutation run under runs/mutations/ or use the included example results.
        </p>
      ) : null}
    </section>
  );
}

export function MutationExplorer({ client = mutationApi }: { client?: MutationApiClient }) {
  const [loadState, setLoadState] = useState(initialExplorerLoadState);
  const [retryState, setRetryState] = useState(initialExplorerRetryState);
  const [records, setRecords] = useState<MutationRecordIndexEntry[]>([]);
  const [diagnostics, setDiagnostics] = useState<{ file: string; line: number; error: string }[]>([]);
  const [filters, setFilters] = useState(DEFAULT_EXPLORER_FILTERS);
  const [selectedCandidateId, setSelectedCandidateId] = useState<string | null>(null);
  const [detail, setDetail] = useState<MutationRecordDetail | null>(null);
  const [runsLoading, setRunsLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const { runsRetry, recordsRetry } = retryState;
  const selectedRunId = loadState.selectedRunId;
  const recordsLoading = isRecordIndexPending(loadState);
  const detailLoader = useMemo(() => createLatestDetailLoader(client, {
    onSuccess: (response) => {
      setDetail(response);
      setDetailLoading(false);
    },
    onError: (reason) => {
      setDetailError(reason instanceof Error ? reason.message : "Unable to load mutation detail.");
      setDetailLoading(false);
    },
  }), [client]);

  useEffect(() => {
    let cancelled = false;
    setRunsLoading(true);
    void client.runs().then((response) => {
      if (cancelled) return;
      setLoadState((state) => applyRunsLoaded(state, response));
      setRunsLoading(false);
    }).catch((reason: unknown) => {
      if (cancelled) return;
      setLoadState((state) => applyRunsFailed(state, reason));
      setRunsLoading(false);
    });
    return () => { cancelled = true; };
  }, [client, runsRetry]);

  useEffect(() => {
    if (!selectedRunId) return;
    let cancelled = false;
    setRecords([]);
    setDiagnostics([]);
    detailLoader.cancel();
    setSelectedCandidateId(null);
    setDetail(null);
    setDetailError(null);
    void client.records(selectedRunId).then((response) => {
      if (cancelled) return;
      setRecords(response.records);
      setDiagnostics(response.diagnostics);
      setLoadState((state) => applyRecordsLoaded(state, selectedRunId));
    }).catch((reason: unknown) => {
      if (cancelled) return;
      setLoadState((state) => applyRecordsFailed(state, reason));
    });
    return () => { cancelled = true; };
  }, [client, detailLoader, recordsRetry, selectedRunId]);

  useEffect(() => {
    if (selectedRunId) setFilters(resetRunScopedFilters);
  }, [selectedRunId]);

  useEffect(() => () => detailLoader.cancel(), [detailLoader]);

  function selectRecord(record: MutationRecordIndexEntry) {
    if (!selectedRunId) return;
    const runId = selectedRunId;
    setSelectedCandidateId(record.candidate_id);
    setDetail(null);
    setDetailError(null);
    setDetailLoading(true);
    void detailLoader.load(runId, record.candidate_id);
  }

  function changeRun(runId: string) {
    setLoadState((state) => selectExplorerRun(state, runId));
  }

  return (
    <MutationExplorerView
      runs={loadState.runs}
      selectedRunId={selectedRunId}
      records={records}
      filters={filters}
      selectedCandidateId={selectedCandidateId}
      detail={detail}
      runsLoading={runsLoading}
      recordsLoading={recordsLoading}
      detailLoading={detailLoading}
      runsError={loadState.runsError}
      recordsError={loadState.recordsError}
      detailError={detailError}
      diagnostics={diagnostics}
      omittedRunCount={loadState.omittedRunCount}
      omittedRuns={loadState.omittedRuns}
      onRunChange={changeRun}
      onFiltersChange={setFilters}
      onSelect={selectRecord}
      onRetryRuns={() => setRetryState(retryRuns)}
      onRetryRecords={() => {
        setLoadState(beginRecordsReload);
        setRetryState(retryRecords);
      }}
    />
  );
}
