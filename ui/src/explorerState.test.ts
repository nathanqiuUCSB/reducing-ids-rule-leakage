import { describe, expect, it } from "vitest";
import type { MutationRunSummary, MutationRunsResponse } from "./mutationApi";
import {
  applyRecordsFailed,
  applyRecordsLoaded,
  applyRunsFailed,
  applyRunsLoaded,
  beginRecordsReload,
  chooseDefaultMutationRun,
  initialExplorerLoadState,
  initialExplorerRetryState,
  isRecordIndexPending,
  nextSelectedRun,
  retryRecords,
  retryRuns,
  selectExplorerRun,
} from "./explorerState";

function summary(runId: string): MutationRunSummary {
  return {
    run_id: runId,
    fixture_count: 1,
    record_count: 1,
    malformed_line_count: 0,
    diagnostics: [],
  };
}

function listing(
  runs: MutationRunSummary[],
  omitted: { run_id: string; error: string }[] = [],
): MutationRunsResponse {
  return {
    runs,
    omitted_run_count: omitted.length,
    omitted_runs: omitted,
  };
}

const v1 = summary("dataset-component-mutations");
const v2 = summary("dataset-component-mutations-v2");
const smoke = summary("expansion-smoke");

describe("explorer run selection", () => {
  it("seeds the completed v2 experiment before any other run", () => {
    expect(chooseDefaultMutationRun([smoke, v1, v2])).toBe(v2.run_id);
    expect(chooseDefaultMutationRun([smoke, summary("other-v2")]))
      .toBe("other-v2");
    expect(chooseDefaultMutationRun([smoke, v1])).toBe(smoke.run_id);
    expect(chooseDefaultMutationRun([])).toBeNull();
  });

  it("keeps the current run when a refreshed listing still contains it", () => {
    expect(nextSelectedRun(smoke.run_id, [v2, smoke])).toBe(smoke.run_id);
  });

  it("seeds the default only when the selection is absent or removed", () => {
    expect(nextSelectedRun(null, [smoke, v2])).toBe(v2.run_id);
    expect(nextSelectedRun("retired-run", [smoke, v2])).toBe(v2.run_id);
    expect(nextSelectedRun("retired-run", [])).toBeNull();
  });

  it("preserves the selection across a run-list refresh", () => {
    const state = applyRunsLoaded(initialExplorerLoadState(), listing([v1, v2, smoke]));
    const chosen = selectExplorerRun(state, v1.run_id);

    expect(state.selectedRunId).toBe(v2.run_id);
    expect(applyRunsLoaded(chosen, listing([v1, v2, smoke])).selectedRunId)
      .toBe(v1.run_id);
    expect(applyRunsLoaded(chosen, listing([v2, smoke])).selectedRunId)
      .toBe(v2.run_id);
  });
});

describe("explorer error state", () => {
  it("never clears a record error when the run list succeeds", () => {
    const failed = applyRecordsFailed(
      applyRunsLoaded(initialExplorerLoadState(), listing([v2])),
      new Error("Records unavailable"),
    );

    const refreshed = applyRunsLoaded(failed, listing([v2, smoke]));

    expect(failed.recordsError).toBe("Records unavailable");
    expect(refreshed.recordsError).toBe("Records unavailable");
    expect(refreshed.runsError).toBeNull();
  });

  it("keeps run and record failures independent", () => {
    const both = applyRecordsFailed(
      applyRunsFailed(initialExplorerLoadState(), new Error("Runs unavailable")),
      new Error("Records unavailable"),
    );

    expect(both.runsError).toBe("Runs unavailable");
    expect(both.recordsError).toBe("Records unavailable");
    expect(applyRecordsLoaded(both, smoke.run_id).runsError)
      .toBe("Runs unavailable");
    expect(applyRecordsLoaded(both, smoke.run_id).recordsError).toBeNull();
    expect(selectExplorerRun(both, smoke.run_id).recordsError).toBeNull();
    expect(selectExplorerRun(both, smoke.run_id).runsError).toBe("Runs unavailable");
  });

  it("falls back to readable copy for non-Error rejections", () => {
    expect(applyRunsFailed(initialExplorerLoadState(), "boom").runsError)
      .toBe("Unable to load mutation runs.");
    expect(applyRecordsFailed(initialExplorerLoadState(), null).recordsError)
      .toBe("Unable to load mutation index.");
  });

  it("does not mutate the previous state", () => {
    const state = initialExplorerLoadState();

    applyRunsLoaded(state, listing([v2]));
    applyRecordsFailed(state, new Error("Records unavailable"));

    expect(state).toEqual(initialExplorerLoadState());
  });
});

describe("explorer omitted runs", () => {
  it("carries the server's omitted-run notice alongside the listing", () => {
    const omission = {
      run_id: "combination-hybrid-v1",
      error: "duplicate candidate ID across fixtures: et-1-content-remove",
    };

    const state = applyRunsLoaded(
      initialExplorerLoadState(),
      listing([v2], [omission]),
    );

    expect(state.omittedRunCount).toBe(1);
    expect(state.omittedRuns).toEqual([omission]);
    expect(initialExplorerLoadState().omittedRuns).toEqual([]);
    expect(applyRunsLoaded(state, listing([v2])).omittedRuns).toEqual([]);
  });

  it("tolerates a server that does not report omissions yet", () => {
    const state = applyRunsLoaded(initialExplorerLoadState(), { runs: [v2] });

    expect(state.omittedRunCount).toBe(0);
    expect(state.omittedRuns).toEqual([]);
  });
});

describe("explorer record-index pending window", () => {
  it("stays pending from run selection until that run's index resolves", () => {
    const seeded = applyRunsLoaded(initialExplorerLoadState(), listing([v2]));

    expect(isRecordIndexPending(initialExplorerLoadState())).toBe(false);
    expect(isRecordIndexPending(seeded)).toBe(true);
    expect(isRecordIndexPending(applyRecordsLoaded(seeded, v2.run_id)))
      .toBe(false);
  });

  it("re-enters the pending window when another run is selected", () => {
    const loaded = applyRecordsLoaded(
      applyRunsLoaded(initialExplorerLoadState(), listing([v2, smoke])),
      v2.run_id,
    );

    const switched = selectExplorerRun(loaded, smoke.run_id);

    expect(isRecordIndexPending(switched)).toBe(true);
    expect(isRecordIndexPending(applyRecordsLoaded(switched, smoke.run_id)))
      .toBe(false);
  });

  it("ignores an index that resolved for a run the user already left", () => {
    const switched = selectExplorerRun(
      applyRunsLoaded(initialExplorerLoadState(), listing([v2, smoke])),
      smoke.run_id,
    );

    expect(isRecordIndexPending(applyRecordsLoaded(switched, v2.run_id)))
      .toBe(true);
  });

  it("stops pending on failure and resumes it on an explicit reload", () => {
    const failed = applyRecordsFailed(
      applyRunsLoaded(initialExplorerLoadState(), listing([v2])),
      new Error("Index unavailable"),
    );

    expect(isRecordIndexPending(failed)).toBe(false);
    expect(isRecordIndexPending(beginRecordsReload(failed))).toBe(true);
    expect(beginRecordsReload(failed).recordsError).toBeNull();
    expect(
      isRecordIndexPending(
        beginRecordsReload(applyRecordsLoaded(failed, v2.run_id)),
      ),
    ).toBe(true);
  });
});

describe("explorer retry keys", () => {
  it("retries records without changing the run-list request key", () => {
    const retried = retryRecords(initialExplorerRetryState());

    expect(retried.recordsRetry).toBe(1);
    expect(retried.runsRetry).toBe(initialExplorerRetryState().runsRetry);
  });

  it("retries the run list without changing the records request key", () => {
    const retried = retryRuns(initialExplorerRetryState());

    expect(retried.runsRetry).toBe(1);
    expect(retried.recordsRetry).toBe(initialExplorerRetryState().recordsRetry);
  });
});
