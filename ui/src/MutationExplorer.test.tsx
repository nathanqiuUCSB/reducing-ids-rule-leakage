import { isValidElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type {
  MutationRecordDetail,
  MutationRecordIndexEntry,
  MutationRunSummary,
} from "./mutationApi";
import { chooseDefaultMutationRun } from "./explorerState";
import type { MutationRecordStatus } from "./mutationApi";
import {
  createLatestDetailLoader,
  DEFAULT_EXPLORER_FILTERS,
  loadMutationDetail,
  MutationExplorerView,
  resetRunScopedFilters,
  type MutationExplorerViewProps,
} from "./MutationExplorer";
import { MutationDetailPanel } from "./MutationDetailPanel";
import { MutationFilterBar } from "./MutationFilterBar";
import { MutationTable } from "./MutationTable";
import { RuleDiff } from "./RuleDiff";
import { filterRecords } from "./mutationExplorer";

function findElements(
  node: ReactNode,
  predicate: (element: React.ReactElement<Record<string, unknown>>) => boolean,
): React.ReactElement<Record<string, unknown>>[] {
  const matches: React.ReactElement<Record<string, unknown>>[] = [];
  function visit(value: ReactNode) {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (!isValidElement<Record<string, unknown>>(value)) return;
    if (predicate(value)) matches.push(value);
    visit(value.props.children as ReactNode);
  }
  visit(node);
  return matches;
}

const baseRecord: MutationRecordIndexEntry = {
  candidate_id: "et-example-content-remove",
  component: "content",
  operator: "remove",
  params: { index: 0 },
  description: "remove the first content match",
  revision: 1,
  fingerprint: "abc",
  buffer: "http.uri",
  option_index: 0,
  status: "evaluated",
  syntax_valid: true,
  syntax_error: null,
  positive_recall: 1,
  negative_false_positive_rate: 0,
  benign_corpus_available: true,
  benign_false_positive_rate: 0,
  benign_aggregate: null,
  benign_cache_errors: [],
  attacker_prediction: "CVE-2025-9999",
  attacker_correct: false,
  attacker_error: null,
  target_cve: "CVE-2025-0108",
  relationship_tier: "closely_related",
  meaningful_obscurity: false,
  mutation_category: "semantic",
  evaluated_at: "2026-08-03T00:00:00Z",
  experiment_manifest_hash: null,
  source_candidate_ids: null,
  block_count: null,
  fixture: "et-example",
  baseline_exact: true,
  is_emergent_miss: true,
  is_balanced_emergent_miss: true,
  is_unbalanced_emergent_miss: false,
  is_closely_related_guess: true,
};

const unbalancedRecord: MutationRecordIndexEntry = {
  ...baseRecord,
  candidate_id: "et-example-flow-remove",
  component: "flow",
  operator: "drop",
  description: "remove established flow requirement",
  buffer: null,
  negative_false_positive_rate: 0.25,
  benign_false_positive_rate: 0.1,
  relationship_tier: "same_ecosystem",
  is_balanced_emergent_miss: false,
  is_unbalanced_emergent_miss: true,
  is_closely_related_guess: false,
};

const providerFailure: MutationRecordIndexEntry = {
  ...baseRecord,
  candidate_id: "et-example-pcre-provider",
  component: "pcre",
  operator: "simplify",
  description: "simplify the regular expression",
  status: "attacker_provider_failed",
  attacker_prediction: null,
  attacker_error: "provider unavailable",
  relationship_tier: null,
  meaningful_obscurity: null,
  is_emergent_miss: false,
  is_balanced_emergent_miss: false,
  is_unbalanced_emergent_miss: false,
  is_closely_related_guess: false,
};

const detail: MutationRecordDetail = {
  ...baseRecord,
  rule: 'alert http any any -> any any (content:"mutated"; sid:1;)',
  baseline_rule: 'alert http any any -> any any (content:"baseline"; sid:1;)',
  mutated_rule: 'alert http any any -> any any (content:"mutated"; sid:1;)',
  case_results: {},
  benign_capture_results: {},
  attacker_exchange: null,
  case_groups: {
    positive: [{
      name: "P0",
      pcap_name: "P0-canonical.pcap",
      fired: true,
      passed: true,
      reason: "canonical exploit",
    }],
    negative: [{
      name: "N0",
      pcap_name: "N0-wrong-content.pcap",
      fired: false,
      passed: true,
      reason: "wrong content",
      predicate_id: "content-0",
    }],
    benign: [{
      source_id: "HTTP",
      fired: false,
      reason: "benign web traffic",
    }, {
      source_id: "DNS",
      reason: "capture result unavailable",
    }],
  },
  suite_reason: "complete behavior suite",
  attacker: {
    status: "success",
    predicted_cve: "CVE-2025-9999",
    reasoning: "Same product and nearby vulnerable parser.",
    clues: ["HTTP path", "parser token"],
    prompt: "Identify the CVE.",
    raw_response: '{"predicted_cve":"CVE-2025-9999"}',
    error: null,
  },
  diagnostics: [],
};

const combinationRecord: MutationRecordIndexEntry = {
  ...baseRecord,
  candidate_id: "et-example-combination-2",
  component: "combination",
  operator: "blocks_2",
  description: "Combine 2 baseline-relative mutations",
  buffer: null,
  option_index: null,
  experiment_manifest_hash: "manifest-hash",
  source_candidate_ids: ["et-example-flow-remove", "et-example-content-shorten"],
  block_count: 2,
  experiment_role: "primary",
  included_components: ["flow", "content"],
  included_operators: ["remove", "shorten_suffix"],
  included_families: ["flow", "content"],
  included_block_labels: ["flow/remove", "content/shorten_suffix"],
  exact_obscurity_comparison: "improved_obscurity",
  effective_obscurity_comparison: "reinforced_obscurity",
  source_join_status: "complete",
  source_join_diagnostic_count: 0,
  precision_change: "precision_only_cost",
};

const malformedCombinationRecord: MutationRecordIndexEntry = {
  ...combinationRecord,
  candidate_id: "et-example-combination-malformed",
  source_join_status: "unavailable",
  source_join_diagnostic_count: 2,
  exact_obscurity_comparison: "unmeasured",
  effective_obscurity_comparison: "unmeasured",
  precision_change: "unmeasured",
};

const combinationDetail: MutationRecordDetail = {
  ...detail,
  ...combinationRecord,
  building_blocks: [
    {
      candidate_id: "et-example-flow-remove",
      join_status: "available",
      component: "flow",
      operator: "remove",
      description: "Remove established flow requirement",
      buffer: null,
      params: {},
      mutation_category: "semantic",
      positive_recall: 1,
      negative_false_positive_rate: 0,
      benign_false_positive_rate: 0,
      attacker: {
        status: "provider",
        predicted_cve: null,
        reasoning: null,
        clues: [],
        error: "provider unavailable",
      },
      attacker_prediction: null,
      attacker_correct: null,
      relationship_tier: null,
      meaningful_obscurity: null,
      baseline_rule: 'alert http any any -> any any (flow:established; sid:1;)',
      mutated_rule: "alert http any any -> any any (sid:1;)",
      exact_attribution: "unmeasured",
      effective_attribution: "unmeasured",
    },
    {
      candidate_id: "et-example-content-shorten",
      join_status: "available",
      component: "content",
      operator: "shorten_suffix",
      description: "Shorten the content suffix",
      buffer: "http.uri",
      params: { length: 3 },
      mutation_category: "semantic",
      positive_recall: 1,
      negative_false_positive_rate: 0,
      benign_false_positive_rate: 0,
      attacker: {
        status: "success",
        predicted_cve: "CVE-2025-9999",
        reasoning: "Nearby parser behavior.",
        clues: ["URI suffix"],
        error: null,
      },
      attacker_prediction: "CVE-2025-9999",
      attacker_correct: false,
      relationship_tier: "closely_related",
      meaningful_obscurity: false,
      baseline_rule: 'alert http any any -> any any (content:"baseline"; sid:1;)',
      mutated_rule: 'alert http any any -> any any (content:"base"; sid:1;)',
      exact_attribution: "miss",
      effective_attribution: "hit",
    },
    {
      candidate_id: "et-example-missing",
      join_status: "unavailable",
      component: null,
      operator: null,
      description: null,
      buffer: null,
      params: null,
      mutation_category: null,
      positive_recall: null,
      negative_false_positive_rate: null,
      benign_false_positive_rate: null,
      attacker: {
        status: "unavailable",
        predicted_cve: null,
        reasoning: null,
        clues: [],
        error: null,
      },
      attacker_prediction: null,
      attacker_correct: null,
      relationship_tier: null,
      meaningful_obscurity: null,
      baseline_rule: null,
      mutated_rule: null,
      exact_attribution: "unmeasured",
      effective_attribution: "unmeasured",
    },
  ],
  join_diagnostics: [{
    source_candidate_id: "et-example-missing",
    error: "missing source ID",
  }],
};

const runs: MutationRunSummary[] = [
  {
    run_id: "dataset-component-mutations-v1",
    fixture_count: 1,
    record_count: 2,
    malformed_line_count: 0,
    diagnostics: [],
  },
  {
    run_id: "dataset-component-mutations-v2",
    fixture_count: 2,
    record_count: 3,
    malformed_line_count: 0,
    diagnostics: [],
  },
];

function viewProps(
  overrides: Partial<MutationExplorerViewProps> = {},
): MutationExplorerViewProps {
  return {
    runs,
    selectedRunId: runs[1].run_id,
    records: [],
    filters: DEFAULT_EXPLORER_FILTERS,
    selectedCandidateId: null,
    detail: null,
    runsLoading: false,
    recordsLoading: false,
    detailLoading: false,
    runsError: null,
    recordsError: null,
    detailError: null,
    omittedRunCount: 0,
    omittedRuns: [],
    onRunChange: () => undefined,
    onFiltersChange: () => undefined,
    onSelect: () => undefined,
    onRetryRuns: () => undefined,
    onRetryRecords: () => undefined,
    ...overrides,
  };
}

describe("Mutation Explorer components", () => {
  it("chooses v2 by default and lazy-loads only the selected detail", async () => {
    expect(chooseDefaultMutationRun(runs)).toBe("dataset-component-mutations-v2");
    const record = vi.fn().mockResolvedValue(detail);

    await expect(loadMutationDetail({ record }, "run-v2", baseRecord.candidate_id))
      .resolves.toEqual(detail);
    expect(record).toHaveBeenCalledWith("run-v2", baseRecord.candidate_id);
  });

  it("renders every quick filter with its count and semantic controls", () => {
    const html = renderToStaticMarkup(
      <MutationFilterBar
        records={[baseRecord, unbalancedRecord, providerFailure]}
        filters={{
          ...DEFAULT_EXPLORER_FILTERS,
          searchText: "content",
        }}
        onChange={() => undefined}
      />,
    );

    expect(html).toContain('aria-label="All: 1 record"');
    expect(html).toContain('aria-label="Emergent: 1 record"');
    expect(html).toContain('aria-label="Balanced: 1 record"');
    expect(html).toContain('aria-label="Unbalanced: 0 records"');
    expect(html).toContain('aria-label="Close CVE: 1 record"');
    expect(html).toContain("<label>Search mutations");
    expect(html.match(/<select/g)).toHaveLength(5);
  });

  it("shows combination-only block, included-family, and role controls", () => {
    const html = renderToStaticMarkup(
      <MutationFilterBar
        records={[combinationRecord]}
        filters={DEFAULT_EXPLORER_FILTERS}
        onChange={() => undefined}
      />,
    );

    expect(html).toContain("Block count");
    expect(html).toContain("Included family");
    expect(html).toContain("Experiment role");
    expect(html).toContain("2 blocks");
    expect(html).toContain("Primary experiment");
    expect(html.match(/<select/g)).toHaveLength(8);
  });

  it("updates the block-count filter through the rendered control", () => {
    const changed = vi.fn();
    const tree = MutationFilterBar({
      records: [combinationRecord],
      filters: DEFAULT_EXPLORER_FILTERS,
      onChange: changed,
    });
    const [select] = findElements(
      tree,
      (element) => element.type === "select" && element.props["aria-label"] === "Block count",
    );

    expect(select).toBeDefined();
    (select.props.onChange as (event: { target: { value: string } }) => void)({
      target: { value: "2" },
    });
    expect(changed).toHaveBeenCalledWith({
      ...DEFAULT_EXPLORER_FILTERS,
      blockCount: 2,
    });
  });

  it.each([
    ["Included family", "includedFamily", "content"],
    ["Experiment role", "experimentRole", "primary"],
  ] as const)("updates the %s filter through the rendered control", (label, key, value) => {
    const changed = vi.fn();
    const tree = MutationFilterBar({
      records: [combinationRecord],
      filters: DEFAULT_EXPLORER_FILTERS,
      onChange: changed,
    });
    const [select] = findElements(
      tree,
      (element) => element.type === "select" && element.props["aria-label"] === label,
    );

    expect(select).toBeDefined();
    (select.props.onChange as (event: { target: { value: string } }) => void)({
      target: { value },
    });
    expect(changed).toHaveBeenCalledWith({
      ...DEFAULT_EXPLORER_FILTERS,
      [key]: value,
    });
  });

  it("keeps combination controls absent for v2 single records", () => {
    const html = renderToStaticMarkup(
      <MutationFilterBar
        records={[baseRecord]}
        filters={DEFAULT_EXPLORER_FILTERS}
        onChange={() => undefined}
      />,
    );

    expect(html).not.toContain("Block count");
    expect(html).not.toContain("Included family");
    expect(html).not.toContain("Experiment role");
    expect(html.match(/<select/g)).toHaveLength(5);
  });

  it("resets run-scoped filters when switching combination to single", () => {
    const reset = resetRunScopedFilters({
      ...DEFAULT_EXPLORER_FILTERS,
      quickFilter: "balanced_emergent_miss",
      fixture: "old-fixture",
      component: "combination",
      operator: "blocks_7",
      status: "syntax_invalid",
      category: "performance",
      blockCount: 7,
      includedFamily: "pcre",
      experimentRole: "near_cve_confusion_control",
      searchText: "et-example",
    });

    expect(reset.searchText).toBe("et-example");
    expect(filterRecords([baseRecord], reset)).toEqual([baseRecord]);
    expect(reset).toEqual({
      ...DEFAULT_EXPLORER_FILTERS,
      searchText: "et-example",
    });
  });

  it("resets stale provenance filters between combination runs", () => {
    const nextRunRecord = {
      ...combinationRecord,
      candidate_id: "next-combination",
      block_count: 3,
      included_families: ["pcre"],
      experiment_role: "near_cve_confusion_control",
    };
    const reset = resetRunScopedFilters({
      ...DEFAULT_EXPLORER_FILTERS,
      blockCount: 2,
      includedFamily: "content",
      experimentRole: "primary",
    });

    expect(filterRecords([nextRunRecord], reset)).toEqual([nextRunRecord]);
    expect(reset.blockCount).toBe("all");
    expect(reset.includedFamily).toBe("all");
    expect(reset.experimentRole).toBe("all");
  });

  it("uses one valid rowgroup and accessible selected control per family", () => {
    const html = renderToStaticMarkup(
      <MutationTable
        groups={[
          { family: "flow", label: "Flow", records: [unbalancedRecord] },
          { family: "content", label: "Content", records: [baseRecord] },
        ]}
        selectedCandidateId={baseRecord.candidate_id}
        onSelect={() => undefined}
      />,
    );

    expect(html.match(/<tbody>/g)).toHaveLength(2);
    expect(html.match(/scope="rowgroup"/g)).toHaveLength(2);
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain("Remove established flow requirement");
    expect(html).toContain("Remove");
  });

  it("gives every family count a readable unit and family", () => {
    const html = renderToStaticMarkup(
      <MutationTable
        groups={[
          { family: "flow", label: "Flow", records: [unbalancedRecord] },
          { family: "content", label: "Content", records: [baseRecord, providerFailure] },
        ]}
        selectedCandidateId={null}
        onSelect={() => undefined}
      />,
    );

    expect(html).toContain("mutation in Flow");
    expect(html).toContain("mutations in Content");
    expect(html.match(/visually-hidden/g)).toHaveLength(2);
  });

  it("renders understandable combination blocks and separate comparisons", () => {
    const html = renderToStaticMarkup(
      <MutationTable
        groups={[{ family: "combination", label: "Combination", records: [combinationRecord] }]}
        selectedCandidateId={null}
        onSelect={() => undefined}
      />,
    );

    expect(html).toContain("2 building blocks");
    expect(html).toContain("combination-table-wrap");
    expect(html).toContain('role="list" aria-label="Included building blocks"');
    expect(html.match(/role="listitem"/g)).toHaveLength(2);
    expect(html).toContain("Flow / Remove");
    expect(html).toContain("Content / Shorten suffix");
    expect(html).toContain("Exact comparison: improved obscurity");
    expect(html).toContain("Effective comparison: reinforced obscurity");
    expect(html).toContain("Precision-only cost");
    expect(html).toContain("Positive recall");
    expect(html).toContain("Synthetic false-positive rate");
    expect(html).toContain("Benign false-positive rate");
    expect(html).toContain("Combination outcome");
    expect(html).toContain("Experiment role");
    expect(html).toContain("combination in Combination");
    expect(html).toContain("Combination analysis results");
    expect(html).not.toContain("Buffer / component");
    expect(renderToStaticMarkup(
      <MutationTable
        groups={[{ family: "content", label: "Content", records: [baseRecord] }]}
        selectedCandidateId={null}
        onSelect={() => undefined}
      />,
    )).not.toContain("combination-table-wrap");
  });

  it("shows unavailable source joins and diagnostics before detail loads", () => {
    const html = renderToStaticMarkup(
      <MutationTable
        groups={[{
          family: "combination",
          label: "Combination",
          records: [malformedCombinationRecord],
        }]}
        selectedCandidateId={null}
        onSelect={() => undefined}
        combinationMode
      />,
    );

    expect(html).toContain("Source evidence unavailable");
    expect(html).toContain("2 join diagnostics");
    expect(html).toContain("Exact comparison: unmeasured");
    expect(html).toContain("Effective comparison: unmeasured");
  });

  it("uses combination-specific empty-state and screen-reader wording", () => {
    const html = renderToStaticMarkup(
      <MutationTable
        groups={[]}
        selectedCandidateId={null}
        onSelect={() => undefined}
        combinationMode
      />,
    );

    expect(html).toContain("No combinations match these filters.");
    expect(html).not.toContain("No mutations match these filters.");
  });

  it("keeps single table semantics except explicit rate terminology", () => {
    const html = renderToStaticMarkup(
      <MutationTable
        groups={[{ family: "content", label: "Content", records: [baseRecord] }]}
        selectedCandidateId={null}
        onSelect={() => undefined}
      />,
    );

    expect(html).toContain(">Mutation<");
    expect(html).toContain("Buffer / component");
    expect(html).toContain("mutation in Content");
    expect(html).not.toContain("Combination analysis results");
    expect(html).toContain("Synthetic false-positive rate");
    expect(html).toContain("Benign false-positive rate");
  });

  it("selects a combination through its accessible row button", () => {
    const selected = vi.fn();
    const tree = MutationTable({
      groups: [{ family: "combination", label: "Combination", records: [combinationRecord] }],
      selectedCandidateId: null,
      onSelect: selected,
    });
    const [button] = findElements(
      tree,
      (element) => element.type === "button" && element.props["aria-pressed"] === false,
    );

    expect(button).toBeDefined();
    (button.props.onClick as () => void)();
    expect(selected).toHaveBeenCalledWith(combinationRecord);
  });

  it("labels unknown future record statuses instead of rendering nothing", () => {
    const future = "attacker_rate_limited" as MutationRecordStatus;
    const table = renderToStaticMarkup(
      <MutationTable
        groups={[{
          family: "content",
          label: "Content",
          records: [{ ...baseRecord, status: future, is_emergent_miss: false }],
        }]}
        selectedCandidateId={null}
        onSelect={() => undefined}
      />,
    );
    const panel = renderToStaticMarkup(
      <MutationDetailPanel detail={{
        ...detail,
        status: future,
        attacker: {
          ...detail.attacker,
          status: "throttled" as MutationRecordDetail["attacker"]["status"],
        },
      }} />,
    );

    expect(table).toContain("Attacker rate limited");
    expect(table).not.toContain("undefined");
    expect(panel).toContain("Throttled");
    expect(panel).not.toContain("undefined");
  });

  it("renders real provider status without emergent labels or redundant wording", () => {
    const html = renderToStaticMarkup(
      <MutationTable
        groups={[{ family: "pcre", label: "PCRE", records: [providerFailure] }]}
        selectedCandidateId={null}
        onSelect={() => undefined}
      />,
    );

    expect(html).toContain("Attacker provider failure");
    expect(html).toContain("Not emergent");
    expect(html).not.toContain("failed failure");
    expect(html).not.toContain("Balanced emergent");
    expect(html).not.toContain("Unbalanced emergent");
    expect(html).not.toContain(">Emergent<");
  });

  it("renders full rule, PCAP, attribution, and close-CVE evidence", () => {
    const html = renderToStaticMarkup(<MutationDetailPanel detail={detail} />);

    expect(html).toContain("Baseline rule");
    expect(html).toContain("Mutated rule");
    expect(html).toContain("canonical exploit");
    expect(html).toContain("P0-canonical.pcap");
    expect(html).toContain("N0-wrong-content.pcap");
    expect(html).toContain("content-0");
    expect(html).toContain("HTTP");
    expect(html).toContain("Passed");
    expect(html).toContain("Fired");
    expect(html).toContain("Silent");
    expect(html).toContain("Not measured");
    expect(html).toContain("CVE-2025-0108");
    expect(html).toContain("CVE-2025-9999");
    expect(html).toContain("Same product and nearby vulnerable parser.");
    expect(html).toContain("HTTP path");
    expect(html).toContain("Identify the CVE.");
    expect(html).toContain("predicted_cve");
    expect(html).toContain(
      "Closely related CVE guess — not counted as meaningful obscurity.",
    );
  });

  it("renders a compact combined outcome and ordered building-block evidence", () => {
    const html = renderToStaticMarkup(
      <MutationDetailPanel detail={combinationDetail} />,
    );

    expect(html).toContain("Combined outcome");
    expect(html).toContain("Exact comparison: improved obscurity");
    expect(html).toContain("Effective comparison: reinforced obscurity");
    expect(html).toContain("Precision-only cost");
    expect(html).toContain("Source building blocks");
    expect(html.indexOf("Flow / Remove")).toBeLessThan(
      html.indexOf("Content / Shorten suffix"),
    );
    expect(html).toContain("Rule diff: baseline → single mutation");
    expect(html).toContain("Removed");
    expect(html).toContain("Inserted");
    expect(html).toContain("Synthetic false-positive rate");
    expect(html).toContain("Benign false-positive rate");
    expect(html).not.toContain(">Synthetic precision<");
    expect(html).not.toContain(">Benign precision<");
  });

  it("presents failed and missing source evidence as unavailable, never a miss", () => {
    const html = renderToStaticMarkup(
      <MutationDetailPanel detail={combinationDetail} />,
    );
    const providerBlock = html.slice(
      html.indexOf("Flow / Remove"),
      html.indexOf("Content / Shorten suffix"),
    );

    expect(providerBlock).toContain("Provider failure");
    expect(providerBlock).toContain("Attribution unavailable");
    expect(providerBlock).not.toContain(">Miss<");
    expect(html).toContain("Unavailable source block (et-example-missing)");
    expect(html).toContain("Source evidence unavailable");
    expect(html).toContain("missing source ID");
    expect(html).not.toContain('class="payload"');
  });

  it("keeps building-block evidence absent from single detail", () => {
    const html = renderToStaticMarkup(<MutationDetailPanel detail={detail} />);

    expect(html).not.toContain("Combined outcome");
    expect(html).not.toContain("Source building blocks");
  });

  it("announces the close-CVE note politely rather than interrupting", () => {
    const html = renderToStaticMarkup(<MutationDetailPanel detail={detail} />);

    expect(html).toContain(
      '<p class="close-cve-warning" role="status">Closely related CVE guess',
    );
    expect(html).not.toContain('role="alert"');
  });

  it("reports benign captures as fired or silent without a pass verdict", () => {
    const html = renderToStaticMarkup(<MutationDetailPanel detail={{
      ...detail,
      case_groups: {
        ...detail.case_groups,
        benign: [
          { source_id: "HTTP", fired: false, reason: "benign web traffic" },
          { source_id: "DNS", error: "capture replay failed" },
        ],
      },
    }} />);
    const benign = html.slice(html.indexOf("Benign captures"));

    expect(benign).toContain("Silent");
    expect(benign).toContain("Not measured");
    expect(benign).toContain("capture replay failed");
    expect(benign).not.toContain("Passed");
    expect(benign).not.toContain("Unknown");
  });

  it("shows attacker failures as failures and never as misses", () => {
    const failedDetail: MutationRecordDetail = {
      ...detail,
      ...providerFailure,
      attacker: {
        status: "provider",
        predicted_cve: null,
        reasoning: null,
        clues: [],
        prompt: "Identify the CVE.",
        raw_response: null,
        error: "provider unavailable",
      },
    };
    const html = renderToStaticMarkup(
      <MutationDetailPanel detail={failedDetail} />,
    );

    expect(html).toContain("Provider failure");
    expect(html).toContain("Attacker provider failure");
    expect(html).toContain(
      "The attacker ran, but the model provider failed. "
      + "Reported error: provider unavailable. "
      + "This record is not classified as an emergent outcome.",
    );
    expect(html).not.toContain("failed failure");
    expect(html).not.toContain("attacker miss");
  });

  it("keeps an already punctuated attacker error to one sentence break", () => {
    const html = renderToStaticMarkup(
      <MutationDetailPanel detail={{
        ...detail,
        ...providerFailure,
        attacker: {
          status: "provider",
          predicted_cve: null,
          reasoning: null,
          clues: [],
          prompt: null,
          raw_response: null,
          error: "Upstream returned 503.",
        },
      }} />,
    );

    expect(html).toContain("Reported error: Upstream returned 503. This record");
    expect(html).not.toContain("503.. ");
  });

  it("distinguishes validation gates where the attacker did not run", () => {
    for (const [status, sentence] of [
      ["syntax_invalid", "The mutated rule failed syntax validation, so the attacker did not run."],
      ["positive_recall_failed", "The mutated rule failed the positive-recall gate, so the attacker did not run."],
    ] as const) {
      const html = renderToStaticMarkup(
        <MutationDetailPanel detail={{
          ...detail,
          status,
          meaningful_obscurity: null,
          relationship_tier: null,
          attacker_correct: null,
          attacker: {
            status: "validation",
            predicted_cve: null,
            reasoning: null,
            clues: [],
            prompt: null,
            raw_response: null,
            error: null,
          },
        }} />,
      );
      expect(html).toContain(sentence);
      expect(html).not.toContain("attacker failure");
    }
  });

  it("requires successful non-meaningful close outcome for close warning", () => {
    const meaningful = renderToStaticMarkup(
      <MutationDetailPanel detail={{ ...detail, meaningful_obscurity: true }} />,
    );
    const recallGated = renderToStaticMarkup(
      <MutationDetailPanel detail={{ ...detail, positive_recall: 0.5 }} />,
    );
    const failed = renderToStaticMarkup(
      <MutationDetailPanel detail={{
        ...detail,
        status: "attacker_parse_failed",
        attacker: { ...detail.attacker, status: "parse" },
      }} />,
    );

    expect(meaningful).not.toContain("Closely related CVE guess");
    expect(recallGated).not.toContain("Closely related CVE guess");
    expect(failed).not.toContain("Closely related CVE guess");
  });

  it("renders reachable loading and record error retry states", () => {
    expect(renderToStaticMarkup(
      <MutationExplorerView {...viewProps({ runsLoading: true })} />,
    )).toContain("Loading mutation index");

    const recordsErrorHtml = renderToStaticMarkup(
      <MutationExplorerView {...viewProps({ recordsError: "Index unavailable" })} />,
    );
    expect(recordsErrorHtml).toContain("Index unavailable");
    expect(recordsErrorHtml).toContain(">Retry records<");
    expect(recordsErrorHtml).not.toContain(">Retry runs<");
    expect(recordsErrorHtml).not.toContain("Detail unavailable");
  });

  it("retries the run list separately from the record index", () => {
    const html = renderToStaticMarkup(
      <MutationExplorerView {...viewProps({
        runsError: "Runs unavailable",
        recordsError: "Index unavailable",
        records: [baseRecord],
      })} />,
    );

    expect(html).toContain("Runs unavailable");
    expect(html).toContain(">Retry runs<");
    expect(html).toContain("Index unavailable");
    expect(html).toContain(">Retry records<");
  });

  it("shows loading instead of an empty table while the index resolves", () => {
    const html = renderToStaticMarkup(
      <MutationExplorerView {...viewProps({
        runsLoading: false,
        recordsLoading: true,
        records: [],
      })} />,
    );

    expect(html).toContain("Loading mutation index");
    expect(html).not.toContain("No mutations match these filters");
    expect(html).not.toContain("Showing 0 of 0 mutations");
    expect(html).not.toContain("Place a mutation run under runs/mutations/ or use the included example results.");
  });

  it("does not claim there are no runs while the run list is failing", () => {
    const html = renderToStaticMarkup(
      <MutationExplorerView {...viewProps({
        runs: [],
        selectedRunId: null,
        runsError: "Runs unavailable",
      })} />,
    );

    expect(html).toContain("Runs unavailable");
    expect(html).toContain(">Retry runs<");
    expect(html).not.toContain("Place a mutation run under runs/mutations/ or use the included example results.");
  });

  it("reports runs the server could not read as a data-quality notice", () => {
    const html = renderToStaticMarkup(
      <MutationExplorerView {...viewProps({
        records: [baseRecord],
        omittedRunCount: 1,
        omittedRuns: [{
          run_id: "combination-hybrid-v1",
          error: "duplicate candidate ID across fixtures: et-1-content-remove",
        }],
      })} />,
    );

    expect(html).toContain("1 run could not be read");
    expect(html).toContain("combination-hybrid-v1");
    expect(html).toContain("duplicate candidate ID across fixtures");
    expect(renderToStaticMarkup(
      <MutationExplorerView {...viewProps({ records: [baseRecord] })} />,
    )).not.toContain("could not be read");
  });

  it("uses honest combination wording for run diagnostics", () => {
    const diagnostic = {
      file: "results.jsonl",
      line: 4,
      error: "source join row malformed",
    };
    const combinationHtml = renderToStaticMarkup(
      <MutationExplorerView {...viewProps({
        records: [malformedCombinationRecord],
        diagnostics: [diagnostic],
      })} />,
    );
    const singleHtml = renderToStaticMarkup(
      <MutationExplorerView {...viewProps({
        records: [baseRecord],
        diagnostics: [diagnostic],
      })} />,
    );

    expect(combinationHtml).toContain("Combination run diagnostics (1)");
    expect(combinationHtml).not.toContain("Skipped source lines and directories");
    expect(combinationHtml).toContain('aria-label="Combination results"');
    expect(combinationHtml).toContain("results.jsonl");
    expect(combinationHtml).toContain("Line 4");
    expect(combinationHtml).not.toContain('class="payload"');
    expect(singleHtml).toContain("Skipped source lines and directories (1)");
    expect(singleHtml).toContain('aria-label="Mutation results"');
    expect(singleHtml).toContain('class="payload"');
  });

  it("keeps showing the loaded index when only the run list failed", () => {
    const html = renderToStaticMarkup(
      <MutationExplorerView {...viewProps({
        runsError: "Runs unavailable",
        records: [baseRecord],
      })} />,
    );

    expect(html).toContain("Runs unavailable");
    expect(html).toContain(">Retry runs<");
    expect(html).toContain("Remove the first content match");
    expect(html).not.toContain(">Retry records<");
  });

  it("renders a reachable detail error with the loaded index", () => {
    const html = renderToStaticMarkup(
      <MutationExplorerView {...viewProps({
        records: [baseRecord],
        selectedCandidateId: baseRecord.candidate_id,
        detailError: "Detail unavailable",
      })} />,
    );
    expect(html).toContain("Detail unavailable");
    expect(html).toContain("Remove the first content match");
  });

  it("ignores stale detail responses after a newer selection", async () => {
    let resolveFirst!: (value: MutationRecordDetail) => void;
    let resolveSecond!: (value: MutationRecordDetail) => void;
    const record = vi.fn()
      .mockReturnValueOnce(new Promise<MutationRecordDetail>((resolve) => { resolveFirst = resolve; }))
      .mockReturnValueOnce(new Promise<MutationRecordDetail>((resolve) => { resolveSecond = resolve; }));
    const committed: string[] = [];
    const loader = createLatestDetailLoader({ record }, {
      onSuccess: (value) => committed.push(value.candidate_id),
      onError: () => undefined,
    });

    const first = loader.load("run-v2", baseRecord.candidate_id);
    const second = loader.load("run-v2", unbalancedRecord.candidate_id);
    resolveSecond({ ...detail, candidate_id: unbalancedRecord.candidate_id });
    await second;
    resolveFirst(detail);
    await first;

    expect(committed).toEqual([unbalancedRecord.candidate_id]);
  });

  it("preserves the existing option-level rule diff presentation", () => {
    const html = renderToStaticMarkup(
      <RuleDiff
        before={'alert http any any -> any any (content:"old"; sid:1;)'}
        after={'alert http any any -> any any (content:"new"; sid:1;)'}
        label="Baseline to mutation"
      />,
    );

    expect(html).toContain("Removed");
    expect(html).toContain("Inserted");
    expect(html).toContain('content:&quot;old&quot;;');
    expect(html).toContain('content:&quot;new&quot;;');
  });
});
