import { describe, expect, it } from "vitest";
import {
  filterRecords,
  groupByFamily,
  isCombinationRecord,
  SEARCHABLE_INDEX_FIELDS,
  sortRecords,
  type ExplorerFilters,
} from "./mutationExplorer";
import type {
  CombinationBuildingBlock,
  MutationRecordDetail,
  MutationRecordIndexEntry,
} from "./mutationApi";
import {
  formatComparisonLabel,
  formatExperimentRole,
  formatFamilyLabel,
  formatFpLabel,
  formatPrecisionChange,
  formatSourceBlockLabel,
  syntheticFpStatus,
  benignFpStatus,
} from "./mutationLabels";

const TARGET = "CVE-2025-0108";

function indexRecord(
  overrides: Partial<MutationRecordIndexEntry> = {},
): MutationRecordIndexEntry {
  return {
    candidate_id: "et-example-content-remove",
    component: "content",
    operator: "remove",
    params: { index: 0 },
    description: "Remove this content dependency group.",
    revision: 1,
    fingerprint: "example-fingerprint",
    buffer: null,
    option_index: null,
    status: "evaluated",
    syntax_valid: true,
    syntax_error: null,
    positive_recall: 1.0,
    negative_false_positive_rate: 0.0,
    benign_corpus_available: true,
    benign_false_positive_rate: 0.0,
    benign_aggregate: { captures_evaluated: 5 },
    benign_cache_errors: [],
    attacker_prediction: "CVE-2024-0012",
    attacker_correct: false,
    attacker_error: null,
    target_cve: TARGET,
    relationship_tier: "closely_related",
    meaningful_obscurity: false,
    mutation_category: "semantic",
    evaluated_at: "2026-08-02T11:38:15.981026+00:00",
    experiment_manifest_hash: null,
    source_candidate_ids: null,
    block_count: null,
    fixture: "et-example",
    baseline_exact: true,
    is_emergent_miss: true,
    is_balanced_emergent_miss: true,
    is_unbalanced_emergent_miss: false,
    is_closely_related_guess: true,
    ...overrides,
  };
}

function searchOverride(
  field: (typeof SEARCHABLE_INDEX_FIELDS)[number],
  token: string,
): Partial<MutationRecordIndexEntry> {
  switch (field) {
    case "candidate_id":
      return { candidate_id: token };
    case "description":
      return { description: token };
    case "fixture":
      return { fixture: token };
    case "component":
      return { component: token };
    case "operator":
      return { operator: token };
    case "attacker_prediction":
      return { attacker_prediction: token };
    case "target_cve":
      return { target_cve: token };
  }
}

const exactHit = indexRecord({
  candidate_id: "et-example-exact",
  is_emergent_miss: false,
  is_balanced_emergent_miss: false,
  is_unbalanced_emergent_miss: false,
  is_closely_related_guess: false,
  attacker_prediction: TARGET,
  relationship_tier: "exact_match",
});

const emergent = indexRecord({
  candidate_id: "et-example-emergent",
  is_balanced_emergent_miss: false,
  is_unbalanced_emergent_miss: true,
  is_closely_related_guess: false,
  relationship_tier: "unclassified",
});

const balanced = indexRecord({
  candidate_id: "et-example-balanced",
  is_balanced_emergent_miss: true,
  is_unbalanced_emergent_miss: false,
  is_closely_related_guess: true,
});

const unbalanced = indexRecord({
  candidate_id: "et-example-unbalanced",
  negative_false_positive_rate: 0.25,
  is_balanced_emergent_miss: false,
  is_unbalanced_emergent_miss: true,
  is_closely_related_guess: false,
  relationship_tier: "unclassified",
});

const closeGuess = indexRecord({
  candidate_id: "et-example-close",
  is_balanced_emergent_miss: true,
  is_closely_related_guess: true,
  relationship_tier: "closely_related",
});

const providerFailure = indexRecord({
  candidate_id: "et-example-provider",
  component: "flow",
  operator: "remove_established",
  status: "attacker_provider_failed",
  attacker_prediction: null,
  attacker_error: "provider unavailable",
  is_emergent_miss: false,
  is_balanced_emergent_miss: false,
  is_unbalanced_emergent_miss: false,
  is_closely_related_guess: false,
  relationship_tier: null,
});

const defaults: ExplorerFilters = {
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

const fixtureRecords = [
  exactHit,
  emergent,
  balanced,
  unbalanced,
  closeGuess,
  providerFailure,
];

describe("filterRecords quick filters", () => {
  it("filters emergent misses using backend booleans", () => {
    expect(
      filterRecords(fixtureRecords, { ...defaults, quickFilter: "emergent_miss" }),
    ).toEqual([emergent, balanced, unbalanced, closeGuess]);
  });

  it("filters balanced emergent misses", () => {
    expect(
      filterRecords(fixtureRecords, {
        ...defaults,
        quickFilter: "balanced_emergent_miss",
      }),
    ).toEqual([balanced, closeGuess]);
  });

  it("filters unbalanced emergent misses", () => {
    expect(
      filterRecords(fixtureRecords, {
        ...defaults,
        quickFilter: "unbalanced_emergent_miss",
      }),
    ).toEqual([emergent, unbalanced]);
  });

  it("filters closely related guesses", () => {
    expect(
      filterRecords(fixtureRecords, {
        ...defaults,
        quickFilter: "closely_related_guess",
      }),
    ).toEqual([balanced, closeGuess]);
  });

  it("never treats provider failures as emergent misses", () => {
    expect(
      filterRecords(fixtureRecords, { ...defaults, quickFilter: "emergent_miss" }),
    ).not.toContain(providerFailure);
  });
});

describe("filterRecords dimensional filters", () => {
  it("filters by fixture, family, operator, status, and category", () => {
    const records = [
      indexRecord({ fixture: "et-a", component: "flow", operator: "remove", status: "evaluated", mutation_category: "semantic" }),
      indexRecord({ fixture: "et-b", component: "pcre", operator: "remove", status: "evaluated", mutation_category: "representation" }),
      indexRecord({ fixture: "et-a", component: "flow", operator: "relax_start_anchor", status: "syntax_invalid", mutation_category: "semantic" }),
    ];

    expect(filterRecords(records, { ...defaults, fixture: "et-a" })).toHaveLength(2);
    expect(filterRecords(records, { ...defaults, component: "pcre" })).toEqual([records[1]]);
    expect(filterRecords(records, { ...defaults, operator: "remove" })).toHaveLength(2);
    expect(filterRecords(records, { ...defaults, status: "syntax_invalid" })).toEqual([records[2]]);
    expect(filterRecords(records, { ...defaults, category: "representation" })).toEqual([records[1]]);
  });

  it("does not mutate the source array", () => {
    const records = [...fixtureRecords];
    const snapshot = [...records];
    filterRecords(records, { ...defaults, quickFilter: "emergent_miss" });
    expect(records).toEqual(snapshot);
  });

  it("filters combinations by block count without excluding single records", () => {
    const single = indexRecord({ candidate_id: "single" });
    const twoBlocks = combinationRecord({
      candidate_id: "two",
      block_count: 2,
    });
    const threeBlocks = combinationRecord({
      candidate_id: "three",
      block_count: 3,
    });

    expect(
      filterRecords([threeBlocks, single, twoBlocks], {
        ...defaults,
        blockCount: 2,
      }),
    ).toEqual([single, twoBlocks]);
  });

  it("matches an included family against any combination member", () => {
    const single = indexRecord({ candidate_id: "single" });
    const flowContent = combinationRecord({
      candidate_id: "flow-content",
      included_families: ["flow", "content"],
    });
    const pcre = combinationRecord({
      candidate_id: "pcre",
      included_families: ["pcre"],
    });

    expect(
      filterRecords([flowContent, pcre, single], {
        ...defaults,
        includedFamily: "content",
      }),
    ).toEqual([flowContent, single]);
  });

  it.each(["primary", "near_cve_confusion_control"] as const)(
    "filters combinations by %s experiment role while preserving singles",
    (experimentRole) => {
      const single = indexRecord({ candidate_id: "single" });
      const primary = combinationRecord({
        candidate_id: "primary",
        experiment_role: "primary",
      });
      const control = combinationRecord({
        candidate_id: "control",
        experiment_role: "near_cve_confusion_control",
      });

      expect(
        filterRecords([single, primary, control], {
          ...defaults,
          experimentRole,
        }),
      ).toEqual([single, experimentRole === "primary" ? primary : control]);
    },
  );

  it("intersects quick, search, block-count, family, and arbitrary-role filters", () => {
    const matching = combinationRecord({
      candidate_id: "matching-token-target",
      block_count: 2,
      included_families: ["flow", "content"],
      experiment_role: "secondary_analysis",
      is_emergent_miss: true,
    });
    const records = [
      matching,
      combinationRecord({
        candidate_id: "matching-token-not-emergent",
        experiment_role: "secondary_analysis",
        is_emergent_miss: false,
      }),
      combinationRecord({
        candidate_id: "different-search-target",
        experiment_role: "secondary_analysis",
      }),
      combinationRecord({
        candidate_id: "matching-token-three-blocks",
        block_count: 3,
        experiment_role: "secondary_analysis",
      }),
      combinationRecord({
        candidate_id: "matching-token-wrong-family",
        included_families: ["flow", "pcre"],
        experiment_role: "secondary_analysis",
      }),
      combinationRecord({
        candidate_id: "matching-token-wrong-role",
        experiment_role: "primary",
      }),
    ];

    expect(
      filterRecords(records, {
        ...defaults,
        quickFilter: "emergent_miss",
        searchText: "matching-token",
        blockCount: 2,
        includedFamily: "content",
        experimentRole: "secondary_analysis",
      }),
    ).toEqual([matching]);
  });
});

describe("filterRecords search fields", () => {
  it("searches exactly the required index fields", () => {
    expect(SEARCHABLE_INDEX_FIELDS).toEqual([
      "candidate_id",
      "description",
      "fixture",
      "component",
      "operator",
      "attacker_prediction",
      "target_cve",
    ]);
  });

  it.each(SEARCHABLE_INDEX_FIELDS)("matches search text by %s independently", (field) => {
    const token = `findme-${field}-token`;
    const matched = indexRecord(searchOverride(field, token));
    const unmatched = indexRecord();

    expect(
      filterRecords([matched, unmatched], { ...defaults, searchText: token }),
    ).toEqual([matched]);
    expect(
      filterRecords([unmatched], { ...defaults, searchText: token }),
    ).toEqual([]);
  });

  it("matches search text case-insensitively", () => {
    const matched = indexRecord({ description: "Remove Sticky Buffer Requirement" });
    expect(
      filterRecords([matched], { ...defaults, searchText: "sticky buffer" }),
    ).toEqual([matched]);
  });
});

describe("sortRecords and groupByFamily", () => {
  it("sorts canonical families before unknown families alphabetically", () => {
    const records = [
      indexRecord({ component: "zz_custom", operator: "alpha", fixture: "et-z", candidate_id: "z-1" }),
      indexRecord({ component: "content", operator: "remove", fixture: "et-a", candidate_id: "a-1" }),
      indexRecord({ component: "aa_custom", operator: "beta", fixture: "et-y", candidate_id: "y-1" }),
      indexRecord({ component: "flow", operator: "remove_direction", fixture: "et-a", candidate_id: "a-2" }),
      indexRecord({ component: "flow", operator: "remove_direction", fixture: "et-b", candidate_id: "b-1" }),
    ];

    expect(sortRecords(records).map((entry) => entry.component)).toEqual([
      "flow",
      "flow",
      "content",
      "aa_custom",
      "zz_custom",
    ]);
  });

  it("preserves stable operator, fixture, and candidate ordering within a family", () => {
    const records = [
      indexRecord({ component: "flow", operator: "remove_established", fixture: "et-b", candidate_id: "b-2" }),
      indexRecord({ component: "flow", operator: "remove_direction", fixture: "et-a", candidate_id: "a-2" }),
      indexRecord({ component: "flow", operator: "remove_direction", fixture: "et-a", candidate_id: "a-1" }),
    ];

    expect(
      sortRecords(records).map((entry) => [
        entry.operator,
        entry.fixture,
        entry.candidate_id,
      ]),
    ).toEqual([
      ["remove_direction", "et-a", "a-1"],
      ["remove_direction", "et-a", "a-2"],
      ["remove_established", "et-b", "b-2"],
    ]);
  });

  it("groups records by family with human labels in canonical order", () => {
    const records = sortRecords([
      indexRecord({ component: "content", candidate_id: "c-1" }),
      indexRecord({ component: "flow", candidate_id: "f-1" }),
      indexRecord({ component: "zz_custom", candidate_id: "z-1" }),
    ]);

    expect(groupByFamily(records)).toEqual([
      {
        family: "flow",
        label: "Flow",
        records: [records[0]],
      },
      {
        family: "content",
        label: "Content",
        records: [records[1]],
      },
      {
        family: "zz_custom",
        label: "Zz custom",
        records: [records[2]],
      },
    ]);
  });

  it("detects only records carrying combination extensions", () => {
    expect(isCombinationRecord(indexRecord())).toBe(false);
    expect(isCombinationRecord(combinationRecord())).toBe(true);
    expect(
      isCombinationRecord(indexRecord({
        component: "combination",
        block_count: 2,
      })),
    ).toBe(false);
  });

  it("sorts combinations by fixture, block count, families, then candidate", () => {
    const records = [
      combinationRecord({ fixture: "fixture-b", block_count: 2, included_families: ["flow"], candidate_id: "a" }),
      combinationRecord({ fixture: "fixture-a", block_count: 3, included_families: ["content"], candidate_id: "a" }),
      combinationRecord({ fixture: "fixture-a", block_count: 2, included_families: ["pcre"], candidate_id: "a" }),
      combinationRecord({ fixture: "fixture-a", block_count: 2, included_families: ["flow", "content"], candidate_id: "b" }),
      combinationRecord({ fixture: "fixture-a", block_count: 2, included_families: ["flow", "content"], candidate_id: "a" }),
    ];
    const snapshot = [...records];

    expect(sortRecords(records).map((record) => record.candidate_id)).toEqual([
      "a",
      "b",
      "a",
      "a",
      "a",
    ]);
    expect(sortRecords(records).map((record) => record.fixture)).toEqual([
      "fixture-a",
      "fixture-a",
      "fixture-a",
      "fixture-a",
      "fixture-b",
    ]);
    expect(records).toEqual(snapshot);
  });

  it("keeps the established single-record ordering unchanged", () => {
    const records = [
      indexRecord({ component: "content", operator: "remove", fixture: "et-a", candidate_id: "content" }),
      indexRecord({ component: "flow", operator: "z", fixture: "et-a", candidate_id: "flow-z" }),
      indexRecord({ component: "flow", operator: "a", fixture: "et-b", candidate_id: "flow-a-b" }),
      indexRecord({ component: "flow", operator: "a", fixture: "et-a", candidate_id: "flow-a-a" }),
    ];

    expect(sortRecords(records).map((record) => record.candidate_id)).toEqual([
      "flow-a-a",
      "flow-a-b",
      "flow-z",
      "content",
    ]);
  });
});

describe("mutationApi types", () => {
  it("keeps index-only derived flags off the detail type", () => {
    type DetailHasIndexFlags = MutationRecordDetail extends {
      is_emergent_miss: boolean;
    }
      ? true
      : false;
    const detailHasIndexFlags = false as DetailHasIndexFlags;
    expect(detailHasIndexFlags).toBe(false);
  });

  it("models strict projected combination detail blocks", () => {
    const block: CombinationBuildingBlock = {
      candidate_id: "fixture-a-flow",
      join_status: "available",
      component: "flow",
      operator: "remove",
      description: "Remove flow.",
      buffer: null,
      params: {},
      mutation_category: "semantic",
      positive_recall: 1,
      negative_false_positive_rate: 0,
      benign_false_positive_rate: null,
      attacker: {
        status: "success",
        predicted_cve: TARGET,
        reasoning: null,
        clues: [],
        error: null,
      },
      attacker_prediction: TARGET,
      attacker_correct: true,
      relationship_tier: "exact_match",
      meaningful_obscurity: false,
      baseline_rule: "alert ...",
      mutated_rule: "alert ...",
      exact_attribution: "hit",
      effective_attribution: "hit",
    };
    const unavailableBlock: CombinationBuildingBlock = {
      candidate_id: "fixture-a-missing",
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
    };
    const detail: MutationRecordDetail = {
      ...indexRecord(),
      fixture: "fixture-a",
      rule: "alert ...",
      baseline_rule: "alert ...",
      mutated_rule: "alert ...",
      case_results: {},
      benign_capture_results: {},
      attacker_exchange: null,
      case_groups: { positive: [], negative: [], benign: [] },
      suite_reason: null,
      attacker: {
        status: "success",
        predicted_cve: TARGET,
        reasoning: null,
        clues: [],
        prompt: null,
        raw_response: null,
        error: null,
      },
      diagnostics: [],
      building_blocks: [block, unavailableBlock],
      join_diagnostics: [
        { source_candidate_id: null, error: "baseline missing" },
        {
          source_candidate_id: null,
          file: "results.jsonl",
          line: 3,
          error: "malformed source row",
        },
      ],
    };

    expect(detail.building_blocks).toEqual([block, unavailableBlock]);
  });
});

describe("mutationLabels", () => {
  it("formats family labels for canonical and unknown components", () => {
    expect(formatFamilyLabel("sticky_buffer")).toBe("Sticky buffer");
    expect(formatFamilyLabel("destination_port")).toBe("Destination port");
    expect(formatFamilyLabel("zz_custom")).toBe("Zz custom");
  });

  it("derives synthetic and benign false-positive labels from measured rates", () => {
    expect(syntheticFpStatus(indexRecord({ negative_false_positive_rate: 0 }))).toBe("clean");
    expect(syntheticFpStatus(indexRecord({ negative_false_positive_rate: 0.25 }))).toBe("dirty");
    expect(syntheticFpStatus(indexRecord({ negative_false_positive_rate: null }))).toBe("unmeasured");
    expect(benignFpStatus(indexRecord({ benign_false_positive_rate: 0 }))).toBe("clean");
    expect(benignFpStatus(indexRecord({ benign_false_positive_rate: null }))).toBe("unmeasured");
    expect(formatFpLabel("clean")).toBe("Clean");
    expect(formatFpLabel("dirty")).toBe("False positive");
    expect(formatFpLabel("unmeasured")).toBe("Unmeasured");
  });

  it("distinguishes exact and effective comparison outcomes", () => {
    expect(formatComparisonLabel("exact", "improved_obscurity")).toBe(
      "Exact comparison: improved obscurity",
    );
    expect(formatComparisonLabel("effective", "reinforced_obscurity")).toBe(
      "Effective comparison: reinforced obscurity",
    );
    expect(formatComparisonLabel("exact", "unmeasured")).toBe(
      "Exact comparison: unmeasured",
    );
    expect(formatComparisonLabel("effective", "unmeasured")).toBe(
      "Effective comparison: unmeasured",
    );
  });

  it("labels roles, precision changes, and source blocks", () => {
    expect(formatExperimentRole("primary")).toBe("Primary experiment");
    expect(formatExperimentRole("near_cve_confusion_control")).toBe(
      "Near-CVE confusion control",
    );
    expect(formatExperimentRole(null)).toBe("Experiment role unassigned");
    expect(formatPrecisionChange("precision_only_cost")).toBe(
      "Precision-only cost",
    );
    expect(formatPrecisionChange("no_precision_cost")).toBe("No precision cost");
    expect(formatPrecisionChange("unmeasured")).toBe(
      "Precision change unmeasured",
    );
    expect(
      formatSourceBlockLabel({
        candidate_id: "fixture-a-flow",
        join_status: "available",
        component: "flow",
        operator: "remove_established",
      }),
    ).toBe("Flow / Remove established");
    expect(
      formatSourceBlockLabel({
        candidate_id: "fixture-a-missing",
        join_status: "unavailable",
        component: null,
        operator: null,
      }),
    ).toBe("Unavailable source block (fixture-a-missing)");
  });

  it("formats unknown comparison, precision, and role values readably", () => {
    expect(formatComparisonLabel("exact", "future_obscurity_mode")).toBe(
      "Exact comparison: Future obscurity mode",
    );
    expect(formatComparisonLabel("effective", undefined)).toBe(
      "Effective comparison: unmeasured",
    );
    expect(formatPrecisionChange("future_precision_mode")).toBe(
      "Future precision mode",
    );
    expect(formatPrecisionChange(undefined)).toBe("Precision change unmeasured");
    expect(formatExperimentRole("secondary_analysis")).toBe(
      "Secondary analysis",
    );
  });
});

function combinationRecord(
  overrides: Partial<MutationRecordIndexEntry> = {},
): MutationRecordIndexEntry {
  return indexRecord({
    candidate_id: "fixture-a-combination",
    component: "combination",
    operator: "blocks_2",
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
    precision_change: "no_precision_cost",
    ...overrides,
  });
}
