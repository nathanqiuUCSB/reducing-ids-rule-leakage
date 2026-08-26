import type {
  AnalysisCategory,
  ExperimentRole,
  ExplorerQuickFilter,
  MutationRecordIndexEntry,
} from "./mutationApi";
import { formatFamilyLabel } from "./mutationLabels";

export const MUTATION_FAMILY_ORDER = [
  "flow",
  "pcre",
  "sticky_buffer",
  "destination_port",
  "relative_constraint",
  "buffer_size",
  "byte_test",
  "content_modifier",
  "negated_content",
  "content",
  "baseline",
] as const;

export type ExplorerFilters = {
  quickFilter: ExplorerQuickFilter;
  fixture: string | "all";
  component: string | "all";
  operator: string | "all";
  status: string | "all";
  category: "all" | AnalysisCategory;
  blockCount?: number | "all";
  includedFamily?: string | "all";
  experimentRole?: ExperimentRole | "all";
  searchText: string;
};

export type FamilyGroup = {
  family: string;
  label: string;
  records: MutationRecordIndexEntry[];
};

export const SEARCHABLE_INDEX_FIELDS = [
  "candidate_id",
  "description",
  "fixture",
  "component",
  "operator",
  "attacker_prediction",
  "target_cve",
] as const satisfies ReadonlyArray<keyof MutationRecordIndexEntry>;

export type SearchableIndexField = (typeof SEARCHABLE_INDEX_FIELDS)[number];

const familyRank = new Map<string, number>(
  MUTATION_FAMILY_ORDER.map((family, index) => [family, index]),
);

export function familySortKey(component: string): number {
  return familyRank.get(component) ?? MUTATION_FAMILY_ORDER.length;
}

export function isCombinationRecord(
  record: MutationRecordIndexEntry,
): boolean {
  return (
    record.component === "combination"
    && Array.isArray(record.included_families)
  );
}

function compareStringArrays(left: string[], right: string[]): number {
  const sharedLength = Math.min(left.length, right.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const delta = left[index].localeCompare(right[index]);
    if (delta !== 0) {
      return delta;
    }
  }
  return left.length - right.length;
}

function compareCombinationRecords(
  left: MutationRecordIndexEntry,
  right: MutationRecordIndexEntry,
): number {
  const fixtureDelta = left.fixture.localeCompare(right.fixture);
  if (fixtureDelta !== 0) {
    return fixtureDelta;
  }

  const blockCountDelta = (left.block_count ?? 0) - (right.block_count ?? 0);
  if (blockCountDelta !== 0) {
    return blockCountDelta;
  }

  const familyDelta = compareStringArrays(
    left.included_families ?? [],
    right.included_families ?? [],
  );
  if (familyDelta !== 0) {
    return familyDelta;
  }

  return left.candidate_id.localeCompare(right.candidate_id);
}

function compareRecords(
  left: MutationRecordIndexEntry,
  right: MutationRecordIndexEntry,
): number {
  if (isCombinationRecord(left) && isCombinationRecord(right)) {
    return compareCombinationRecords(left, right);
  }

  const leftRank = familySortKey(left.component);
  const rightRank = familySortKey(right.component);
  if (leftRank !== rightRank) {
    return leftRank - rightRank;
  }
  if (
    leftRank >= MUTATION_FAMILY_ORDER.length
    && left.component !== right.component
  ) {
    return left.component.localeCompare(right.component);
  }

  const operatorDelta = left.operator.localeCompare(right.operator);
  if (operatorDelta !== 0) {
    return operatorDelta;
  }

  const fixtureDelta = left.fixture.localeCompare(right.fixture);
  if (fixtureDelta !== 0) {
    return fixtureDelta;
  }

  return left.candidate_id.localeCompare(right.candidate_id);
}

export function sortRecords(
  records: MutationRecordIndexEntry[],
): MutationRecordIndexEntry[] {
  return [...records].sort(compareRecords);
}

function matchesQuickFilter(
  record: MutationRecordIndexEntry,
  quickFilter: ExplorerQuickFilter,
): boolean {
  switch (quickFilter) {
    case "all":
      return true;
    case "emergent_miss":
      return record.is_emergent_miss;
    case "balanced_emergent_miss":
      return record.is_balanced_emergent_miss;
    case "unbalanced_emergent_miss":
      return record.is_unbalanced_emergent_miss;
    case "closely_related_guess":
      return record.is_closely_related_guess;
  }
}

function searchableText(record: MutationRecordIndexEntry): string {
  return SEARCHABLE_INDEX_FIELDS.map((field) => {
    const value = record[field];
    return value == null ? "" : String(value);
  })
    .join("\n")
    .toLowerCase();
}

export function filterRecords(
  records: MutationRecordIndexEntry[],
  filters: ExplorerFilters,
): MutationRecordIndexEntry[] {
  const search = filters.searchText.trim().toLowerCase();
  const blockCount = filters.blockCount ?? "all";
  const includedFamily = filters.includedFamily ?? "all";
  const experimentRole = filters.experimentRole ?? "all";

  return records.filter((record) => {
    if (!matchesQuickFilter(record, filters.quickFilter)) {
      return false;
    }
    if (filters.fixture !== "all" && record.fixture !== filters.fixture) {
      return false;
    }
    if (filters.component !== "all" && record.component !== filters.component) {
      return false;
    }
    if (filters.operator !== "all" && record.operator !== filters.operator) {
      return false;
    }
    if (filters.status !== "all" && record.status !== filters.status) {
      return false;
    }
    if (
      filters.category !== "all"
      && record.mutation_category !== filters.category
    ) {
      return false;
    }
    if (isCombinationRecord(record)) {
      if (blockCount !== "all" && record.block_count !== blockCount) {
        return false;
      }
      if (
        includedFamily !== "all"
        && !record.included_families?.includes(includedFamily)
      ) {
        return false;
      }
      if (
        experimentRole !== "all"
        && record.experiment_role !== experimentRole
      ) {
        return false;
      }
    }
    if (search && !searchableText(record).includes(search)) {
      return false;
    }
    return true;
  });
}

function compareFamilies(left: string, right: string): number {
  const leftRank = familySortKey(left);
  const rightRank = familySortKey(right);
  if (leftRank !== rightRank) {
    if (
      leftRank >= MUTATION_FAMILY_ORDER.length
      && rightRank >= MUTATION_FAMILY_ORDER.length
    ) {
      return left.localeCompare(right);
    }
    return leftRank - rightRank;
  }
  return left.localeCompare(right);
}

export function groupByFamily(
  records: MutationRecordIndexEntry[],
): FamilyGroup[] {
  const grouped = new Map<string, MutationRecordIndexEntry[]>();
  for (const record of records) {
    const bucket = grouped.get(record.component);
    if (bucket) {
      bucket.push(record);
    } else {
      grouped.set(record.component, [record]);
    }
  }

  return [...grouped.keys()]
    .sort(compareFamilies)
    .map((family) => ({
      family,
      label: formatFamilyLabel(family),
      records: sortRecords(grouped.get(family) ?? []),
    }));
}
