import type {
  ExplorerQuickFilter,
  MutationRecordIndexEntry,
} from "./mutationApi";
import {
  filterRecords,
  isCombinationRecord,
  type ExplorerFilters,
} from "./mutationExplorer";
import {
  formatExperimentRole,
  formatFamilyLabel,
  formatMutationLabel,
} from "./mutationLabels";

type QuickFilterOption = {
  value: ExplorerQuickFilter;
  label: string;
};

const QUICK_FILTERS: QuickFilterOption[] = [
  { value: "all", label: "All" },
  { value: "emergent_miss", label: "Emergent" },
  { value: "balanced_emergent_miss", label: "Balanced" },
  { value: "unbalanced_emergent_miss", label: "Unbalanced" },
  { value: "closely_related_guess", label: "Close CVE" },
];

function unique(records: MutationRecordIndexEntry[], field: keyof MutationRecordIndexEntry) {
  return [...new Set(records.map((record) => String(record[field])))].sort();
}

export type MutationFilterBarProps = {
  records: MutationRecordIndexEntry[];
  filters: ExplorerFilters;
  onChange: (filters: ExplorerFilters) => void;
};

export function MutationFilterBar({
  records,
  filters,
  onChange,
}: MutationFilterBarProps) {
  const combinationRecords = records.filter(isCombinationRecord);
  const combinationMode = combinationRecords.length > 0;
  const blockCounts = [...new Set(
    combinationRecords
      .map((record) => record.block_count)
      .filter((value): value is number => typeof value === "number"),
  )].sort((left, right) => left - right);
  const includedFamilies = [...new Set(
    combinationRecords.flatMap((record) => record.included_families ?? []),
  )].sort();
  const experimentRoles = [...new Set(
    combinationRecords
      .map((record) => record.experiment_role)
      .filter((value): value is NonNullable<typeof value> => Boolean(value)),
  )].sort();
  const update = <Key extends keyof ExplorerFilters>(
    key: Key,
    value: ExplorerFilters[Key],
  ) => onChange({ ...filters, [key]: value });

  return (
    <section className="mutation-filters" aria-label="Mutation filters">
      <fieldset className="quick-filters">
        <legend>Quick filters</legend>
        {QUICK_FILTERS.map((option) => {
          const count = filterRecords(records, {
            ...filters,
            quickFilter: option.value,
          }).length;
          return (
            <button
              key={option.value}
              type="button"
              className={filters.quickFilter === option.value ? "selected" : ""}
              aria-pressed={filters.quickFilter === option.value}
              aria-label={`${option.label}: ${count} ${count === 1 ? "record" : "records"}`}
              onClick={() => update("quickFilter", option.value)}
            >
              {option.label}
              <span className="filter-count" aria-hidden="true">{count}</span>
            </button>
          );
        })}
      </fieldset>
      <div className="filter-grid">
        <label>
          Search mutations
          <input
            type="search"
            value={filters.searchText}
            onChange={(event) => update("searchText", event.target.value)}
            placeholder="Candidate, CVE, operator, fixture…"
          />
        </label>
        <label>
          Fixture
          <select
            value={filters.fixture}
            onChange={(event) => update("fixture", event.target.value)}
          >
            <option value="all">All fixtures</option>
            {unique(records, "fixture").map((value) => <option key={value}>{value}</option>)}
          </select>
        </label>
        <label>
          Family
          <select
            value={filters.component}
            onChange={(event) => update("component", event.target.value)}
          >
            <option value="all">All families</option>
            {unique(records, "component").map((value) => (
              <option key={value} value={value}>{formatFamilyLabel(value)}</option>
            ))}
          </select>
        </label>
        <label>
          Operator
          <select
            value={filters.operator}
            onChange={(event) => update("operator", event.target.value)}
          >
            <option value="all">All operators</option>
            {unique(records, "operator").map((value) => (
              <option key={value} value={value}>{formatMutationLabel(value)}</option>
            ))}
          </select>
        </label>
        <label>
          Status
          <select
            value={filters.status}
            onChange={(event) => update("status", event.target.value)}
          >
            <option value="all">All statuses</option>
            {unique(records, "status").map((value) => (
              <option key={value} value={value}>{formatMutationLabel(value)}</option>
            ))}
          </select>
        </label>
        <label>
          Category
          <select
            value={filters.category}
            onChange={(event) => update(
              "category",
              event.target.value as ExplorerFilters["category"],
            )}
          >
            <option value="all">All categories</option>
            <option value="semantic">Semantic</option>
            <option value="representation">Representation</option>
            <option value="performance">Performance</option>
          </select>
        </label>
        {combinationMode && (
          <>
            <label>
              Block count
              <select
                aria-label="Block count"
                value={filters.blockCount ?? "all"}
                onChange={(event) => update(
                  "blockCount",
                  event.target.value === "all" ? "all" : Number(event.target.value),
                )}
              >
                <option value="all">All block counts</option>
                {blockCounts.map((value) => (
                  <option key={value} value={value}>
                    {value} {value === 1 ? "block" : "blocks"}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Included family
              <select
                aria-label="Included family"
                value={filters.includedFamily ?? "all"}
                onChange={(event) => update("includedFamily", event.target.value)}
              >
                <option value="all">All included families</option>
                {includedFamilies.map((value) => (
                  <option key={value} value={value}>{formatFamilyLabel(value)}</option>
                ))}
              </select>
            </label>
            <label>
              Experiment role
              <select
                aria-label="Experiment role"
                value={filters.experimentRole ?? "all"}
                onChange={(event) => update("experimentRole", event.target.value)}
              >
                <option value="all">All experiment roles</option>
                {experimentRoles.map((value) => (
                  <option key={value} value={value}>{formatExperimentRole(value)}</option>
                ))}
              </select>
            </label>
          </>
        )}
      </div>
    </section>
  );
}
