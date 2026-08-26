import type { MutationRecordIndexEntry } from "./mutationApi";
import { isCombinationRecord, type FamilyGroup } from "./mutationExplorer";
import {
  benignFpStatus,
  formatComparisonLabel,
  formatExperimentRole,
  formatFamilyLabel,
  formatFpLabel,
  formatMutationLabel,
  formatPrecisionChange,
  formatRate,
  formatRecordStatus,
  formatRelationship,
  isValidationGateStatus,
  syntheticFpStatus,
} from "./mutationLabels";

export type MutationTableProps = {
  groups: FamilyGroup[];
  selectedCandidateId: string | null;
  onSelect: (record: MutationRecordIndexEntry) => void;
  combinationMode?: boolean;
};

function OutcomeLabels({ record }: { record: MutationRecordIndexEntry }) {
  if (record.status !== "evaluated") {
    return (
      <span className="outcome-labels">
        <span className={`pill ${isValidationGateStatus(record.status) ? "pending" : "rejected"}`}>
          {formatRecordStatus(record.status)}
        </span>
        <span className="pill neutral">Not emergent</span>
      </span>
    );
  }
  return (
    <span className="outcome-labels">
      {record.is_balanced_emergent_miss && <span className="pill passed">Balanced emergent</span>}
      {record.is_unbalanced_emergent_miss && <span className="pill pending">Unbalanced emergent</span>}
      {record.is_emergent_miss && !record.is_balanced_emergent_miss && !record.is_unbalanced_emergent_miss
        && <span className="pill pending">Emergent</span>}
      {!record.is_emergent_miss && <span className="pill neutral">Not emergent</span>}
    </span>
  );
}

function includedBlockLabels(record: MutationRecordIndexEntry): string[] {
  if (record.included_components?.length && record.included_operators?.length) {
    return record.included_components.map((component, index) => (
      `${formatFamilyLabel(component)} / ${formatMutationLabel(record.included_operators?.[index] ?? "unknown")}`
    ));
  }
  return (record.included_block_labels ?? []).map((label) => {
    const separator = label.indexOf("/");
    if (separator < 0) return formatMutationLabel(label);
    return `${formatFamilyLabel(label.slice(0, separator))} / ${formatMutationLabel(label.slice(separator + 1))}`;
  });
}

function CombinationOutcome({ record }: { record: MutationRecordIndexEntry }) {
  return (
    <span className="combination-outcome">
      <span className="comparison-labels">
        <span className="pill neutral">
          {formatComparisonLabel("exact", record.exact_obscurity_comparison)}
        </span>
        <span className="pill neutral">
          {formatComparisonLabel("effective", record.effective_obscurity_comparison)}
        </span>
        <span className={`pill ${record.precision_change === "precision_only_cost" ? "rejected" : "neutral"}`}>
          {formatPrecisionChange(record.precision_change)}
        </span>
      </span>
      <OutcomeLabels record={record} />
    </span>
  );
}

function SourceJoinSummary({ record }: { record: MutationRecordIndexEntry }) {
  const available = record.source_join_status === "complete";
  const status = available
    ? "Source evidence complete"
    : "Source evidence unavailable";
  const diagnosticCount = record.source_join_diagnostic_count;
  return (
    <span className="source-join-index">
      <span className={`pill ${available ? "passed" : "pending"}`}>{status}</span>
      <small>
        {typeof diagnosticCount === "number"
          ? `${diagnosticCount} join ${diagnosticCount === 1 ? "diagnostic" : "diagnostics"}`
          : "Join diagnostic count unavailable"}
      </small>
    </span>
  );
}

export function MutationTable({
  groups,
  selectedCandidateId,
  onSelect,
  combinationMode,
}: MutationTableProps) {
  const isCombinationMode = combinationMode
    ?? groups.some((group) => group.records.some(isCombinationRecord));
  if (!groups.length) {
    return (
      <p className="empty mutation-empty">
        {isCombinationMode
          ? "No combinations match these filters."
          : "No mutations match these filters."}
      </p>
    );
  }
  return (
    <div className={`mutation-table-wrap${isCombinationMode ? " combination-table-wrap" : ""}`}>
      <table className="mutation-table">
        {isCombinationMode && (
          <caption className="visually-hidden">
            Combination analysis results with included building blocks, source availability,
            attribution, and comparison outcomes.
          </caption>
        )}
        <thead>
          <tr>
            <th scope="col">{isCombinationMode ? "Combination" : "Mutation"}</th>
            <th scope="col">{isCombinationMode ? "Experiment role" : "Buffer / component"}</th>
            <th scope="col">{isCombinationMode ? "Positive recall" : "Recall"}</th>
            <th scope="col">Synthetic false-positive rate</th>
            <th scope="col">Benign false-positive rate</th>
            <th scope="col">Attribution</th>
            <th scope="col">{isCombinationMode ? "Combination outcome" : "Outcome"}</th>
          </tr>
        </thead>
        {groups.map((group) => (
          <tbody key={group.family}>
            <tr className="family-row">
              <th scope="rowgroup" colSpan={7}>
                {group.label}
                <span className="family-count">
                  {group.records.length}
                  <span className="visually-hidden">
                    {` ${isCombinationMode
                      ? group.records.length === 1 ? "combination" : "combinations"
                      : group.records.length === 1 ? "mutation" : "mutations"} in ${group.label}`}
                  </span>
                </span>
              </th>
            </tr>
            {group.records.map((record) => (
              <tr
                key={record.candidate_id}
                className={selectedCandidateId === record.candidate_id ? "selected" : ""}
              >
                <th scope="row">
                  <button
                    type="button"
                    aria-pressed={selectedCandidateId === record.candidate_id}
                    onClick={() => onSelect(record)}
                  >
                    <strong>{formatMutationLabel(record.description)}</strong>
                    {isCombinationRecord(record) ? (
                      <>
                        <small>
                          {record.block_count ?? includedBlockLabels(record).length} building blocks · {record.fixture}
                        </small>
                        <span
                          className="included-block-labels"
                          role="list"
                          aria-label="Included building blocks"
                        >
                          {includedBlockLabels(record).map((label, index) => (
                            <span role="listitem" key={`${label}-${index}`}>{label}</span>
                          ))}
                        </span>
                        <SourceJoinSummary record={record} />
                      </>
                    ) : (
                      <small>{formatMutationLabel(record.operator)} · {record.fixture}</small>
                    )}
                  </button>
                </th>
                <td>
                  {isCombinationRecord(record)
                    ? formatExperimentRole(record.experiment_role)
                    : record.buffer ?? formatMutationLabel(record.component)}
                </td>
                <td>{formatRate(record.positive_recall)}</td>
                <td>
                  <span className={`pill fp-${syntheticFpStatus(record)}`}>
                    {formatFpLabel(syntheticFpStatus(record))}
                  </span>
                  <small>{formatRate(record.negative_false_positive_rate)}</small>
                </td>
                <td>
                  <span className={`pill fp-${benignFpStatus(record)}`}>
                    {formatFpLabel(benignFpStatus(record))}
                  </span>
                  <small>{formatRate(record.benign_false_positive_rate)}</small>
                </td>
                <td>
                  <span>Target: {record.target_cve}</span>
                  <span>Guess: {record.attacker_prediction ?? "Unavailable"}</span>
                  <small>{formatRelationship(record.relationship_tier)}</small>
                </td>
                <td>
                  {isCombinationRecord(record)
                    ? <CombinationOutcome record={record} />
                    : <OutcomeLabels record={record} />}
                </td>
              </tr>
            ))}
          </tbody>
        ))}
      </table>
    </div>
  );
}
