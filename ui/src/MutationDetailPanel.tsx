import type {
  AttackerDetailStatus,
  MutationRecordDetail,
} from "./mutationApi";
import {
  asSentence,
  benignFpStatus,
  formatComparisonLabel,
  formatExperimentRole,
  formatFpLabel,
  formatMutationLabel,
  formatPrecisionChange,
  formatRate,
  formatRecordStatus,
  formatRelationship,
  isAttackerFailureStatus,
  isValidationGateStatus,
  recordStatusBanner,
  syntheticFpStatus,
} from "./mutationLabels";
import { CombinationBuildingBlocks } from "./CombinationBuildingBlocks";
import { RuleDiff } from "./RuleDiff";

const ATTACKER_STATUS_LABELS: Record<AttackerDetailStatus, string> = {
  success: "Successful response",
  provider: "Provider failure",
  parse: "Parse failure",
  empty_response: "Empty response failure",
  empty_prediction: "Empty prediction failure",
  validation: "Attacker not run",
};

function attackerStatusLabel(status: AttackerDetailStatus): string {
  return ATTACKER_STATUS_LABELS[status] ?? formatMutationLabel(String(status));
}

function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Unavailable";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function PcapGroup({
  title,
  cases,
  showVerdict = true,
}: {
  title: string;
  cases: Record<string, unknown>[];
  showVerdict?: boolean;
}) {
  return (
    <section className="pcap-group">
      <h4>{title} <span className="pill neutral">{cases.length}</span></h4>
      {cases.length ? (
        <ul>
          {cases.map((entry, index) => {
            const name = displayValue(
              entry.pcap_name ?? entry.name ?? entry.source_id ?? `Case ${index + 1}`,
            );
            const passLabel = entry.passed === true
              ? "Passed"
              : entry.passed === false ? "Failed" : "Unknown";
            const activityLabel = entry.fired === true
              ? "Fired"
              : entry.fired === false ? "Silent" : "Not measured";
            return (
              <li key={`${name}-${index}`}>
                <header>
                  <strong>{name}</strong>
                  <span className="pcap-status">
                    {showVerdict && (
                      <span className={`pill ${entry.passed === true ? "passed" : entry.passed === false ? "rejected" : "pending"}`}>
                        {passLabel}
                      </span>
                    )}
                    <span className="pill neutral">{activityLabel}</span>
                  </span>
                </header>
                {entry.reason != null && <p>{displayValue(entry.reason)}</p>}
                {entry.predicate_id != null && (
                  <small>Predicate: {displayValue(entry.predicate_id)}</small>
                )}
                {entry.source_id != null && <small>Source: {displayValue(entry.source_id)}</small>}
                {entry.error != null && <p className="error-inline">{displayValue(entry.error)}</p>}
              </li>
            );
          })}
        </ul>
      ) : <p className="muted">No cases recorded.</p>}
    </section>
  );
}

export function isCloseCveDetail(detail: MutationRecordDetail): boolean {
  return detail.status === "evaluated"
    && detail.component !== "baseline"
    && detail.positive_recall === 1
    && detail.attacker.status === "success"
    && detail.attacker_error === null
    && detail.attacker.predicted_cve !== null
    && detail.attacker.predicted_cve !== detail.target_cve
    && detail.attacker_correct === false
    && detail.relationship_tier === "closely_related"
    && detail.meaningful_obscurity === false;
}

export function MutationDetailPanel({ detail }: { detail: MutationRecordDetail }) {
  const combinationMode = detail.building_blocks !== undefined;
  const attackerFailed = isAttackerFailureStatus(detail.status);
  const validationGate = isValidationGateStatus(detail.status);
  const statusBanner = recordStatusBanner(detail.status);
  const baselineRule = detail.baseline_rule ?? "";
  const mutatedRule = detail.mutated_rule ?? detail.rule ?? "";
  const attackerFailureText = [
    statusBanner,
    detail.attacker.error
      ? `Reported error: ${asSentence(detail.attacker.error)}`
      : null,
    "This record is not classified as an emergent outcome.",
  ].filter(Boolean).join(" ");
  return (
    <article className="mutation-detail-panel" aria-labelledby="mutation-detail-title">
      <header className="mutation-detail-header">
        <div>
          <p className="eyebrow">{formatMutationLabel(detail.component)} · {detail.fixture}</p>
          <h2 id="mutation-detail-title">{formatMutationLabel(detail.description)}</h2>
          <p className="muted"><code>{detail.candidate_id}</code></p>
        </div>
        <span className={`pill ${detail.syntax_valid ? "passed" : "rejected"}`}>
          {detail.syntax_valid ? "Syntax valid" : "Syntax invalid"}
        </span>
      </header>

      {isCloseCveDetail(detail) && (
        <p className="close-cve-warning" role="status">
          Closely related CVE guess — not counted as meaningful obscurity.
        </p>
      )}
      {validationGate && statusBanner && (
        <p className="validation-gate" role="status">
          <strong>{formatRecordStatus(detail.status)}</strong> — {statusBanner}
        </p>
      )}
      {attackerFailed && statusBanner && (
        <p className="attacker-failure" role="status">
          <strong>{formatRecordStatus(detail.status)}</strong> — {attackerFailureText}
        </p>
      )}

      {combinationMode && (
        <section className="combined-outcome" aria-labelledby="combined-outcome-title">
          <div>
            <h3 id="combined-outcome-title">Combined outcome</h3>
            <p className="muted">
              {detail.block_count ?? detail.building_blocks?.length ?? 0} building blocks ·{" "}
              {formatExperimentRole(detail.experiment_role)}
            </p>
          </div>
          <div className="comparison-labels" aria-label="Combination comparisons">
            <span className="pill neutral">
              {formatComparisonLabel("exact", detail.exact_obscurity_comparison)}
            </span>
            <span className="pill neutral">
              {formatComparisonLabel("effective", detail.effective_obscurity_comparison)}
            </span>
            <span className={`pill ${detail.precision_change === "precision_only_cost" ? "rejected" : "neutral"}`}>
              {formatPrecisionChange(detail.precision_change)}
            </span>
          </div>
        </section>
      )}

      <section className="metric-grid" aria-label="Mutation outcome summary">
        <div><span>Positive recall</span><strong>{formatRate(detail.positive_recall)}</strong></div>
        <div>
          <span>Synthetic false-positive rate</span>
          <strong>{formatFpLabel(syntheticFpStatus(detail))} · {formatRate(detail.negative_false_positive_rate)} FP</strong>
        </div>
        <div>
          <span>Benign false-positive rate</span>
          <strong>{formatFpLabel(benignFpStatus(detail))} · {formatRate(detail.benign_false_positive_rate)} FP</strong>
        </div>
        <div><span>Exact CVE</span><strong>{detail.attacker_correct === true ? "Match" : detail.attacker_correct === false ? "Different" : "Unavailable"}</strong></div>
        <div><span>Effective attribution</span><strong>{formatRelationship(detail.relationship_tier)}</strong></div>
        <div><span>Meaningful obscurity</span><strong>{displayValue(detail.meaningful_obscurity)}</strong></div>
      </section>

      {combinationMode && (
        <CombinationBuildingBlocks
          blocks={detail.building_blocks ?? []}
          diagnostics={detail.join_diagnostics}
        />
      )}

      <section className="detail-section">
        <h3>Mutation parameters</h3>
        <dl className="parameter-list">
          <div><dt>Operator</dt><dd>{formatMutationLabel(detail.operator)}</dd></div>
          <div><dt>Buffer</dt><dd>{detail.buffer ?? "None"}</dd></div>
          <div><dt>Option index</dt><dd>{displayValue(detail.option_index)}</dd></div>
          {Object.entries(detail.params).map(([name, value]) => (
            <div key={name}><dt>{formatMutationLabel(name)}</dt><dd>{displayValue(value)}</dd></div>
          ))}
        </dl>
      </section>

      <section className="detail-section rule-comparison">
        <h3>Rule comparison</h3>
        <div className="rule-pair">
          <div><h4>Baseline rule</h4><pre className="rule">{baselineRule || "Unavailable"}</pre></div>
          <div><h4>Mutated rule</h4><pre className="rule">{mutatedRule || "Unavailable"}</pre></div>
        </div>
        {baselineRule && mutatedRule && (
          <RuleDiff
            before={baselineRule}
            after={mutatedRule}
            label="Rule diff: baseline → mutation"
            open
          />
        )}
      </section>

      <section className="detail-section">
        <h3>PCAP outcomes</h3>
        {detail.suite_reason && <p className="muted">Suite: {detail.suite_reason}</p>}
        <div className="pcap-groups">
          <PcapGroup title="Positive captures" cases={detail.case_groups.positive} />
          <PcapGroup title="Negative captures" cases={detail.case_groups.negative} />
          <PcapGroup
            title="Benign captures"
            cases={detail.case_groups.benign}
            showVerdict={false}
          />
        </div>
      </section>

      <section className="detail-section attacker-detail">
        <h3>Attacker attribution</h3>
        <dl className="attribution-grid">
          <div><dt>Target CVE</dt><dd>{detail.target_cve}</dd></div>
          <div><dt>Attacker guess</dt><dd>{detail.attacker.predicted_cve ?? "Unavailable"}</dd></div>
          <div><dt>Response status</dt><dd>{attackerStatusLabel(detail.attacker.status)}</dd></div>
          <div><dt>Relationship</dt><dd>{formatRelationship(detail.relationship_tier)}</dd></div>
        </dl>
        <h4>Model reasoning</h4>
        <p>{detail.attacker.reasoning ?? "No reasoning was returned."}</p>
        <h4>Model clues</h4>
        {detail.attacker.clues.length ? (
          <ul className="clues">
            {detail.attacker.clues.map((clue, index) => <li key={`${clue}-${index}`}>{clue}</li>)}
          </ul>
        ) : <p className="muted">No clues were returned.</p>}
        {!combinationMode && (
          <>
            <details>
              <summary>Full attacker prompt</summary>
              <pre className="payload">{detail.attacker.prompt ?? "Not recorded."}</pre>
            </details>
            <details>
              <summary>Raw model response</summary>
              <pre className="payload">{detail.attacker.raw_response ?? "Not recorded."}</pre>
            </details>
          </>
        )}
      </section>

      {!combinationMode && detail.diagnostics.length > 0 && (
        <details className="diagnostics">
          <summary>Run diagnostics ({detail.diagnostics.length})</summary>
          <pre className="payload">{JSON.stringify(detail.diagnostics, null, 2)}</pre>
        </details>
      )}
    </article>
  );
}
