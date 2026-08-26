import type {
  AttackerDetailStatus,
  CombinationAttribution,
  CombinationBuildingBlock,
  CombinationJoinDiagnostic,
} from "./mutationApi";
import {
  formatFamilyLabel,
  formatMutationLabel,
  formatRate,
  formatRelationship,
  formatSourceBlockLabel,
} from "./mutationLabels";
import { RuleDiff } from "./RuleDiff";

const ATTACKER_STATUS_LABELS: Record<AttackerDetailStatus, string> = {
  success: "Successful response",
  provider: "Provider failure",
  parse: "Parse failure",
  empty_response: "Empty response failure",
  empty_prediction: "Empty prediction failure",
  validation: "Attacker not run",
};

function attributionLabel(value: CombinationAttribution): string {
  return value === "hit"
    ? "Hit"
    : value === "miss" ? "Miss" : "Unmeasured";
}

function parameterValue(value: unknown): string {
  if (value == null || value === "") return "Unavailable";
  if (Array.isArray(value)) return value.map(parameterValue).join(", ");
  if (typeof value === "object") return "Structured value";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function AvailableBuildingBlock({
  block,
  position,
}: {
  block: Extract<CombinationBuildingBlock, { join_status: "available" }>;
  position: number;
}) {
  const attackerAvailable = block.attacker.status === "success";
  return (
    <article className="building-block-card">
      <header>
        <div>
          <p className="building-block-position">Source {position}</p>
          <h4>{formatSourceBlockLabel(block)}</h4>
          <p>{block.description}</p>
        </div>
        <span className="pill neutral">{formatMutationLabel(block.mutation_category)}</span>
      </header>
      <code className="building-block-id">{block.candidate_id}</code>
      <dl className="building-block-summary">
        <div><dt>Positive recall</dt><dd>{formatRate(block.positive_recall)}</dd></div>
        <div>
          <dt>Synthetic false-positive rate</dt>
          <dd>{formatRate(block.negative_false_positive_rate)}</dd>
        </div>
        <div>
          <dt>Benign false-positive rate</dt>
          <dd>{formatRate(block.benign_false_positive_rate)}</dd>
        </div>
        <div><dt>Buffer</dt><dd>{block.buffer ?? "None"}</dd></div>
        <div><dt>Attacker status</dt><dd>{ATTACKER_STATUS_LABELS[block.attacker.status]}</dd></div>
        <div><dt>Attacker guess</dt><dd>{block.attacker.predicted_cve ?? "Unavailable"}</dd></div>
        <div>
          <dt>Exact attribution</dt>
          <dd>{attackerAvailable ? attributionLabel(block.exact_attribution) : "Unavailable"}</dd>
        </div>
        <div>
          <dt>Effective attribution</dt>
          <dd>{attackerAvailable ? attributionLabel(block.effective_attribution) : "Unavailable"}</dd>
        </div>
        <div><dt>Relationship</dt><dd>{formatRelationship(block.relationship_tier)}</dd></div>
      </dl>
      {!attackerAvailable && (
        <p className="source-unavailable" role="status">
          <strong>Attribution unavailable</strong> — the source attacker result ended with{" "}
          {ATTACKER_STATUS_LABELS[block.attacker.status].toLowerCase()}.
          {block.attacker.error ? ` ${block.attacker.error}` : ""}
        </p>
      )}
      {Object.keys(block.params).length > 0 && (
        <dl className="building-block-params">
          {Object.entries(block.params).map(([name, value]) => (
            <div key={name}>
              <dt>{formatMutationLabel(name)}</dt>
              <dd>{parameterValue(value)}</dd>
            </div>
          ))}
        </dl>
      )}
      {block.baseline_rule && block.mutated_rule ? (
        <RuleDiff
          before={block.baseline_rule}
          after={block.mutated_rule}
          label="Rule diff: baseline → single mutation"
        />
      ) : (
        <p className="muted">Baseline-to-single rule diff unavailable.</p>
      )}
    </article>
  );
}

export function CombinationBuildingBlocks({
  blocks,
  diagnostics = [],
}: {
  blocks: CombinationBuildingBlock[];
  diagnostics?: CombinationJoinDiagnostic[];
}) {
  return (
    <section className="detail-section combination-building-blocks" aria-labelledby="source-blocks-title">
      <h3 id="source-blocks-title">Source building blocks</h3>
      <p className="muted">
        Ordered baseline-relative mutations used to construct this combination.
      </p>
      {diagnostics.length > 0 && (
        <div className="source-join-warning" role="status">
          <strong>Some source evidence is unavailable.</strong>
          <ul>
            {diagnostics.map((diagnostic, index) => (
              <li key={`${diagnostic.source_candidate_id ?? "run"}-${index}`}>
                {diagnostic.source_candidate_id && <code>{diagnostic.source_candidate_id}: </code>}
                {diagnostic.error}
              </li>
            ))}
          </ul>
        </div>
      )}
      {blocks.length > 0 ? (
        <ol className="building-block-list">
          {blocks.map((block, index) => (
            <li key={`${block.candidate_id}-${index}`}>
              {block.join_status === "available" ? (
                <AvailableBuildingBlock block={block} position={index + 1} />
              ) : (
                <article className="building-block-card unavailable">
                  <p className="building-block-position">Source {index + 1}</p>
                  <h4>{formatSourceBlockLabel(block)}</h4>
                  <code className="building-block-id">{block.candidate_id}</code>
                  <p className="source-unavailable" role="status">
                    <strong>Source evidence unavailable.</strong> The source record could not be joined,
                    so mutation, attacker, attribution, and rule-diff evidence cannot be shown.
                  </p>
                </article>
              )}
            </li>
          ))}
        </ol>
      ) : (
        <p className="source-unavailable" role="status">
          Source building-block evidence is unavailable for this combination.
        </p>
      )}
    </section>
  );
}
