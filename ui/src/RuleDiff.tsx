import { diffRules } from "./ruleDiff";

export type RuleDiffProps = {
  before: string;
  after: string;
  label: string;
  open?: boolean;
};

export function RuleDiff({ before, after, label, open = false }: RuleDiffProps) {
  const parts = diffRules(before, after);
  return (
    <details className="rule-diff" open={open}>
      <summary>{label}</summary>
      <div className="diff-legend">
        <span className="removed">Removed</span>
        <span className="added">Inserted</span>
      </div>
      <div className="diff-parts">
        {parts.length > 0
          ? parts.map((part, index) => (
              <code key={`${part.kind}-${index}`} className={`diff-part ${part.kind}`}>
                <span aria-hidden="true">
                  {part.kind === "added" ? "+" : part.kind === "removed" ? "−" : " "}
                </span>
                {part.text}
              </code>
            ))
          : <span className="muted">Rules are identical.</span>}
      </div>
    </details>
  );
}
