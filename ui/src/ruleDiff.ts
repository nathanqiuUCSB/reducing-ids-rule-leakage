export type RuleDiffPart = {
  kind: "unchanged" | "added" | "removed";
  section: "header" | "option" | "rule";
  text: string;
};

type ParsedRule = {
  header: string;
  options: string[];
};

function parseRule(rule: string): ParsedRule | null {
  const open = rule.indexOf("(");
  const close = rule.lastIndexOf(")");
  if (open < 0 || close <= open) return null;

  const options: string[] = [];
  let current = "";
  let quoted = false;
  let escaped = false;
  for (const character of rule.slice(open + 1, close)) {
    current += character;
    if (escaped) {
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
    } else if (character === '"') {
      quoted = !quoted;
    } else if (character === ";" && !quoted) {
      const option = current.trim();
      if (option) options.push(option);
      current = "";
    }
  }
  if (current.trim()) options.push(current.trim());
  return { header: rule.slice(0, open).trim(), options };
}

function diffSequence(
  before: string[],
  after: string[],
  section: RuleDiffPart["section"],
): RuleDiffPart[] {
  const lengths = Array.from(
    { length: before.length + 1 },
    () => Array<number>(after.length + 1).fill(0),
  );
  for (let left = before.length - 1; left >= 0; left -= 1) {
    for (let right = after.length - 1; right >= 0; right -= 1) {
      lengths[left][right] = before[left] === after[right]
        ? lengths[left + 1][right + 1] + 1
        : Math.max(lengths[left + 1][right], lengths[left][right + 1]);
    }
  }

  const parts: RuleDiffPart[] = [];
  let left = 0;
  let right = 0;
  while (left < before.length || right < after.length) {
    if (left < before.length && right < after.length && before[left] === after[right]) {
      parts.push({ kind: "unchanged", section, text: before[left] });
      left += 1;
      right += 1;
    } else if (
      right < after.length
      && (left === before.length || lengths[left][right + 1] > lengths[left + 1][right])
    ) {
      parts.push({ kind: "added", section, text: after[right] });
      right += 1;
    } else {
      parts.push({ kind: "removed", section, text: before[left] });
      left += 1;
    }
  }
  return parts;
}

export function diffRules(before: string, after: string): RuleDiffPart[] {
  if (before === after) {
    return before ? [{ kind: "unchanged", section: "rule", text: before }] : [];
  }
  const previous = parseRule(before);
  const next = parseRule(after);
  if (!previous || !next) {
    return [
      ...(before ? [{ kind: "removed" as const, section: "rule" as const, text: before }] : []),
      ...(after ? [{ kind: "added" as const, section: "rule" as const, text: after }] : []),
    ];
  }

  return [
    ...diffSequence([previous.header], [next.header], "header"),
    ...diffSequence(previous.options, next.options, "option"),
  ];
}
