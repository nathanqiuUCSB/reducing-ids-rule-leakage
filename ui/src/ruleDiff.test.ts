import { describe, expect, it } from "vitest";
import { diffRules } from "./ruleDiff";

describe("diffRules", () => {
  it("highlights inserted and removed Suricata options", () => {
    const before = 'alert http any any -> any any (content:"old"; sid:1; rev:1;)';
    const after = 'alert http any any -> any any (flow:established; content:"new"; sid:1; rev:2;)';

    const diff = diffRules(before, after);

    expect(diff.filter((part) => part.kind === "removed").map((part) => part.text))
      .toEqual(['content:"old";', "rev:1;"]);
    expect(diff.filter((part) => part.kind === "added").map((part) => part.text))
      .toEqual(["flow:established;", 'content:"new";', "rev:2;"]);
    expect(diff.filter((part) => part.kind === "unchanged").map((part) => part.text))
      .toContain("sid:1;");
  });

  it("does not split semicolons inside quoted content", () => {
    const before = 'alert tcp any any -> any any (content:"a;b"; sid:7;)';
    const after = 'alert tcp any any -> any any (content:"a;b;c"; sid:7;)';

    const diff = diffRules(before, after);

    expect(diff.filter((part) => part.kind === "removed").map((part) => part.text))
      .toEqual(['content:"a;b";']);
    expect(diff.filter((part) => part.kind === "added").map((part) => part.text))
      .toEqual(['content:"a;b;c";']);
  });

  it("returns a safe line-oriented diff for malformed rules", () => {
    expect(diffRules("not a complete rule", "still not a rule")).toEqual([
      { kind: "removed", section: "rule", text: "not a complete rule" },
      { kind: "added", section: "rule", text: "still not a rule" },
    ]);
  });
});
