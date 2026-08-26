"""Predicate-linked targeted mutation generation.

Two things happen here.  Every candidate the locked generic matrix already
produces is mapped onto the canonical predicates it touches and, through them,
onto the reviewed baseline clues it can disturb.  Reviewed declarative recipes
then invoke reusable family operators to reach the clues the generic matrix
covers weakly or not at all.

Recipes never carry rule text.  They name a canonical predicate, an operator,
and the operator's arguments, and the family renderer derives the mutated rule
from the parsed baseline.  Parser truth stays authoritative: if a recipe names
a boundary, token, or class the rule does not actually contain, generation
fails loudly rather than emitting an unverified rule.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Literal, Mapping, Protocol, Sequence

from hardening_game.attribution.clue_registry import BaselineRuleClues
from hardening_game.mutations.engine import (
    MutationCandidate,
    build_fixture_candidate,
    canonical_fingerprint,
    generate_generic_candidates,
)
from hardening_game.mutations.families import (
    byte_predicates,
    content as content_family,
    flowbits as flowbits_family,
    modifiers as modifier_family,
    pcre as pcre_family,
    ports as port_family,
    position as position_family,
)
from hardening_game.mutations.specifications import (
    MutationSpec,
    RejectedSpec,
    rejected_spec,
)
from hardening_game.mutations.taxonomy import (
    ANALYSIS_CATEGORIES,
    classify_mutation_category,
)
from hardening_game.predicates import (
    canonical_rule_predicates,
    canonical_touched_predicate_ids,
    resolve_predicate_ids,
)
from hardening_game.suricata.rule_model import ParsedRule, parse_suricata_rule


class TargetedOperator(Protocol):
    """The call shape every clue-targeted family renderer implements."""

    def __call__(
        self,
        rule: ParsedRule,
        params: Mapping[str, object],
        *,
        fixture_name: str,
    ) -> MutationSpec | RejectedSpec: ...


# A recipe may also declare a reviewed refusal.  It produces a rejection record
# rather than a rule, which is how a major clue with no safe operator stays
# visible in the manifest instead of silently disappearing.
REVIEW_REJECTION = "review/rejected"

# A recipe may instead record that a clue is deliberately left at one level.
# It produces neither a candidate nor a rejection, only a note on the clue's
# coverage, so that "one candidate" is a reviewed decision rather than an
# unexplained gap.
REVIEW_SINGLE_LEVEL = "review/single_level"

REVIEW_OPERATORS = (REVIEW_REJECTION, REVIEW_SINGLE_LEVEL)

TARGETED_OPERATORS: dict[str, TargetedOperator] = {
    **byte_predicates.TARGETED_OPERATORS,
    **content_family.TARGETED_OPERATORS,
    **flowbits_family.TARGETED_OPERATORS,
    **modifier_family.TARGETED_OPERATORS,
    **pcre_family.TARGETED_OPERATORS,
    **port_family.TARGETED_OPERATORS,
    **position_family.TARGETED_OPERATORS,
}

_SUPPORTED_VERSION = 1
_RECIPE_FIELDS = {
    "recipe_id",
    "fixture",
    "clue_ids",
    "target_predicate_ids",
    "operator",
    "params",
    "category",
    "rationale",
}
# A semantic reduction may legitimately make the rule fire on a synthetic
# negative that probes the very clue it removed.  That effect has to be declared
# per recipe so the negative sweep asserts an exact expected set rather than
# tolerating any regression.
_OPTIONAL_RECIPE_FIELDS = {
    "expected_negative_firings",
    "match_set_effect",
    "match_set_effect_rationale",
}

# What one candidate does to the set of packets its rule matches, and how well
# that is evidenced.  The analysis category answers "is this edit semantic"; this
# answers the two different questions "can this edit be observed in traffic at
# all" and "has it been".  Nothing here is a default: every value is either
# derived from committed evidence or declared with a reviewed reason.
#   observed_widening            a committed negative capture in the fixture's
#                                own suite fires on this rule and not on the
#                                baseline, so the widening is demonstrated
#   logical_widening_unobserved  the operator can only broaden, but no committed
#                                capture demonstrates a difference; the claim is
#                                about the edit, not about measured behaviour
#   state_side_effect_only       the edit removes a state side effect, such as a
#                                flowbits set; the rule matches the same packets
#   pinned_by_sibling_predicate  the relaxed material is independently required
#                                by another option of the same rule, so the
#                                combined match set is unchanged
#   representation_preserving    a representation edit; the rule text changes and
#                                the match set does not
MATCH_SET_EFFECTS = (
    "observed_widening",
    "logical_widening_unobserved",
    "state_side_effect_only",
    "pinned_by_sibling_predicate",
    "representation_preserving",
)

# A recipe may only declare the two effects that no capture could ever show,
# because they are claims about the rule's structure.  Widening is never
# declared: it is derived from whether a committed capture demonstrates it.
DECLARABLE_MATCH_SET_EFFECTS = (
    "state_side_effect_only",
    "pinned_by_sibling_predicate",
)

# Headline evidence tier for a clue, aggregated over its covering candidates.
MATCH_SET_EVIDENCE = ("observed", "logical_only", "preserving")
_TOP_LEVEL_FIELDS = {"version", "recipes"}
_RECIPE_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_MINIMUM_RATIONALE = 60
_UNFILLED = ("tbd", "todo", "fixme", "to be decided", "placeholder text", "xxx")
_REJECTION_REASONS = {"structural", "unsupported", "suricata_preflight"}

# Params a recipe may never supply.  Some of these carry candidate identity or
# provenance and are injected by this module; the rest are parser truth that the
# family renderer derives from the rule.  Letting a recipe set any of them would
# let the reviewed file, rather than the parser, decide what an edit touched.
_RESERVED_PARAM_KEYS = frozenset(
    {
        "buffer",
        "clue_ids",
        "compensation",
        "component",
        "content_index",
        "direction",
        "operation",
        "operator",
        "option_index",
        "option_indexes",
        "predicate_id",
        "predicate_ids",
        "rationale",
        "recipe_id",
    }
)


@dataclass(frozen=True)
class ClueTargetRecipe:
    recipe_id: str
    fixture: str
    clue_ids: tuple[str, ...]
    target_predicate_ids: tuple[str, ...]
    operator: str
    params: dict[str, object]
    category: str
    rationale: str
    expected_negative_firings: tuple[str, ...] = ()
    match_set_effect: str | None = None
    match_set_effect_rationale: str = ""


@dataclass(frozen=True)
class ClueTargetRecipeSet:
    version: int
    recipes: tuple[ClueTargetRecipe, ...]


@dataclass(frozen=True)
class MappedCandidate:
    """One candidate with the clue evidence it is expected to disturb."""

    candidate: MutationCandidate
    status: Literal["existing", "new"]
    category: str
    clue_ids: tuple[str, ...]
    clue_ranks: tuple[int | None, ...]
    touched_predicate_ids: tuple[str, ...]
    rationale: str
    compensation: tuple[Mapping[str, object], ...] = ()
    recipe_id: str | None = None
    # Always derived by `derive_match_set_effect`; never defaulted, so a generic
    # candidate cannot inherit a widening claim it has no evidence for.
    match_set_effect: str = "logical_widening_unobserved"


# How strongly a clue is actually reachable, so that a count of "covered" clues
# never implies that every one of them can be weakened.
#   semantic            at least one edit removes or broadens the clue itself
#   representation_only every edit preserves the matched bytes exactly
#   rejected_semantic   representation only, and a reviewed rejection records
#                       why no semantic reduction of this clue is safe
#   uncovered           no candidate touches the clue at all
CoverageStrength = Literal[
    "semantic", "representation_only", "rejected_semantic", "uncovered"
]
COVERAGE_STRENGTHS: tuple[CoverageStrength, ...] = (
    "semantic",
    "representation_only",
    "rejected_semantic",
    "uncovered",
)


@dataclass(frozen=True)
class ReviewedRejection:
    """A rejection that a reviewed recipe asked for and explained.

    `provenance` distinguishes the two ways a reviewed rejection can arise, which
    carry very different weight:

    - `operator_derived` — a real operator was run against the real rule and
      refused; `diagnostic` is the operator's own account of what blocked it.
    - `hand_reviewed_refusal` — the reviewer declined to run any operator, and
      `diagnostic` is a human judgement about the rule, not a machine finding.
    """

    recipe_id: str
    rejection_id: str
    clue_ids: tuple[str, ...]
    predicate_ids: tuple[str, ...]
    reason: str
    diagnostic: str
    rationale: str
    provenance: str = "operator_derived"


REJECTION_PROVENANCES = ("operator_derived", "hand_reviewed_refusal")


@dataclass(frozen=True)
class ReviewNote:
    """A reviewed statement about a clue that produces no rule of its own."""

    recipe_id: str
    kind: str
    clue_ids: tuple[str, ...]
    predicate_ids: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class ClueCoverage:
    clue_id: str
    rank: int | None
    predicate_ids: tuple[str, ...]
    candidate_ids: tuple[str, ...]
    rejection_ids: tuple[str, ...]
    coverage_strength: CoverageStrength
    # Every distinct `MATCH_SET_EFFECTS` value among the candidates covering this
    # clue, sorted.  Reported in full rather than collapsed, so a clue that mixes
    # an observed reduction with a provably inert one says exactly that.
    match_set_effects: tuple[str, ...] = ()
    # Headline evidence tier: `observed` when at least one covering candidate has
    # a committed capture behind it, `logical_only` when the strongest claim is
    # about the edit rather than measured behaviour, `preserving` when no
    # covering candidate can change the match set, `None` when uncovered.
    match_set_evidence: str | None = None
    semantic_candidate_ids: tuple[str, ...] = ()
    representation_candidate_ids: tuple[str, ...] = ()
    reviewed_rejection_ids: tuple[str, ...] = ()
    single_level: bool = False
    review_notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClueTargetedManifest:
    fixture: str
    candidates: tuple[MappedCandidate, ...]
    rejections: tuple[RejectedSpec, ...]
    coverage: tuple[ClueCoverage, ...]
    duplicate_recipe_ids: tuple[str, ...] = field(default=())
    reviewed_rejections: tuple[ReviewedRejection, ...] = field(default=())
    review_notes: tuple[ReviewNote, ...] = field(default=())


# ---------------------------------------------------------------------------
# Recipe loading
# ---------------------------------------------------------------------------


def _text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _id_list(value: object, *, field_name: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise ValueError(f"{field_name} must be a non-empty array of identifiers")
    items = tuple(item.strip() for item in value)
    if len(set(items)) != len(items):
        raise ValueError(f"{field_name} contains duplicate identifiers")
    return items


def _optional_id_list(value: object, *, field_name: str) -> tuple[str, ...]:
    if value == []:
        return ()
    return _id_list(value, field_name=field_name)


def _rationale(value: object, *, recipe_id: str) -> str:
    text = _text(value, field_name="rationale")
    lowered = text.casefold()
    if len(text) < _MINIMUM_RATIONALE:
        raise ValueError(
            f"recipe {recipe_id} rationale must explain the targeted clue in at "
            f"least {_MINIMUM_RATIONALE} characters"
        )
    if not text.endswith("."):
        raise ValueError(f"recipe {recipe_id} rationale must end in a full stop")
    if any(marker in lowered for marker in _UNFILLED):
        raise ValueError(f"recipe {recipe_id} rationale contains unfilled text")
    return text


def _parse_recipe(value: object) -> ClueTargetRecipe:
    if not isinstance(value, dict):
        raise ValueError("recipe must be an object")
    missing_fields = _RECIPE_FIELDS - set(value)
    extra_fields = set(value) - _RECIPE_FIELDS - _OPTIONAL_RECIPE_FIELDS
    if missing_fields or extra_fields:
        raise ValueError(
            "recipe must contain exactly: "
            + ", ".join(sorted(_RECIPE_FIELDS))
            + " and optionally: "
            + ", ".join(sorted(_OPTIONAL_RECIPE_FIELDS))
        )
    recipe_id = _text(value["recipe_id"], field_name="recipe_id")
    if not _RECIPE_ID.fullmatch(recipe_id):
        raise ValueError(f"invalid recipe_id: {recipe_id!r}")
    operator = _text(value["operator"], field_name="operator")
    if operator not in REVIEW_OPERATORS and operator not in TARGETED_OPERATORS:
        raise ValueError(f"unknown targeted operator: {operator!r}")
    params = value["params"]
    if not isinstance(params, dict) or any(
        not isinstance(key, str) for key in params
    ):
        raise ValueError(f"recipe {recipe_id} params must be a string-keyed object")
    reserved = sorted(set(params) & _RESERVED_PARAM_KEYS)
    if reserved:
        raise ValueError(
            f"recipe {recipe_id} may not supply reserved params: "
            + ", ".join(reserved)
        )
    category = _text(value["category"], field_name="category")
    if category not in ANALYSIS_CATEGORIES:
        raise ValueError(
            f"recipe {recipe_id} category must be one of: "
            + ", ".join(ANALYSIS_CATEGORIES)
        )
    expected_negatives = _optional_id_list(
        value.get("expected_negative_firings", []),
        field_name=f"recipe {recipe_id} expected_negative_firings",
    )
    if operator == REVIEW_REJECTION:
        if params.get("reason") not in _REJECTION_REASONS:
            raise ValueError(
                f"recipe {recipe_id} reviewed rejection needs a reason in: "
                + ", ".join(sorted(_REJECTION_REASONS))
            )
        _text(params.get("diagnostic"), field_name="diagnostic")
    elif operator == REVIEW_SINGLE_LEVEL:
        if params:
            raise ValueError(
                f"recipe {recipe_id} single-level note takes no params; its "
                "rationale carries the review"
            )
    else:
        component, _, name = operator.partition("/")
        declared = classify_mutation_category(
            component=component, operator=name, params=dict(params)
        )
        if declared != category:
            raise ValueError(
                f"recipe {recipe_id} declares category {category!r} but "
                f"{operator} is classified as {declared!r}"
            )
    if expected_negatives and (
        operator in REVIEW_OPERATORS or category != "semantic"
    ):
        raise ValueError(
            f"recipe {recipe_id} declares expected negative firings, which only "
            "a semantic reduction may do"
        )
    effect = value.get("match_set_effect")
    if effect is not None and effect not in DECLARABLE_MATCH_SET_EFFECTS:
        raise ValueError(
            f"recipe {recipe_id} match_set_effect must be one of: "
            + ", ".join(DECLARABLE_MATCH_SET_EFFECTS)
            + "; widening is derived from committed evidence, never declared"
        )
    effect_rationale = value.get("match_set_effect_rationale", "")
    if effect is not None:
        if category != "semantic" or operator in REVIEW_OPERATORS:
            raise ValueError(
                f"recipe {recipe_id} may only claim a match-set-preserving "
                "effect for a semantic edit that generates a rule"
            )
        if expected_negatives:
            raise ValueError(
                f"recipe {recipe_id} claims its match set cannot widen but also "
                "declares negative firings"
            )
        effect_rationale = _rationale(effect_rationale, recipe_id=recipe_id)
    elif effect_rationale:
        raise ValueError(
            f"recipe {recipe_id} supplies a match_set_effect_rationale without "
            "claiming a match-set-preserving effect"
        )
    return ClueTargetRecipe(
        recipe_id=recipe_id,
        fixture=_text(value["fixture"], field_name="fixture"),
        clue_ids=_id_list(value["clue_ids"], field_name="clue_ids"),
        target_predicate_ids=_id_list(
            value["target_predicate_ids"], field_name="target_predicate_ids"
        ),
        operator=operator,
        params=dict(params),
        category=category,
        rationale=_rationale(value["rationale"], recipe_id=recipe_id),
        expected_negative_firings=expected_negatives,
        match_set_effect=effect,
        match_set_effect_rationale=effect_rationale,
    )


def load_clue_target_recipes(path: Path) -> ClueTargetRecipeSet:
    """Load the reviewed recipe file, failing closed on anything unexpected."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path} is not valid JSON: {error}") from error
    if not isinstance(data, dict) or set(data) != _TOP_LEVEL_FIELDS:
        raise ValueError(
            "recipe file must contain exactly: " + ", ".join(sorted(_TOP_LEVEL_FIELDS))
        )
    version = data["version"]
    if isinstance(version, bool) or version != _SUPPORTED_VERSION:
        raise ValueError(f"unsupported recipe version: {version!r}")
    raw = data["recipes"]
    if not isinstance(raw, list) or not raw:
        raise ValueError("recipes must be a non-empty array")
    recipes = tuple(_parse_recipe(item) for item in raw)
    seen: set[str] = set()
    for recipe in recipes:
        if recipe.recipe_id in seen:
            raise ValueError(f"duplicate recipe_id: {recipe.recipe_id}")
        seen.add(recipe.recipe_id)
    ordering = [(recipe.fixture, recipe.recipe_id) for recipe in recipes]
    if ordering != sorted(ordering):
        raise ValueError("recipes must be sorted by fixture then recipe_id")
    return ClueTargetRecipeSet(version=version, recipes=recipes)


def recipes_sha256(recipes: ClueTargetRecipeSet) -> str:
    """Hash canonical recipe content, independent of JSON whitespace."""
    canonical = json.dumps(
        asdict(recipes), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def recipes_for_fixture(
    recipes: ClueTargetRecipeSet, fixture: str
) -> tuple[ClueTargetRecipe, ...]:
    return tuple(recipe for recipe in recipes.recipes if recipe.fixture == fixture)


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------


def _clue_links(
    touched: Sequence[str], rule_clues: BaselineRuleClues
) -> tuple[tuple[str, ...], tuple[int | None, ...]]:
    touched_set = set(touched)
    linked = [
        clue
        for clue in rule_clues.clues
        if touched_set & set(clue.predicate_ids)
    ]
    linked.sort(key=lambda clue: (clue.rank is None, clue.rank or 0, clue.clue_id))
    return (
        tuple(clue.clue_id for clue in linked),
        tuple(clue.rank for clue in linked),
    )


def _compensation_records(
    params: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    compensation = params.get("compensation")
    if compensation is None:
        return ()
    if isinstance(compensation, Mapping):
        return (compensation,)
    if isinstance(compensation, (list, tuple)):
        return tuple(compensation)
    raise ValueError("mutation compensation must be an object or an array of objects")


def map_existing_candidates(
    candidates: Sequence[MutationCandidate],
    *,
    parsed: ParsedRule,
    rule_clues: BaselineRuleClues,
) -> tuple[MappedCandidate, ...]:
    """Link every already-generated candidate to canonical predicates and clues."""
    known = canonical_rule_predicates(parsed)
    mapped: list[MappedCandidate] = []
    for candidate in candidates:
        touched = canonical_touched_predicate_ids(
            candidate.params, known_predicate_ids=known
        )
        clue_ids, clue_ranks = _clue_links(touched, rule_clues)
        category = classify_mutation_category(
            component=candidate.component,
            operator=candidate.operator,
            params=dict(candidate.params),
        )
        mapped.append(
            MappedCandidate(
                candidate=candidate,
                status="existing",
                category=category,
                clue_ids=clue_ids,
                clue_ranks=clue_ranks,
                touched_predicate_ids=touched,
                rationale=candidate.description,
                compensation=_compensation_records(candidate.params),
                # A generic candidate has no recipe, so it declares nothing and
                # names no committed capture: its widening stays unobserved.
                match_set_effect=derive_match_set_effect(
                    category=category,
                    declared_effect=None,
                    expected_negative_firings=(),
                ),
            )
        )
    return tuple(mapped)


# ---------------------------------------------------------------------------
# Targeted generation
# ---------------------------------------------------------------------------


def _operator_params(recipe: ClueTargetRecipe) -> dict[str, object]:
    return {
        **recipe.params,
        "predicate_id": recipe.target_predicate_ids[0],
        "predicate_ids": list(recipe.target_predicate_ids),
    }


def _reviewed_rejection(recipe: ClueTargetRecipe) -> RejectedSpec:
    return rejected_spec(
        fixture_name=recipe.fixture,
        component="review",
        operator="rejected",
        params={
            "recipe_id": recipe.recipe_id,
            "predicate_ids": list(recipe.target_predicate_ids),
        },
        reason=str(recipe.params["reason"]),
        diagnostic=str(recipe.params["diagnostic"]),
    )


def build_clue_targeted_manifest(
    *,
    fixture_name: str,
    baseline_rule: str,
    revision: int,
    rule_clues: BaselineRuleClues,
    recipes: ClueTargetRecipeSet,
) -> ClueTargetedManifest:
    """Compose the locked generic matrix with reviewed clue-targeted candidates."""
    if rule_clues.rule_id != fixture_name:
        raise ValueError(
            f"clue registry entry {rule_clues.rule_id!r} does not describe "
            f"{fixture_name!r}"
        )
    parsed = parse_suricata_rule(baseline_rule)
    known = canonical_rule_predicates(parsed)
    generic = generate_generic_candidates(
        baseline_rule, revision=revision, fixture_name=fixture_name
    )
    mapped = list(
        map_existing_candidates(
            generic.accepted, parsed=parsed, rule_clues=rule_clues
        )
    )
    fingerprints = {record.candidate.fingerprint for record in mapped}
    baseline_fingerprint = canonical_fingerprint(baseline_rule)

    rejections: list[RejectedSpec] = list(generic.rejected)
    rejection_predicates: dict[str, tuple[str, ...]] = {
        rejection.id: _rejection_predicates(rejection, known)
        for rejection in generic.rejected
    }
    duplicates: list[str] = []
    reviewed_rejections: list[ReviewedRejection] = []
    review_notes: list[ReviewNote] = []
    next_revision = revision + len(generic.accepted)

    for recipe in recipes_for_fixture(recipes, fixture_name):
        declared = resolve_predicate_ids(
            recipe.target_predicate_ids, known_predicate_ids=known
        )
        if recipe.operator == REVIEW_SINGLE_LEVEL:
            review_notes.append(
                ReviewNote(
                    recipe_id=recipe.recipe_id,
                    kind="single_level",
                    clue_ids=recipe.clue_ids,
                    predicate_ids=declared,
                    rationale=recipe.rationale,
                )
            )
            continue
        if recipe.operator == REVIEW_REJECTION:
            rejection = _reviewed_rejection(recipe)
            rejections.append(rejection)
            rejection_predicates[rejection.id] = declared
            reviewed_rejections.append(
                # The reviewer refused to run an operator; the text is a human
                # judgement about the rule, not an operator's finding.
                _reviewed_record(
                    recipe,
                    rejection,
                    declared,
                    provenance="hand_reviewed_refusal",
                )
            )
            continue
        outcome = TARGETED_OPERATORS[recipe.operator](
            parsed, _operator_params(recipe), fixture_name=fixture_name
        )
        if isinstance(outcome, RejectedSpec):
            rejections.append(outcome)
            rejection_predicates[outcome.id] = declared
            reviewed_rejections.append(
                # A real operator ran against the real rule and refused, so the
                # diagnostic is the operator's own.
                _reviewed_record(
                    recipe, outcome, declared, provenance="operator_derived"
                )
            )
            continue
        if canonical_fingerprint(outcome.rule) == baseline_fingerprint:
            raise ValueError(
                f"recipe {recipe.recipe_id} produced the unchanged baseline rule"
            )
        params = {
            **outcome.params,
            "recipe_id": recipe.recipe_id,
            "clue_ids": list(recipe.clue_ids),
        }
        # Validate the recipe's claims before deduplication, so a recipe that
        # happens to reproduce an existing rule is still held to the same
        # predicate and clue truth as one that produces a new rule.
        touched = canonical_touched_predicate_ids(params, known_predicate_ids=known)
        missing = set(declared) - set(touched)
        if missing:
            raise ValueError(
                f"recipe {recipe.recipe_id} declares predicates its operator does "
                "not touch: " + ", ".join(sorted(missing))
            )
        clue_ids, clue_ranks = _clue_links(touched, rule_clues)
        undeclared = set(recipe.clue_ids) - set(clue_ids)
        if undeclared:
            raise ValueError(
                f"recipe {recipe.recipe_id} targets clues its edit does not reach: "
                + ", ".join(sorted(undeclared))
            )
        candidate = build_fixture_candidate(
            fixture_name=fixture_name,
            component=outcome.component,
            operator=outcome.operator,
            params=params,
            description=outcome.description,
            rule=outcome.rule,
            revision=next_revision,
        )
        if candidate.fingerprint in fingerprints:
            duplicates.append(recipe.recipe_id)
            continue
        fingerprints.add(candidate.fingerprint)
        next_revision += 1
        mapped.append(
            MappedCandidate(
                candidate=candidate,
                status="new",
                category=recipe.category,
                clue_ids=clue_ids,
                clue_ranks=clue_ranks,
                touched_predicate_ids=touched,
                rationale=recipe.rationale,
                compensation=_compensation_records(candidate.params),
                recipe_id=recipe.recipe_id,
                match_set_effect=derive_match_set_effect(
                    category=recipe.category,
                    declared_effect=recipe.match_set_effect,
                    expected_negative_firings=recipe.expected_negative_firings,
                ),
            )
        )

    reviewed_ids = {record.rejection_id for record in reviewed_rejections}
    coverage = tuple(
        _clue_coverage(
            clue,
            mapped=mapped,
            rejections=rejections,
            rejection_predicates=rejection_predicates,
            reviewed_rejection_ids=reviewed_ids,
            review_notes=review_notes,
        )
        for clue in rule_clues.clues
    )
    return ClueTargetedManifest(
        fixture=fixture_name,
        candidates=tuple(mapped),
        rejections=tuple(rejections),
        coverage=coverage,
        duplicate_recipe_ids=tuple(duplicates),
        reviewed_rejections=tuple(reviewed_rejections),
        review_notes=tuple(review_notes),
    )


def _reviewed_record(
    recipe: ClueTargetRecipe,
    rejection: RejectedSpec,
    declared: tuple[str, ...],
    *,
    provenance: str,
) -> ReviewedRejection:
    if provenance not in REJECTION_PROVENANCES:
        raise ValueError(f"unknown rejection provenance: {provenance!r}")
    return ReviewedRejection(
        recipe_id=recipe.recipe_id,
        rejection_id=rejection.id,
        clue_ids=recipe.clue_ids,
        predicate_ids=declared,
        reason=rejection.reason,
        diagnostic=rejection.diagnostic,
        rationale=recipe.rationale,
        provenance=provenance,
    )


def derive_match_set_effect(
    *,
    category: str,
    declared_effect: str | None,
    expected_negative_firings: Sequence[str],
) -> str:
    """Decide what one candidate does to the match set, from evidence alone.

    A representation edit preserves the match set by definition.  A semantic edit
    either carries a reviewed structural reason why its match set cannot move, or
    is a widening — and that widening is `observed` only when the recipe names
    committed negative captures that demonstrate it.  A candidate with no recipe,
    such as every generic matrix candidate, therefore never reaches `observed`.
    """
    if category != "semantic":
        return "representation_preserving"
    if declared_effect is not None:
        return declared_effect
    if expected_negative_firings:
        return "observed_widening"
    return "logical_widening_unobserved"


_PRESERVING_EFFECTS = frozenset(
    {
        "state_side_effect_only",
        "pinned_by_sibling_predicate",
        "representation_preserving",
    }
)


def _match_set_evidence(effects: Sequence[str]) -> str | None:
    """Aggregate one clue's candidate effects into a headline evidence tier."""
    if not effects:
        return None
    if "observed_widening" in effects:
        return "observed"
    if "logical_widening_unobserved" in effects:
        return "logical_only"
    return "preserving"


def _clue_coverage(
    clue,
    *,
    mapped: Sequence[MappedCandidate],
    rejections: Sequence[RejectedSpec],
    rejection_predicates: Mapping[str, tuple[str, ...]],
    reviewed_rejection_ids: set[str],
    review_notes: Sequence[ReviewNote],
) -> ClueCoverage:
    predicates = set(clue.predicate_ids)
    covering = [
        record
        for record in mapped
        if set(record.touched_predicate_ids) & predicates
    ]
    effects = tuple(sorted({record.match_set_effect for record in covering}))
    semantic = tuple(
        record.candidate.id for record in covering if record.category == "semantic"
    )
    representation = tuple(
        record.candidate.id
        for record in covering
        if record.category == "representation"
    )
    linked_rejections = tuple(
        rejection.id
        for rejection in rejections
        if set(rejection_predicates.get(rejection.id, ())) & predicates
    )
    reviewed = tuple(
        rejection_id
        for rejection_id in linked_rejections
        if rejection_id in reviewed_rejection_ids
    )
    if not covering:
        strength: CoverageStrength = "uncovered"
    elif semantic:
        strength = "semantic"
    elif reviewed:
        strength = "rejected_semantic"
    else:
        strength = "representation_only"
    notes = tuple(
        note.rationale
        for note in review_notes
        if clue.clue_id in note.clue_ids or set(note.predicate_ids) & predicates
    )
    return ClueCoverage(
        clue_id=clue.clue_id,
        rank=clue.rank,
        predicate_ids=clue.predicate_ids,
        candidate_ids=tuple(record.candidate.id for record in covering),
        rejection_ids=linked_rejections,
        coverage_strength=strength,
        match_set_effects=effects,
        match_set_evidence=_match_set_evidence(effects),
        semantic_candidate_ids=semantic,
        representation_candidate_ids=representation,
        reviewed_rejection_ids=reviewed,
        single_level=len(covering) == 1,
        review_notes=notes,
    )


def _rejection_predicates(
    rejection: RejectedSpec, known: Mapping[str, Mapping[str, object]]
) -> tuple[str, ...]:
    try:
        return canonical_touched_predicate_ids(
            rejection.params, known_predicate_ids=known
        )
    except ValueError:
        # A rejection may name an option this model refuses to describe further,
        # such as an unmodelled byte_jump; it then links to no clue.
        return ()
