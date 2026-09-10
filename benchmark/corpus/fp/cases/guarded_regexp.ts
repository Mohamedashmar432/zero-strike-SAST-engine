// Phase 3: a RegExp built from an admin-authored template field.
//
// `field` arrives as a function parameter, so its taint is seeding-only with
// no source behind it. A visitor filling in the form cannot reach this string.
const NESTED_QUANTIFIER = /(\+|\*|\{\d+,?\d*\})\s*(\+|\*|\{\d+,?\d*\})/;

export function fieldRules(field: { regex: string }) {
  if (!field.regex || NESTED_QUANTIFIER.test(field.regex)) {
    return {};
  }
  return { value: new RegExp(field.regex) };
}
