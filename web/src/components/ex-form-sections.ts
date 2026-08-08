import type { ExFormItem } from "@/components/ex-form";

/**
 * Stable-sorts `items` into `order` so each section renders as one block, and
 * returns a `defaultShow` covering `defaultSections`.
 *
 * Sorting instead of reordering the literals keeps every field where its author
 * put it inside its group, and lets conditionally pushed fields join the right
 * section without splicing. Deriving `defaultShow` matters because ExForm cuts
 * the list at a raw index — a hardcoded number silently starts slicing a
 * section in half as soon as any field is added.
 */
export function sortIntoSections(
  items: ExFormItem[],
  order: string[],
  defaultSections: string[],
): number {
  items.sort(
    (a, b) => order.indexOf(a.section ?? "") - order.indexOf(b.section ?? ""),
  );
  return items.filter((item) => defaultSections.includes(item.section ?? ""))
    .length;
}
