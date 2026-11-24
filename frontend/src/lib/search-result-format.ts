import type { PlatformFieldConfig } from "./search-api";

export interface ResultFieldEntry {
  key: string;
  label: string;
  value: string;
  isWide: boolean;
  isMatched: boolean;
}

const WIDE_FIELD_KEY_PATTERN =
  /^(description|content|body|summary|bio|biography|profile_text|experience_summary|requirements|responsibilities|excerpt|notes)$/i;

const ACRONYM_TOKENS = new Set([
  "id",
  "url",
  "api",
  "sql",
  "ai",
  "ml",
  "b2b",
  "rrf",
  "bm25f",
]);

/**
 * Resolve a clear human-readable field label from engine config metadata or field key.
 */
export function formatFieldLabel(
  fieldKey: string,
  fieldConfig?: PlatformFieldConfig,
): string {
  const configuredLabel = fieldConfig?.label?.trim();
  if (configuredLabel) return configuredLabel;

  const spaced = fieldKey
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  if (!spaced) return fieldKey;

  return spaced
    .split(" ")
    .map((word) => {
      const lower = word.toLowerCase();
      if (ACRONYM_TOKENS.has(lower)) return lower.toUpperCase();
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(" ");
}

/**
 * Clean HTML tags, common HTML entities, and excessive whitespace from any field value.
 */
export function cleanFieldValue(value: unknown, maxLength = 340): string {
  if (value === null || value === undefined) return "";
  const cleaned = String(value)
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();

  if (!cleaned) return "";
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}…` : cleaned;
}

/**
 * Determine whether a field should span full card width for comfortable reading.
 */
export function isWideField(
  fieldKey: string,
  cleanedValue: string,
  fieldConfig?: PlatformFieldConfig,
): boolean {
  if (fieldConfig?.role === "description") return true;
  if (WIDE_FIELD_KEY_PATTERN.test(fieldKey.trim())) return true;
  return cleanedValue.length > 110;
}

/**
 * Convert an engine search result's fields record into structured, well-labelled entries
 * consistently across all configured search engines.
 */
export function buildResultFieldEntries(
  fields: Record<string, string | number | boolean | null>,
  configuredFields?: PlatformFieldConfig[],
  matchedFields?: string[],
): ResultFieldEntry[] {
  const configByKey = new Map<string, PlatformFieldConfig>();
  for (const field of configuredFields ?? []) {
    configByKey.set(field.key, field);
  }
  const matchedSet = new Set(matchedFields ?? []);

  const entries: ResultFieldEntry[] = [];
  for (const [key, rawValue] of Object.entries(fields || {})) {
    const cleaned = cleanFieldValue(rawValue);
    if (!cleaned) continue;
    const cfg = configByKey.get(key);
    entries.push({
      key,
      label: formatFieldLabel(key, cfg),
      value: cleaned,
      isWide: isWideField(key, cleaned, cfg),
      isMatched: matchedSet.has(key),
    });
  }
  return entries;
}
