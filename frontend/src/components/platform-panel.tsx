import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import PlatformSearchResults from "./platform-search-results";
import {
  EngineRequestCoordinator,
  isAbortError,
  isSearchResultForActiveEngine,
  resolveCategoryAfterRefresh,
  resolveSelectedEngineRecord,
} from "../lib/engine-testing-state";
import {
  createPlatformCategory,
  discoverPlatformSourceSchema,
  suggestPlatformSourceMapping,
  previewPlatformJoinView,
  validatePlatformSource,
  getPlatformSourceProfiles,
  getPlatformCategories,
  getPlatformCategoryHistory,
  getPlatformFeedback,
  ingestPlatformDocuments,
  rollbackPlatformCategory,
  runPlatformAdminSearch,
  syncPlatformCategory,
  updatePlatformCategory,
  type PlatformCategoryConfig,
  type PlatformCategoryRecord,
  type PlatformCategoryHistoryItem,
  type PlatformFeedbackItem,
  type PlatformFeedbackSummary,
  type PlatformFieldConfig,
  type PlatformFieldRole,
  type PlatformSearchFilter,
  type PlatformSearchResponse,
  type PlatformSourceFilter,
  type PlatformSourceProfile,
  type PlatformSourceCatalog,
  type PlatformSourceMappingSuggestions,
  type PlatformSourceRelationship,
  type PlatformJoinViewPreview,
  type PlatformSourceValidation,
} from "../lib/search-api";

export type PlatformPanelMode = "all" | "engines" | "testing" | "feedback";

interface PlatformPanelProps {
  mode?: PlatformPanelMode;
  initialCategoryId?: string;
  openEditorNonce?: number;
  onSelectMode?: (mode: PlatformPanelMode, categoryId?: string) => void;
  onSelectedCategoryChange?: (categoryId: string) => void;
  onCategoriesUpdated?: (categories: PlatformCategoryRecord[]) => void;
}

const ROLE_OPTIONS: PlatformFieldRole[] = [
  "title",
  "skill",
  "location",
  "category",
  "description",
  "general",
];

const ROLE_LEXICAL_BOOSTS: Record<PlatformFieldRole, number> = {
  title: 2.6,
  skill: 2.2,
  category: 1.45,
  location: 1.25,
  description: 1.0,
  general: 1.0,
};

/**
 * Preserve exact backend model defaults when loading a saved category config.
 * Never substitute role-based UI suggestion defaults (such as filterable=true,
 * data_type="keyword", or query_filter_mode="preferred") for persisted fields.
 */
export function normalizeLoadedFieldConfig(
  field: PlatformFieldConfig,
): PlatformFieldConfig {
  return {
    ...field,
    aliases: [...(field.aliases || [])],
    filterable: field.filterable ?? false,
    data_type: field.data_type ?? "text",
    query_filter_mode: field.query_filter_mode ?? "none",
    query_match: field.query_match ?? "all",
  };
}

const INITIAL_FIELDS: PlatformFieldConfig[] = [
  {
    key: "full_name",
    source_column: "FullName",
    label: "Full Name",
    role: "title",
    weight: 4,
    searchable: true,
    semantic: false,
    aliases: ["name", "person"],
    filterable: false,
    data_type: "text",
    query_filter_mode: "none",
    query_match: "all",
  },
  {
    key: "profession",
    source_column: "Profession",
    label: "Profession",
    role: "category",
    weight: 4.5,
    searchable: true,
    semantic: true,
    aliases: ["profession", "occupation"],
    filterable: true,
    data_type: "keyword",
    query_filter_mode: "preferred",
    query_match: "any",
  },
  {
    key: "profile_text",
    source_column: "ProfileText",
    label: "Profile Text",
    role: "description",
    weight: 3,
    searchable: true,
    semantic: true,
    aliases: ["bio", "biography"],
    filterable: false,
    data_type: "text",
    query_filter_mode: "none",
    query_match: "all",
  },
  {
    key: "location",
    source_column: "Location",
    label: "Location",
    role: "location",
    weight: 2,
    searchable: true,
    semantic: false,
    aliases: ["city", "place", "location"],
    filterable: true,
    data_type: "keyword",
    query_filter_mode: "preferred",
    query_match: "any",
  },
];

const DEFAULT_RULES = {
  lexical_enabled: true,
  semantic_enabled: true,
  semantic_min_score: 20,
  semantic_high_confidence_score: 75,
  semantic_candidate_limit: 50,
  lexical_weight: 0.65,
  semantic_weight: 0.35,
};

function getError(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function parseSynonymGroups(value: string): Array<{ terms: string[] }> {
  return value
    .split(/\r?\n/)
    .map((line) => {
      const seen = new Set<string>();
      const terms: string[] = [];
      for (const raw of line.split(",")) {
        const cleaned = raw.trim().toLowerCase().replace(/\s+/g, " ");
        if (cleaned && !seen.has(cleaned)) {
          seen.add(cleaned);
          terms.push(cleaned);
        }
      }
      return terms;
    })
    .filter((terms) => terms.length >= 2)
    .map((terms) => ({ terms }));
}

export default function PlatformPanel({
  mode = "all",
  initialCategoryId,
  openEditorNonce = 0,
  onSelectMode,
  onSelectedCategoryChange,
  onCategoriesUpdated,
}: PlatformPanelProps) {
  const [categories, setCategories] = useState<PlatformCategoryRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [rollingBackVersion, setRollingBackVersion] = useState<number | null>(null);
  const [pendingRollbackItem, setPendingRollbackItem] =
    useState<PlatformCategoryHistoryItem | null>(null);
  const [rollbackReasonInput, setRollbackReasonInput] = useState("");
  const [syncing, setSyncing] = useState("");
  const [togglingStatus, setTogglingStatus] = useState("");
  const [ingesting, setIngesting] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [categoryId, setCategoryId] = useState("people");
  const [displayName, setDisplayName] = useState("People");
  const [description, setDescription] = useState("Search BONC people profiles");
  const [engineActive, setEngineActive] = useState(true);
  const [sourceType, setSourceType] = useState<"sqlserver" | "push">("sqlserver");
  const [connectionEnv, setConnectionEnv] = useState("");
  const [sourceProfiles, setSourceProfiles] = useState<PlatformSourceProfile[]>([]);
  const [sourceCatalog, setSourceCatalog] = useState<PlatformSourceCatalog | null>(null);
  const [discoveringSource, setDiscoveringSource] = useState(false);
  const [suggestingMapping, setSuggestingMapping] = useState(false);
  const [mappingSuggestions, setMappingSuggestions] =
    useState<PlatformSourceMappingSuggestions | null>(null);
  const [selectedJoinRelationships, setSelectedJoinRelationships] = useState<string[]>([]);
  const [viewSchema, setViewSchema] = useState("searchai");
  const [viewName, setViewName] = useState("vw_Search_People_v2");
  const [viewPreview, setViewPreview] = useState<PlatformJoinViewPreview | null>(null);
  const [previewingView, setPreviewingView] = useState(false);
  const [validatingSource, setValidatingSource] = useState(false);
  const [sourceValidation, setSourceValidation] =
    useState<PlatformSourceValidation | null>(null);
  const [schema, setSchema] = useState("searchai");
  const [table, setTable] = useState("vw_Search_People_v2");
  const [idColumn, setIdColumn] = useState("DocumentId");
  const [maxRecords, setMaxRecords] = useState(50000);
  const [sourceFilters, setSourceFilters] = useState<PlatformSourceFilter[]>([]);
  const [publicEnabled, setPublicEnabled] = useState(false);
  const [fields, setFields] = useState<PlatformFieldConfig[]>(INITIAL_FIELDS);
  const [synonymText, setSynonymText] = useState("");
  const [minScore, setMinScore] = useState(20);
  const [highConfidenceScore, setHighConfidenceScore] = useState(75);
  const [lexicalWeight, setLexicalWeight] = useState(0.65);
  const [semanticWeight, setSemanticWeight] = useState(0.35);
  const [lexicalEnabled, setLexicalEnabled] = useState(true);
  const [semanticEnabled, setSemanticEnabled] = useState(true);
  const [candidateLimit, setCandidateLimit] = useState(50);
  const [editingVersion, setEditingVersion] = useState<number | null>(null);
  const [showEditorForm, setShowEditorForm] = useState(false);

  const [selectedCategory, setSelectedCategory] = useState(initialCategoryId || "");
  const [rawDocuments, setRawDocuments] = useState(
    '[\n  {\n    "document_id": "person-1",\n    "title": "Sample Document",\n    "fields": { "full_name": "Sample Name", "profession": "Software Developer", "profile_text": "Python backend developer", "location": "Indore" }\n  }\n]',
  );
  const [categoryHistory, setCategoryHistory] = useState<PlatformCategoryHistoryItem[]>([]);
  const [feedbackSummary, setFeedbackSummary] = useState<PlatformFeedbackSummary | null>(null);
  const [allFeedbackByCategory, setAllFeedbackByCategory] = useState<
    Record<string, PlatformFeedbackSummary>
  >({});
  const [feedbackFilterCategory, setFeedbackFilterCategory] = useState<string>("all");
  const [feedbackFilterVerdict, setFeedbackFilterVerdict] = useState<
    "all" | "relevant" | "not_relevant"
  >("all");
  const [feedbackFilterQuery, setFeedbackFilterQuery] = useState("");
  const [changeReason, setChangeReason] = useState("");

  // Generic Search Engine Testing state (no inline feedback writing)
  const [query, setQuery] = useState("");
  const [searchFilters, setSearchFilters] = useState<PlatformSearchFilter[]>([]);
  const [searchResult, setSearchResult] = useState<PlatformSearchResponse | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchDurationMs, setSearchDurationMs] = useState<number | null>(null);
  const [testPage, setTestPage] = useState(1);
  const [testPageSize, setTestPageSize] = useState(10);
  const [showQueryPlanJson, setShowQueryPlanJson] = useState(false);
  const [expandedDocRawIds, setExpandedDocRawIds] = useState<Record<string, boolean>>({});

  // Engine selection refs & async request coordinators (prevent stale snap-back and request races)
  const selectedCategoryRef = useRef<string>(initialCategoryId || "");
  const initialCategoryIdRef = useRef<string | undefined>(initialCategoryId);
  initialCategoryIdRef.current = initialCategoryId;
  const prevInitialCategoryIdRef = useRef<string | undefined>(initialCategoryId);
  const userClearedSelectionRef = useRef<boolean>(false);
  const lastHandledEditorNonceRef = useRef<number>(0);
  const onCategoriesUpdatedRef = useRef(onCategoriesUpdated);
  onCategoriesUpdatedRef.current = onCategoriesUpdated;
  const onSelectedCategoryChangeRef = useRef(onSelectedCategoryChange);
  onSelectedCategoryChangeRef.current = onSelectedCategoryChange;

  const searchCoordinatorRef = useRef<EngineRequestCoordinator>(
    new EngineRequestCoordinator(initialCategoryId || ""),
  );
  const historyCoordinatorRef = useRef<EngineRequestCoordinator>(
    new EngineRequestCoordinator(initialCategoryId || ""),
  );
  const feedbackCoordinatorRef = useRef<EngineRequestCoordinator>(
    new EngineRequestCoordinator(initialCategoryId || ""),
  );
  const refreshRequestIdRef = useRef<number>(0);
  const refreshAbortRef = useRef<AbortController | null>(null);

  const loadHistory = useCallback(async (id: string) => {
    if (!id) {
      historyCoordinatorRef.current.invalidate();
      historyCoordinatorRef.current.setActiveCategory("");
      setCategoryHistory([]);
      return;
    }
    const token = historyCoordinatorRef.current.begin(id);
    try {
      const items = await getPlatformCategoryHistory(id, { signal: token.signal });
      if (!historyCoordinatorRef.current.isCurrent(token)) return;
      setCategoryHistory(items);
    } catch (e) {
      if (!historyCoordinatorRef.current.isCurrent(token) || isAbortError(e)) return;
      setCategoryHistory([]);
    }
  }, []);

  const loadFeedback = useCallback(async (id: string) => {
    if (!id) {
      feedbackCoordinatorRef.current.invalidate();
      feedbackCoordinatorRef.current.setActiveCategory("");
      setFeedbackSummary(null);
      return;
    }
    const token = feedbackCoordinatorRef.current.begin(id);
    try {
      const summary = await getPlatformFeedback(id, 200, { signal: token.signal });
      if (!feedbackCoordinatorRef.current.isCurrent(token)) return;
      setAllFeedbackByCategory((prev) => ({ ...prev, [id]: summary }));
      setFeedbackSummary(summary);
    } catch (e) {
      if (!feedbackCoordinatorRef.current.isCurrent(token) || isAbortError(e)) return;
      setFeedbackSummary(null);
    }
  }, []);

  const selectEngine = useCallback(
    (
      nextCategoryId: string,
      options: {
        notifyParent?: boolean;
        clearNotices?: boolean;
        resetTesting?: boolean;
      } = {},
    ) => {
      const isChanging = nextCategoryId !== selectedCategoryRef.current;
      selectedCategoryRef.current = nextCategoryId;
      userClearedSelectionRef.current = nextCategoryId === "";

      searchCoordinatorRef.current.invalidate();
      searchCoordinatorRef.current.setActiveCategory(nextCategoryId);
      historyCoordinatorRef.current.invalidate();
      historyCoordinatorRef.current.setActiveCategory(nextCategoryId);
      feedbackCoordinatorRef.current.invalidate();
      feedbackCoordinatorRef.current.setActiveCategory(nextCategoryId);

      setSelectedCategory(nextCategoryId);

      if (options.resetTesting !== false || isChanging) {
        setSearchFilters([]);
        setSearchResult(null);
        setSearchDurationMs(null);
        setSearching(false);
        setTestPage(1);
        setShowQueryPlanJson(false);
        setExpandedDocRawIds({});
      }

      if (options.clearNotices !== false) {
        setError("");
        setNotice("");
      }

      setCategoryHistory([]);
      setFeedbackSummary(null);

      if (options.notifyParent !== false) {
        onSelectedCategoryChangeRef.current?.(nextCategoryId);
      }

      if (nextCategoryId) {
        void loadHistory(nextCategoryId);
        void loadFeedback(nextCategoryId);
      }
    },
    [loadFeedback, loadHistory],
  );

  const loadAllCategoriesFeedback = useCallback(
    async (records: PlatformCategoryRecord[]) => {
      const entries = await Promise.all(
        records.map(async (rec) => {
          try {
            const summary = await getPlatformFeedback(rec.config.category_id, 200);
            return [rec.config.category_id, summary] as const;
          } catch {
            return [
              rec.config.category_id,
              { total_count: 0, relevant_count: 0, not_relevant_count: 0, items: [] },
            ] as const;
          }
        }),
      );
      setAllFeedbackByCategory(Object.fromEntries(entries));
    },
    [],
  );

  const refresh = useCallback(async () => {
    refreshAbortRef.current?.abort();
    const controller = new AbortController();
    refreshAbortRef.current = controller;
    refreshRequestIdRef.current += 1;
    const requestId = refreshRequestIdRef.current;

    setLoading(true);
    setError("");
    try {
      const result = await getPlatformCategories({ signal: controller.signal });
      if (requestId !== refreshRequestIdRef.current || controller.signal.aborted) {
        return;
      }
      setCategories(result);
      onCategoriesUpdatedRef.current?.(result);
      const currentSelected = selectedCategoryRef.current;
      const nextSelected = resolveCategoryAfterRefresh({
        categories: result,
        currentSelectedCategory: currentSelected,
        initialCategoryId: initialCategoryIdRef.current,
        userClearedSelection: userClearedSelectionRef.current,
      });
      if (nextSelected !== currentSelected) {
        selectEngine(nextSelected, {
          notifyParent: true,
          clearNotices: false,
          resetTesting: true,
        });
      } else if (nextSelected) {
        void loadHistory(nextSelected);
        void loadFeedback(nextSelected);
      }
      void loadAllCategoriesFeedback(result);
    } catch (e) {
      if (
        requestId !== refreshRequestIdRef.current ||
        controller.signal.aborted ||
        isAbortError(e)
      ) {
        return;
      }
      setError(
        getError(
          e,
          "Unable to load search engines. Verify that Search Admin Backend and upstream AI Search are running.",
        ),
      );
    } finally {
      if (requestId === refreshRequestIdRef.current) {
        setLoading(false);
      }
    }
  }, [loadAllCategoriesFeedback, loadFeedback, loadHistory, selectEngine]);

  useEffect(() => {
    void refresh();
    const searchCoord = searchCoordinatorRef.current;
    const historyCoord = historyCoordinatorRef.current;
    const feedbackCoord = feedbackCoordinatorRef.current;
    return () => {
      refreshRequestIdRef.current += 1;
      refreshAbortRef.current?.abort();
      refreshAbortRef.current = null;
      searchCoord.invalidate();
      historyCoord.invalidate();
      feedbackCoord.invalidate();
    };
  }, [refresh]);

  useEffect(() => {
    if (initialCategoryId === prevInitialCategoryIdRef.current) {
      return;
    }
    prevInitialCategoryIdRef.current = initialCategoryId;
    if (initialCategoryId && initialCategoryId !== selectedCategoryRef.current) {
      selectEngine(initialCategoryId, {
        notifyParent: false,
        clearNotices: false,
        resetTesting: true,
      });
    }
  }, [initialCategoryId, selectEngine]);

  useEffect(() => {
    void getPlatformSourceProfiles()
      .then((profiles) => {
        setSourceProfiles(profiles);
        setConnectionEnv((current) =>
          current || (profiles[0] ? "SEARCH_SOURCE_" + profiles[0].profile_id : ""),
        );
      })
      .catch(() => setSourceProfiles([]));
  }, []);

  const sourceProfileId = connectionEnv.startsWith("SEARCH_SOURCE_")
    ? connectionEnv.slice("SEARCH_SOURCE_".length)
    : "";
  const sourceTables = useMemo(
    () => sourceCatalog?.tables.filter((item) => item.schema === schema) ?? [],
    [sourceCatalog, schema],
  );
  const selectedSourceTable = sourceTables.find((item) => item.name === table) ?? null;
  const sourceColumns = selectedSourceTable?.columns ?? [];

  const totalSemanticWeight = useMemo(
    () =>
      fields
        .filter((f) => f.searchable && f.semantic && f.weight > 0)
        .reduce((acc, f) => acc + f.weight, 0),
    [fields],
  );

  const synonymDiagnostics = useMemo(() => {
    const groups = parseSynonymGroups(synonymText);
    const seen = new Map<string, number>();
    const overlaps: string[] = [];
    groups.forEach((g, idx) => {
      for (const term of g.terms) {
        const prev = seen.get(term);
        if (prev !== undefined && prev !== idx + 1) {
          overlaps.push(`"${term}" appears in both Group #${prev} and Group #${idx + 1}`);
        } else {
          seen.set(term, idx + 1);
        }
      }
    });
    return { groups, overlaps };
  }, [synonymText]);

  const joinableRelationships = useMemo(() => {
    const relationships = sourceCatalog?.relationships || [];
    if (!sourceCatalog || !table) return [];
    const keyFor = (relationship: PlatformSourceRelationship) =>
      [
        relationship.constraint_name,
        relationship.from_schema,
        relationship.from_table,
        relationship.to_schema,
        relationship.to_table,
      ].join("|");
    const selected = new Set(selectedJoinRelationships);
    const includedTables = new Set([schema + "." + table]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const relationship of relationships) {
        if (!selected.has(keyFor(relationship))) continue;
        const fromKey = relationship.from_schema + "." + relationship.from_table;
        const toKey = relationship.to_schema + "." + relationship.to_table;
        if (includedTables.has(fromKey) && !includedTables.has(toKey)) {
          includedTables.add(toKey);
          changed = true;
        }
      }
    }
    return relationships.filter((relationship) => {
      const key = keyFor(relationship);
      if (selected.has(key)) return true;
      const fromKey = relationship.from_schema + "." + relationship.from_table;
      const toKey = relationship.to_schema + "." + relationship.to_table;
      return includedTables.has(fromKey) && !includedTables.has(toKey);
    });
  }, [sourceCatalog, schema, table, selectedJoinRelationships]);

  const updateField = (index: number, patch: Partial<PlatformFieldConfig>) => {
    setFields((current) =>
      current.map((field, i) => (i === index ? { ...field, ...patch } : field)),
    );
  };

  const addField = () => {
    const number = fields.length + 1;
    setFields((current) => [
      ...current,
      {
        key: "field_" + number,
        source_column: "Column" + number,
        label: "Field " + number,
        role: "general",
        weight: 1,
        searchable: true,
        semantic: true,
        aliases: [],
        filterable: false,
        data_type: "text",
        query_filter_mode: "none",
        query_match: "all",
      },
    ]);
  };

  const removeField = (index: number) => {
    setFields((current) => current.filter((_, i) => i !== index));
  };

  const addSourceFilter = () => {
    setSourceValidation(null);
    setSourceFilters((current) => [
      ...current,
      { column: "", operator: "eq", value: undefined, values: [] },
    ]);
  };

  const updateSourceFilter = (index: number, patch: Partial<PlatformSourceFilter>) => {
    setSourceValidation(null);
    setSourceFilters((current) =>
      current.map((filter, i) => (i === index ? { ...filter, ...patch } : filter)),
    );
  };

  const loadCategoryForEdit = (item: PlatformCategoryRecord) => {
    const config = item.config;
    setCategoryId(config.category_id);
    setDisplayName(config.display_name);
    setDescription(config.description || "");
    setEngineActive(config.active);
    setSourceType(config.source.type);
    setSourceCatalog(null);
    setMappingSuggestions(null);
    setSourceValidation(null);
    setSelectedJoinRelationships([]);
    setViewPreview(null);
    if (config.source.type === "sqlserver") {
      setConnectionEnv(config.source.connection_env);
      setSchema(config.source.schema);
      setTable(config.source.table);
      setIdColumn(config.source.id_column);
      setMaxRecords(config.source.max_records);
      setSourceFilters(
        config.source.filters.map((filter) => ({
          ...filter,
          values: [...(filter.values || [])],
        })),
      );
    } else {
      setSourceFilters([]);
    }
    setFields(config.fields.map(normalizeLoadedFieldConfig));
    setSynonymText(
      (config.synonyms || []).map((group) => group.terms.join(", ")).join("\n"),
    );
    setMinScore(config.rules.semantic_min_score);
    setHighConfidenceScore(config.rules.semantic_high_confidence_score ?? 75);
    setLexicalWeight(config.rules.lexical_weight);
    setSemanticWeight(config.rules.semantic_weight);
    setLexicalEnabled(config.rules.lexical_enabled);
    setSemanticEnabled(config.rules.semantic_enabled);
    setCandidateLimit(config.rules.semantic_candidate_limit);
    setPublicEnabled(config.public_search_enabled);
    setEditingVersion(item.config_version);
    setShowEditorForm(true);
    selectEngine(config.category_id, {
      notifyParent: true,
      clearNotices: false,
      resetTesting: config.category_id !== selectedCategoryRef.current,
    });
    setNotice(
      `Loaded ${config.display_name} (config v${item.config_version}, index v${item.index_version}) with exact persisted field settings.`,
    );
    setError("");
  };

  const startNewEngine = () => {
    setEditingVersion(null);
    setCategoryId("new_engine");
    setDisplayName("New Search Engine");
    setDescription("Configurable BONC search engine");
    setEngineActive(true);
    setSourceType("sqlserver");
    setConnectionEnv(
      sourceProfiles[0] ? "SEARCH_SOURCE_" + sourceProfiles[0].profile_id : "",
    );
    setSourceCatalog(null);
    setSchema("dbo");
    setTable("");
    setIdColumn("");
    setMaxRecords(50000);
    setSourceFilters([]);
    setFields(INITIAL_FIELDS.map(normalizeLoadedFieldConfig));
    setSynonymText("");
    setMinScore(20);
    setHighConfidenceScore(75);
    setLexicalWeight(0.65);
    setSemanticWeight(0.35);
    setLexicalEnabled(true);
    setSemanticEnabled(true);
    setCandidateLimit(50);
    setPublicEnabled(false);
    setChangeReason("");
    setShowEditorForm(true);
    setNotice("Creating a new search engine configuration.");
    setError("");
  };

  const toggleEngineActiveStatus = async (item: PlatformCategoryRecord) => {
    const nextActive = !item.config.active;
    const confirmed = window.confirm(
      nextActive
        ? `Activate search engine "${item.config.display_name}" (${item.config.category_id})?`
        : `Deactivate search engine "${item.config.display_name}" (${item.config.category_id})? Queries against this engine will be paused until reactivated.`,
    );
    if (!confirmed) return;

    setTogglingStatus(item.config.category_id);
    setError("");
    setNotice("");
    try {
      const updatedConfig: PlatformCategoryConfig = {
        ...item.config,
        active: nextActive,
      };
      await updatePlatformCategory({
        categoryId: item.config.category_id,
        expectedVersion: item.config_version,
        config: updatedConfig,
        changeReason: nextActive
          ? "Activated engine from Admin UI"
          : "Deactivated engine from Admin UI",
      });
      setNotice(
        `${item.config.display_name} is now ${nextActive ? "active" : "disabled"}.`,
      );
      await refresh();
    } catch (e) {
      setError(getError(e, "Unable to change engine status."));
    } finally {
      setTogglingStatus("");
    }
  };

  const discoverSource = async () => {
    if (!sourceProfileId) {
      setError("Select a configured SQL connection profile first.");
      return;
    }
    setDiscoveringSource(true);
    setError("");
    setNotice("");
    try {
      const catalog = await discoverPlatformSourceSchema({
        profileId: sourceProfileId,
      });
      setSourceCatalog(catalog);
      setMappingSuggestions(null);
      setSelectedJoinRelationships([]);
      setViewPreview(null);
      setSourceValidation(null);

      const nextSchema = catalog.schemas.includes(schema)
        ? schema
        : catalog.schemas[0] || "dbo";
      setViewSchema(nextSchema);
      const tables = catalog.tables.filter((item) => item.schema === nextSchema);
      const selected = tables.find((item) => item.name === table) ?? tables[0];
      setSchema(nextSchema);
      if (selected) {
        setTable(selected.name);
        const primaryKey =
          selected.primary_key_columns?.length === 1
            ? selected.primary_key_columns[0]
            : "";
        setIdColumn((current) =>
          primaryKey ||
          (selected.columns.some((column) => column.name === current)
            ? current
            : selected.columns.find((column) => /id$/i.test(column.name))?.name || ""),
        );
      } else {
        setTable("");
        setIdColumn("");
      }
      setNotice(
        `Connected to profile ${sourceProfileId} (${catalog.database}). Discovered ${catalog.tables.length.toLocaleString()} tables/views across [${catalog.schemas.join(", ")}].`,
      );
    } catch (e) {
      setSourceCatalog(null);
      setSourceValidation(null);
      setError(getError(e, "Unable to inspect the configured SQL source."));
    } finally {
      setDiscoveringSource(false);
    }
  };

  const relationshipKey = (relationship: PlatformSourceRelationship) =>
    [
      relationship.constraint_name,
      relationship.from_schema,
      relationship.from_table,
      relationship.to_schema,
      relationship.to_table,
    ].join("|");

  const validateSource = async () => {
    if (!sourceProfileId || !schema || !table || !idColumn) return;
    setValidatingSource(true);
    setError("");
    setNotice("");
    try {
      const result = await validatePlatformSource({
        profileId: sourceProfileId,
        schema,
        table,
        idColumn,
        filters: sourceFilters,
        maxRecords,
      });
      setSourceValidation(result);
      setNotice(
        result.is_valid
          ? `Source validation passed for ${schema}.${table} (${result.total_rows.toLocaleString()} rows, 0 duplicate or NULL IDs).`
          : "Source validation found issues. Review the counts and warnings before syncing.",
      );
    } catch (e) {
      setSourceValidation(null);
      setError(getError(e, "Unable to validate the selected document ID."));
    } finally {
      setValidatingSource(false);
    }
  };

  const previewJoinView = async () => {
    if (!sourceProfileId || !sourceCatalog || !idColumn) return;
    const relationships = (sourceCatalog.relationships || []).filter((relationship) =>
      selectedJoinRelationships.includes(relationshipKey(relationship)),
    );
    setPreviewingView(true);
    setError("");
    setNotice("");
    try {
      const result = await previewPlatformJoinView({
        profileId: sourceProfileId,
        baseSchema: schema,
        baseTable: table,
        baseIdColumn: idColumn,
        viewSchema,
        viewName,
        selectedRelationships: relationships,
      });
      setViewPreview(result);
      setNotice(
        `Generated a SQL preview for ${result.view_schema}.${result.view_name} with ${result.joined_tables.length} tables. No database changes were executed.`,
      );
    } catch (e) {
      setViewPreview(null);
      setError(getError(e, "Unable to generate the SQL view preview."));
    } finally {
      setPreviewingView(false);
    }
  };

  const applyMappingSuggestions = async () => {
    if (!sourceProfileId || !schema || !table) return;
    setSuggestingMapping(true);
    setError("");
    setNotice("");
    try {
      const result = await suggestPlatformSourceMapping({
        profileId: sourceProfileId,
        schema,
        table,
      });
      setSourceValidation(null);
      const safeFields: PlatformFieldConfig[] = result.fields.map((field) =>
        normalizeLoadedFieldConfig(field),
      );
      setFields(safeFields);
      if (result.id_column_suggestion.column) {
        setIdColumn(result.id_column_suggestion.column);
      }
      setMappingSuggestions(result);
      const warnings = result.warnings.length
        ? " Review: " + result.warnings.join(" ")
        : "";
      setNotice(
        `Generated ${result.fields.length} field suggestions for ${schema}.${table}. Identifier: ${result.id_column_suggestion.column || "manual selection required"}.${warnings}`,
      );
    } catch (e) {
      setError(getError(e, "Unable to suggest field mappings."));
    } finally {
      setSuggestingMapping(false);
    }
  };

  const saveCategory = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (synonymDiagnostics.overlaps.length > 0) {
      setError(
        `Resolve overlapping synonym terms before saving: ${synonymDiagnostics.overlaps.join("; ")}`,
      );
      return;
    }
    if (publicEnabled) {
      const confirmed = window.confirm(
        `You have enabled "Public Search" for "${displayName}" (${categoryId}). Confirm that this category contains only approved public data and no private profile records.`,
      );
      if (!confirmed) return;
    }
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const config: PlatformCategoryConfig = {
        category_id: categoryId.trim().toLowerCase(),
        display_name: displayName.trim(),
        description: description.trim(),
        source:
          sourceType === "push"
            ? { type: "push" }
            : {
                type: "sqlserver",
                connection_env: connectionEnv.trim(),
                schema: schema.trim(),
                table: table.trim(),
                id_column: idColumn.trim(),
                max_records: maxRecords,
                filters: sourceFilters,
              },
        fields: fields.map(normalizeLoadedFieldConfig),
        synonyms: synonymDiagnostics.groups,
        rules: {
          ...DEFAULT_RULES,
          lexical_enabled: lexicalEnabled,
          semantic_enabled: semanticEnabled,
          semantic_min_score: minScore,
          semantic_high_confidence_score: highConfidenceScore,
          semantic_candidate_limit: candidateLimit,
          lexical_weight: lexicalWeight,
          semantic_weight: semanticWeight,
        },
        active: engineActive,
        public_search_enabled: publicEnabled,
      };
      const saved =
        editingVersion === null
          ? await createPlatformCategory(config)
          : await updatePlatformCategory({
              categoryId: config.category_id,
              expectedVersion: editingVersion,
              config,
              changeReason,
            });
      setNotice(
        editingVersion === null
          ? `Engine "${saved.config.display_name}" created (v${saved.config_version}). Next, sync its data source or ingest documents.`
          : `Engine "${saved.config.display_name}" updated to config v${saved.config_version}. Re-sync if source mappings changed.`,
      );
      setEditingVersion(saved.config_version);
      setChangeReason("");
      selectEngine(saved.config.category_id, {
        notifyParent: true,
        clearNotices: false,
        resetTesting: saved.config.category_id !== selectedCategoryRef.current,
      });
      await refresh();
    } catch (e) {
      setError(getError(e, "Unable to save category configuration."));
    } finally {
      setSaving(false);
    }
  };

  useEffect(() => {
    if (
      openEditorNonce > 0 &&
      openEditorNonce !== lastHandledEditorNonceRef.current &&
      initialCategoryId &&
      categories.length > 0
    ) {
      const target = categories.find((c) => c.config.category_id === initialCategoryId);
      if (target) {
        lastHandledEditorNonceRef.current = openEditorNonce;
        loadCategoryForEdit(target);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openEditorNonce, initialCategoryId, categories.length]);

  const startRollbackForVersion = (item: PlatformCategoryHistoryItem) => {
    setPendingRollbackItem(item);
    setRollbackReasonInput(`Rollback to config v${item.config_version}`);
    setError("");
  };

  const confirmRollbackToHistoryVersion = async () => {
    if (!pendingRollbackItem || editingVersion === null || !categoryId) return;
    const cleanedReason = rollbackReasonInput.trim();
    if (!cleanedReason) {
      setError("A rollback reason is required for the audit log.");
      return;
    }

    setRollingBackVersion(pendingRollbackItem.config_version);
    setError("");
    setNotice("");
    try {
      const restored = await rollbackPlatformCategory({
        categoryId,
        targetVersion: pendingRollbackItem.config_version,
        expectedVersion: editingVersion,
        reason: cleanedReason,
      });
      setPendingRollbackItem(null);
      setRollbackReasonInput("");
      loadCategoryForEdit(restored);
      setNotice(
        `Rolled back "${restored.config.display_name}" to v${restored.rolled_back_from_version} as new config v${restored.config_version} (index v${restored.index_version}).`,
      );
      await loadHistory(restored.config.category_id);
      await refresh();
    } catch (e) {
      setError(getError(e, "Unable to roll back configuration version."));
    } finally {
      setRollingBackVersion(null);
    }
  };

  const syncCategory = async (id: string) => {
    setSyncing(id);
    setError("");
    setNotice("");
    try {
      const result = await syncPlatformCategory(id);
      setNotice(
        `Synchronized ${result.documents_synced.toLocaleString()} normalized documents into "${id}" and invalidated the cached index.`,
      );
      await refresh();
    } catch (e) {
      setError(getError(e, "Unable to sync the configured source."));
    } finally {
      setSyncing("");
    }
  };

  const selectedRecord = useMemo(
    () => resolveSelectedEngineRecord(categories, selectedCategory),
    [categories, selectedCategory],
  );

  const ingest = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const targetCategory = selectedCategory || categoryId;
    if (!targetCategory) return;
    const confirmed = window.confirm(
      `Replace all indexed documents in "${targetCategory}" with the JSON payload below?`,
    );
    if (!confirmed) return;
    setIngesting(true);
    setError("");
    setNotice("");
    try {
      const parsed = JSON.parse(rawDocuments);
      if (!Array.isArray(parsed))
        throw new Error("The JSON must be an array of document objects.");
      const result = await ingestPlatformDocuments(targetCategory, parsed, true);
      setNotice(
        `Ingested ${result.documents_ingested.toLocaleString()} documents into "${targetCategory}".`,
      );
      await refresh();
    } catch (e) {
      setError(getError(e, "Unable to ingest documents. Check the JSON format."));
    } finally {
      setIngesting(false);
    }
  };

  const addSearchFilter = () => {
    const filterableFields =
      selectedRecord?.config.fields.filter((field) => field.filterable) ?? [];
    if (!filterableFields.length) {
      setError(
        "This engine has no filterable fields configured. Enable Filterable on a field first.",
      );
      return;
    }
    setSearchFilters((current) => [
      ...current,
      {
        field: filterableFields[0].key,
        operator: "eq",
        value: "",
        values: [],
      },
    ]);
  };

  const updateSearchFilter = (
    index: number,
    patch: Partial<PlatformSearchFilter>,
  ) => {
    setSearchFilters((current) =>
      current.map((item, itemIndex) =>
        itemIndex === index ? { ...item, ...patch } : item,
      ),
    );
  };

  const executeTestSearch = useCallback(
    async (nextPage = 1, explicitQuery?: string, explicitCategory?: string) => {
      const targetCategory = explicitCategory || selectedCategoryRef.current;
      const searchText = (explicitQuery ?? query).trim();
      if (!targetCategory || !searchText) return;
      const token = searchCoordinatorRef.current.begin(targetCategory);
      setSearching(true);
      setError("");
      const startedAt = performance.now();
      try {
        const targetRecord = resolveSelectedEngineRecord(categories, targetCategory);
        const selectedFields = targetRecord?.config.fields ?? [];
        const cleanFilters = searchFilters.map((item) => {
          const field = selectedFields.find((candidate) => candidate.key === item.field);
          if (!field?.filterable) {
            throw new Error("Select a configured filterable field.");
          }
          const operator = item.operator;
          if (operator === "in" || operator === "between") {
            const values = (item.values || [])
              .map((value) => String(value).trim())
              .filter(Boolean);
            if (!values.length) {
              throw new Error("Enter filter values for " + field.label + ".");
            }
            if (operator === "between" && values.length !== 2) {
              throw new Error(
                "Between filters require exactly two comma-separated values.",
              );
            }
            return { field: item.field, operator, values };
          }
          if (operator === "is_null" || operator === "not_null") {
            return { field: item.field, operator };
          }
          if (
            item.value === undefined ||
            item.value === null ||
            String(item.value).trim() === ""
          ) {
            throw new Error("Enter a filter value for " + field.label + ".");
          }
          return { field: item.field, operator, value: item.value };
        });
        const result = await runPlatformAdminSearch({
          query: searchText,
          category: targetCategory,
          page: nextPage,
          pageSize: testPageSize,
          filters: cleanFilters,
          signal: token.signal,
        });
        if (
          !searchCoordinatorRef.current.isCurrent(token) ||
          !isSearchResultForActiveEngine(result, targetCategory)
        ) {
          return;
        }
        setSearchDurationMs(Math.round(performance.now() - startedAt));
        setSearchResult(result);
        setTestPage(nextPage);
        setExpandedDocRawIds({});
      } catch (e) {
        if (!searchCoordinatorRef.current.isCurrent(token) || isAbortError(e)) {
          return;
        }
        setSearchResult(null);
        setError(
          getError(
            e,
            "Search test failed. Ensure the category is active and has synced or ingested documents.",
          ),
        );
      } finally {
        if (searchCoordinatorRef.current.isCurrent(token)) {
          setSearching(false);
        }
      }
    },
    [categories, query, searchFilters, testPageSize],
  );

  const runTestSearch = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await executeTestSearch(1);
  };

  const combinedFeedbackItems = useMemo(() => {
    const rows: Array<PlatformFeedbackItem & { category_id: string }> = [];
    for (const [catId, summary] of Object.entries(allFeedbackByCategory)) {
      if (feedbackFilterCategory !== "all" && feedbackFilterCategory !== catId) continue;
      for (const item of summary.items || []) {
        if (feedbackFilterVerdict === "relevant" && !item.is_relevant) continue;
        if (feedbackFilterVerdict === "not_relevant" && item.is_relevant) continue;
        if (
          feedbackFilterQuery.trim() &&
          !item.query.toLowerCase().includes(feedbackFilterQuery.trim().toLowerCase()) &&
          !item.document_id
            .toLowerCase()
            .includes(feedbackFilterQuery.trim().toLowerCase())
        ) {
          continue;
        }
        rows.push({ ...item, category_id: catId });
      }
    }
    return rows.sort((a, b) => b.feedback_id - a.feedback_id);
  }, [
    allFeedbackByCategory,
    feedbackFilterCategory,
    feedbackFilterQuery,
    feedbackFilterVerdict,
  ]);

  const feedbackTotals = useMemo(() => {
    let total = 0;
    let relevant = 0;
    let notRelevant = 0;
    const distinctQueries = new Set<string>();
    for (const [catId, summary] of Object.entries(allFeedbackByCategory)) {
      if (feedbackFilterCategory !== "all" && feedbackFilterCategory !== catId) continue;
      total += summary.total_count;
      relevant += summary.relevant_count;
      notRelevant += summary.not_relevant_count;
      for (const item of summary.items || []) {
        distinctQueries.add(`${catId}:${item.query.toLowerCase()}`);
      }
    }
    return { total, relevant, notRelevant, distinctQueries: distinctQueries.size };
  }, [allFeedbackByCategory, feedbackFilterCategory]);

  const showEnginesSection = mode === "all" || mode === "engines";
  const showTestingSection = mode === "all" || mode === "testing";
  const showFeedbackSection = mode === "all" || mode === "feedback";
  const activeSearchResult = isSearchResultForActiveEngine(searchResult, selectedCategory)
    ? searchResult
    : null;
  const totalTestPages = activeSearchResult
    ? Math.max(
        1,
        Math.ceil(activeSearchResult.total_count / activeSearchResult.page_size),
      )
    : 1;

  return (
    <div className="platform-workspace">
      {error && (
        <div className="inline-error">
          <strong>Operation Notice</strong>
          <span>{error}</span>
        </div>
      )}
      {notice && <div className="success-message">{notice}</div>}

      {showEnginesSection && (
        <>
          <section className="panel platform-intro-panel">
            <div className="panel-title-row">
              <div>
                <span className="section-kicker">ENGINE REGISTRY</span>
                <h2>Configured Search Engines</h2>
              </div>
              <div className="settings-actions" style={{ marginTop: 0 }}>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => void refresh()}
                  disabled={loading}
                >
                  {loading ? "Refreshing…" : "↻ Refresh Registry"}
                </button>
                <button
                  type="button"
                  className="primary-button"
                  onClick={startNewEngine}
                >
                  + New Search Engine
                </button>
              </div>
            </div>
            <p className="panel-intro">
              Each search engine has its own isolated SQL Server view/table source,
              normalized document store, field roles and weights, lexical/semantic rules,
              synonyms, and audit history.
            </p>

            {loading ? (
              <div className="loading-state">
                <span className="spinner dark" /> Loading search engine registry…
              </div>
            ) : categories.length === 0 ? (
              <p className="panel-intro">No search engines configured yet.</p>
            ) : (
              <div className="engine-registry-grid">
                {categories.map((item) => {
                  const cfg = item.config;
                  const isActive = item.status === "active" && cfg.active;
                  const docCount = item.document_count ?? 0;
                  const fb = allFeedbackByCategory[cfg.category_id];
                  const filterableCount = cfg.fields.filter((f) => f.filterable).length;
                  const semanticCount = cfg.fields.filter(
                    (f) => f.searchable && f.semantic && f.weight > 0,
                  ).length;

                  return (
                    <article
                      className={`engine-card ${selectedCategory === cfg.category_id ? "selected" : ""}`}
                      key={cfg.category_id}
                    >
                      <div className="engine-card-header">
                        <div>
                          <div className="engine-title-row">
                            <h3>{cfg.display_name}</h3>
                            <code className="code-pill">{cfg.category_id}</code>
                          </div>
                          <p className="engine-desc">
                            {cfg.description || "No description provided"}
                          </p>
                        </div>
                        <div className="engine-badges">
                          <span className={`badge ${isActive ? "badge-ok" : "badge-warn"}`}>
                            {isActive ? "Active" : "Disabled"}
                          </span>
                          <span
                            className={`badge ${cfg.public_search_enabled ? "badge-warn" : "badge-info"}`}
                          >
                            {cfg.public_search_enabled ? "Public API" : "Admin-Only"}
                          </span>
                        </div>
                      </div>

                      <div className="engine-kpi-row">
                        <div className="engine-kpi">
                          <span>Documents</span>
                          <strong>{docCount.toLocaleString()}</strong>
                        </div>
                        <div className="engine-kpi">
                          <span>Versions</span>
                          <strong>
                            cfg v{item.config_version} · idx v{item.index_version}
                          </strong>
                        </div>
                        <div className="engine-kpi">
                          <span>Fields</span>
                          <strong>
                            {cfg.fields.length} ({filterableCount} filter · {semanticCount}{" "}
                            sem)
                          </strong>
                        </div>
                        <div className="engine-kpi">
                          <span>Synonyms / Feedback</span>
                          <strong>
                            {(cfg.synonyms || []).length} groups · {fb?.total_count ?? 0}{" "}
                            labels
                          </strong>
                        </div>
                      </div>

                      <div className="engine-source-line">
                        <span>Source:</span>
                        {cfg.source.type === "sqlserver" ? (
                          <code>
                            {cfg.source.connection_env} → [{cfg.source.schema}].[
                            {cfg.source.table}] (ID: {cfg.source.id_column})
                          </code>
                        ) : (
                          <code>Push Ingestion API</code>
                        )}
                      </div>

                      <div className="engine-card-actions">
                        <button
                          type="button"
                          className="secondary-button"
                          onClick={() => loadCategoryForEdit(item)}
                        >
                          ✎ Configure &amp; Inspect Fields
                        </button>
                        <button
                          type="button"
                          className="secondary-button"
                          onClick={() => {
                            selectEngine(cfg.category_id, {
                              notifyParent: true,
                              clearNotices: true,
                              resetTesting: true,
                            });
                            onSelectMode?.("testing", cfg.category_id);
                          }}
                        >
                          ⌕ Test Engine
                        </button>
                        {cfg.source.type === "sqlserver" && (
                          <button
                            type="button"
                            className="secondary-button"
                            disabled={syncing === cfg.category_id}
                            onClick={() => void syncCategory(cfg.category_id)}
                          >
                            {syncing === cfg.category_id ? "Syncing…" : "↻ Sync Source"}
                          </button>
                        )}
                        <button
                          type="button"
                          className={`secondary-button ${isActive ? "danger-button" : ""}`}
                          disabled={togglingStatus === cfg.category_id}
                          onClick={() => void toggleEngineActiveStatus(item)}
                        >
                          {togglingStatus === cfg.category_id
                            ? "Updating…"
                            : isActive
                              ? "Pause"
                              : "Activate"}
                        </button>
                      </div>
                    </article>
                  );
                })}
              </div>
            )}
          </section>

          {(showEditorForm || editingVersion !== null) && (
            <section className="panel platform-form-panel">
              <div className="panel-title-row">
                <div>
                  <span className="section-kicker">
                    {editingVersion === null
                      ? "CREATE NEW ENGINE"
                      : `EDITING ${displayName.toUpperCase()} (CONFIG v${editingVersion})`}
                  </span>
                  <h2>
                    {editingVersion === null
                      ? "Create a Search Engine"
                      : `Configure ${displayName} (${categoryId})`}
                  </h2>
                </div>
                <div className="settings-actions" style={{ marginTop: 0 }}>
                  <span className="method-badge">
                    {editingVersion === null
                      ? "POST · /api/admin/platform/categories"
                      : `PUT · /api/admin/platform/categories/${categoryId}`}
                  </span>
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => {
                      setShowEditorForm(false);
                      setEditingVersion(null);
                    }}
                  >
                    Close Editor
                  </button>
                </div>
              </div>

              <form onSubmit={(event) => void saveCategory(event)}>
                <div className="platform-form-grid">
                  <label className="setting-field">
                    <span>Engine ID</span>
                    <small>Lowercase identifier, e.g. people, jobs, articles.</small>
                    <input
                      required
                      value={categoryId}
                      disabled={editingVersion !== null}
                      onChange={(e) => setCategoryId(e.target.value)}
                      pattern="[a-z][a-z0-9_-]{1,62}"
                    />
                  </label>
                  <label className="setting-field">
                    <span>Display Name</span>
                    <small>Human-friendly engine title shown across tools.</small>
                    <input
                      required
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                    />
                  </label>
                  <label className="setting-field wide">
                    <span>Description</span>
                    <input
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Describe what this search engine indexes and serves"
                    />
                  </label>
                </div>

                <div className="settings-section-title">
                  <div>
                    <h3>1. Data Source &amp; Connection</h3>
                    <p>
                      Database credentials remain strictly on the server. Select a
                      registered profile, discover schemas/views, and validate ID
                      uniqueness before syncing.
                    </p>
                  </div>
                </div>

                <div className="platform-form-grid">
                  <label className="setting-field">
                    <span>Source Type</span>
                    <select
                      value={sourceType}
                      onChange={(e) => {
                        setSourceType(e.target.value as "sqlserver" | "push");
                        setSourceValidation(null);
                      }}
                    >
                      <option value="sqlserver">SQL Server Table or View</option>
                      <option value="push">Push API (JSON Document Ingestion)</option>
                    </select>
                  </label>
                  {sourceType === "sqlserver" ? (
                    <>
                      <label className="setting-field">
                        <span>Server Connection Profile</span>
                        <select
                          value={sourceProfileId}
                          onChange={(e) => {
                            setConnectionEnv(
                              e.target.value ? "SEARCH_SOURCE_" + e.target.value : "",
                            );
                            setSourceCatalog(null);
                            setSourceValidation(null);
                            setSourceFilters([]);
                            setMappingSuggestions(null);
                            setSelectedJoinRelationships([]);
                            setViewPreview(null);
                          }}
                          required
                        >
                          <option value="">Select a configured connection</option>
                          {sourceProfiles.map((profile) => (
                            <option key={profile.profile_id} value={profile.profile_id}>
                              {profile.profile_id} ({profile.connection_env})
                            </option>
                          ))}
                          {sourceProfileId &&
                            !sourceProfiles.some(
                              (profile) => profile.profile_id === sourceProfileId,
                            ) && (
                              <option value={sourceProfileId}>
                                {sourceProfileId} (configured)
                              </option>
                            )}
                        </select>
                      </label>
                      <div className="setting-field">
                        <span>Schema &amp; Metadata Discovery</span>
                        <button
                          type="button"
                          className="secondary-button"
                          onClick={() => void discoverSource()}
                          disabled={!sourceProfileId || discoveringSource}
                        >
                          {discoveringSource
                            ? "Connecting…"
                            : "Test Connection & Discover Tables/Views"}
                        </button>
                        <small>
                          Inspects INFORMATION_SCHEMA tables, views, columns, and primary
                          keys read-only.
                        </small>
                      </div>
                      <label className="setting-field">
                        <span>Schema</span>
                        {sourceCatalog ? (
                          <select
                            value={schema}
                            onChange={(e) => {
                              setSchema(e.target.value);
                              setViewSchema(e.target.value);
                              setTable("");
                              setIdColumn("");
                              setSourceFilters([]);
                              setMappingSuggestions(null);
                              setSelectedJoinRelationships([]);
                              setViewPreview(null);
                              setSourceValidation(null);
                            }}
                          >
                            {sourceCatalog.schemas.map((value) => (
                              <option key={value} value={value}>
                                {value}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <input
                            value={schema}
                            onChange={(e) => setSchema(e.target.value)}
                            required
                          />
                        )}
                      </label>
                      <label className="setting-field">
                        <span>Table or View</span>
                        {sourceCatalog ? (
                          <select
                            value={table}
                            onChange={(e) => {
                              const nextTable = sourceTables.find(
                                (item) => item.name === e.target.value,
                              );
                              setTable(e.target.value);
                              setSourceFilters([]);
                              setMappingSuggestions(null);
                              setSelectedJoinRelationships([]);
                              setViewPreview(null);
                              setSourceValidation(null);
                              setIdColumn(
                                nextTable?.primary_key_columns?.length === 1
                                  ? nextTable.primary_key_columns[0]
                                  : nextTable?.columns.find((column) =>
                                      /id$/i.test(column.name),
                                    )?.name || "",
                              );
                            }}
                            required
                          >
                            <option value="">Select table or view</option>
                            {sourceTables.map((item) => (
                              <option key={item.name} value={item.name}>
                                {item.name} ({item.type === "VIEW" ? "view" : "table"})
                                {item.primary_key_columns?.length
                                  ? " · PK: " + item.primary_key_columns.join(", ")
                                  : ""}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <input
                            value={table}
                            onChange={(e) => setTable(e.target.value)}
                            required
                          />
                        )}
                      </label>
                      <label className="setting-field">
                        <span>Unique Document ID Column</span>
                        {sourceCatalog ? (
                          <select
                            value={idColumn}
                            onChange={(e) => {
                              setIdColumn(e.target.value);
                              setSourceValidation(null);
                            }}
                            required
                          >
                            <option value="">Select unique ID column</option>
                            {sourceColumns.map((column) => (
                              <option key={column.name} value={column.name}>
                                {column.name} · {column.data_type}
                                {column.is_primary_key ? " · PK" : ""}
                                {column.is_foreign_key ? " · FK" : ""}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <input
                            value={idColumn}
                            onChange={(e) => setIdColumn(e.target.value)}
                            required
                          />
                        )}
                      </label>
                      <label className="setting-field">
                        <span>Max Records per Sync</span>
                        <input
                          type="number"
                          min="1"
                          max="100000"
                          value={maxRecords}
                          onChange={(e) => {
                            setMaxRecords(Number(e.target.value));
                            setSourceValidation(null);
                          }}
                        />
                      </label>
                      <div className="setting-field">
                        <span>Source Preflight Check</span>
                        <button
                          type="button"
                          className="secondary-button"
                          onClick={() => void validateSource()}
                          disabled={
                            !sourceProfileId ||
                            !schema ||
                            !table ||
                            !idColumn ||
                            validatingSource
                          }
                        >
                          {validatingSource
                            ? "Validating Source…"
                            : "✓ Validate ID Uniqueness & Row Count"}
                        </button>
                        <small>
                          Verifies non-null, non-blank, duplicate-free Document IDs.
                        </small>
                      </div>
                      {sourceValidation && (
                        <div
                          className={`mini-panel wide ${sourceValidation.is_valid ? "validation-ok" : "validation-warn"}`}
                        >
                          <div>
                            <strong>
                              {sourceValidation.is_valid
                                ? "✓ Source Preflight Validation Passed"
                                : "⚠ Source Preflight Validation Requires Attention"}
                            </strong>
                            <p>
                              Source:{" "}
                              <code>
                                [{sourceValidation.schema}].[{sourceValidation.table}]
                              </code>{" "}
                              ({sourceValidation.database}) · ID Column:{" "}
                              <code>{sourceValidation.id_column}</code>
                            </p>
                            <p>
                              <strong>
                                {sourceValidation.total_rows.toLocaleString()}
                              </strong>{" "}
                              total rows ·{" "}
                              <strong>
                                {sourceValidation.distinct_ids.toLocaleString()}
                              </strong>{" "}
                              distinct IDs ·{" "}
                              <strong>{sourceValidation.null_id_count}</strong> NULL IDs ·{" "}
                              <strong>{sourceValidation.blank_id_count}</strong> blank IDs
                              · <strong>{sourceValidation.duplicate_id_count}</strong>{" "}
                              duplicate IDs
                            </p>
                            {sourceValidation.warnings.map((warning) => (
                              <small key={warning} style={{ display: "block" }}>
                                {warning}
                              </small>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  ) : (
                    <p className="panel-intro wide">
                      Save the engine configuration, then push normalized JSON records
                      using the Push Document Ingestion panel below.
                    </p>
                  )}
                </div>

                {sourceType === "sqlserver" &&
                  sourceCatalog &&
                  selectedSourceTable &&
                  (sourceCatalog.relationships || []).length > 0 && (
                    <div className="platform-history">
                      <div className="settings-section-title">
                        <div>
                          <h3>Multi-Table Join View SQL Preview</h3>
                          <p>
                            Select declared foreign-key relationships to preview a read-only
                            SQL view script (no DDL is executed automatically).
                          </p>
                        </div>
                      </div>
                      <div className="platform-form-grid">
                        <label className="setting-field">
                          <span>Target View Schema</span>
                          <input
                            value={viewSchema}
                            onChange={(e) => setViewSchema(e.target.value)}
                          />
                        </label>
                        <label className="setting-field">
                          <span>Target View Name</span>
                          <input
                            value={viewName}
                            onChange={(e) => setViewName(e.target.value)}
                          />
                        </label>
                      </div>
                      {joinableRelationships.map((relationship) => {
                        const key = relationshipKey(relationship);
                        return (
                          <label className="platform-checkbox" key={key}>
                            <input
                              type="checkbox"
                              checked={selectedJoinRelationships.includes(key)}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedJoinRelationships((current) => [
                                    ...current,
                                    key,
                                  ]);
                                } else {
                                  setSelectedJoinRelationships((current) =>
                                    current.filter((item) => item !== key),
                                  );
                                }
                                setViewPreview(null);
                              }}
                            />
                            {relationship.from_schema}.{relationship.from_table} (
                            {relationship.columns.map((c) => c.from_column).join(", ")}) →{" "}
                            {relationship.to_schema}.{relationship.to_table} (
                            {relationship.columns.map((c) => c.to_column).join(", ")})
                          </label>
                        );
                      })}
                      <div className="settings-actions">
                        <span className="action-spacer" />
                        <button
                          type="button"
                          className="secondary-button"
                          onClick={() => void previewJoinView()}
                          disabled={
                            previewingView ||
                            selectedJoinRelationships.length === 0 ||
                            !idColumn
                          }
                        >
                          {previewingView
                            ? "Generating Preview…"
                            : "Generate Join-View SQL Preview"}
                        </button>
                      </div>
                      {viewPreview && (
                        <div className="mini-panel">
                          <div style={{ width: "100%" }}>
                            <strong>
                              {viewPreview.view_schema}.{viewPreview.view_name}
                            </strong>
                            <textarea
                              className="platform-json-input"
                              rows={10}
                              readOnly
                              value={viewPreview.view_sql}
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                {sourceType === "sqlserver" && (
                  <div className="platform-source-filters">
                    <div className="settings-section-title">
                      <div>
                        <h3>SQL Source Filters</h3>
                        <p>
                          WHERE-clause filters applied when syncing rows from [{schema}].[
                          {table}] (e.g., Status = Active, IsDeleted = 0).
                        </p>
                      </div>
                      <button
                        type="button"
                        className="secondary-button"
                        onClick={addSourceFilter}
                      >
                        + Add Source Filter
                      </button>
                    </div>
                    {sourceFilters.map((filter, index) => (
                      <div className="platform-filter-row" key={index}>
                        <label className="setting-field">
                          <span>Column</span>
                          {sourceCatalog ? (
                            <select
                              value={filter.column}
                              required
                              onChange={(e) =>
                                updateSourceFilter(index, { column: e.target.value })
                              }
                            >
                              <option value="">Select column</option>
                              {sourceColumns.map((column) => (
                                <option key={column.name} value={column.name}>
                                  {column.name}
                                </option>
                              ))}
                            </select>
                          ) : (
                            <input
                              value={filter.column}
                              required
                              onChange={(e) =>
                                updateSourceFilter(index, { column: e.target.value })
                              }
                            />
                          )}
                        </label>
                        <label className="setting-field">
                          <span>Operator</span>
                          <select
                            value={filter.operator}
                            onChange={(e) =>
                              updateSourceFilter(index, {
                                operator: e.target
                                  .value as PlatformSourceFilter["operator"],
                                value: undefined,
                                values: [],
                              })
                            }
                          >
                            <option value="eq">Equals (eq)</option>
                            <option value="ne">Not Equal (ne)</option>
                            <option value="in">In List (in)</option>
                            <option value="is_null">Is NULL</option>
                            <option value="not_null">Is Not NULL</option>
                          </select>
                        </label>
                        {filter.operator === "eq" || filter.operator === "ne" ? (
                          <label className="setting-field">
                            <span>Value</span>
                            <input
                              required
                              value={String(filter.value ?? "")}
                              onChange={(e) =>
                                updateSourceFilter(index, { value: e.target.value })
                              }
                            />
                          </label>
                        ) : filter.operator === "in" ? (
                          <label className="setting-field">
                            <span>Values (comma-separated)</span>
                            <input
                              required
                              value={(filter.values || []).join(", ")}
                              onChange={(e) =>
                                updateSourceFilter(index, {
                                  values: e.target.value
                                    .split(",")
                                    .map((v) => v.trim())
                                    .filter(Boolean),
                                })
                              }
                            />
                          </label>
                        ) : (
                          <div className="setting-field">
                            <span>Value</span>
                            <small>No value needed for NULL checks</small>
                          </div>
                        )}
                        <button
                          type="button"
                          className="secondary-button danger-button"
                          onClick={() => {
                            setSourceValidation(null);
                            setSourceFilters((current) =>
                              current.filter((_, i) => i !== index),
                            );
                          }}
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                <div className="settings-section-title">
                  <div>
                    <h3>2. Field Mapping, Roles, Weights &amp; Filter Behavior</h3>
                    <p>
                      Displayed values reflect the exact backend-persisted settings for{" "}
                      <code>filterable</code>, <code>data_type</code>,{" "}
                      <code>query_filter_mode</code>, and <code>query_match</code>.
                    </p>
                  </div>
                  <div className="settings-actions" style={{ marginTop: 0 }}>
                    {sourceType === "sqlserver" && (
                      <button
                        type="button"
                        className="secondary-button"
                        onClick={() => void applyMappingSuggestions()}
                        disabled={!sourceProfileId || !table || suggestingMapping}
                      >
                        {suggestingMapping ? "Suggesting…" : "Auto-Suggest Mappings"}
                      </button>
                    )}
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={addField}
                    >
                      + Add Field
                    </button>
                  </div>
                </div>

                <div className="table-scroll-wrap">
                  <table className="audit-table">
                    <thead>
                      <tr>
                        <th>Field Key</th>
                        <th>Source Column</th>
                        <th>Role</th>
                        <th>Weight</th>
                        <th>BM25F Boost</th>
                        <th>Semantic Share</th>
                        <th>Searchable</th>
                        <th>Semantic</th>
                        <th>Filterable</th>
                        <th>Data Type</th>
                        <th>Query Filter Mode</th>
                        <th>Multi-Value Match</th>
                        <th>Aliases</th>
                      </tr>
                    </thead>
                    <tbody>
                      {fields.map((f) => {
                        const roleBoost = ROLE_LEXICAL_BOOSTS[f.role] ?? 1.0;
                        const effectiveBoost = f.searchable ? f.weight * roleBoost : 0;
                        const semShare =
                          f.searchable && f.semantic && f.weight > 0 && totalSemanticWeight > 0
                            ? ((f.weight / totalSemanticWeight) * 100).toFixed(1) + "%"
                            : "0%";
                        return (
                          <tr key={f.key}>
                            <td>
                              <code>{f.key}</code>
                            </td>
                            <td>
                              <code>{f.source_column}</code>
                            </td>
                            <td>
                              <span className="badge badge-info">{f.role}</span>
                            </td>
                            <td>
                              <strong>{f.weight}</strong>
                            </td>
                            <td>{effectiveBoost.toFixed(2)}</td>
                            <td>{semShare}</td>
                            <td>{f.searchable ? "Yes" : "No"}</td>
                            <td>{f.semantic ? "Yes" : "No"}</td>
                            <td>
                              <span
                                className={`badge ${f.filterable ? "badge-ok" : "badge-muted"}`}
                              >
                                {f.filterable ? "true" : "false"}
                              </span>
                            </td>
                            <td>
                              <code>{f.data_type || "text"}</code>
                            </td>
                            <td>
                              <code>{f.query_filter_mode || "none"}</code>
                            </td>
                            <td>
                              <code>{f.query_match || "all"}</code>
                            </td>
                            <td>{f.aliases.length ? f.aliases.join(", ") : "—"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {mappingSuggestions && (
                  <div className="mini-panel" style={{ marginTop: 12 }}>
                    <div>
                      <strong>Auto-Suggestion Summary</strong>
                      <p>
                        Suggested ID:{" "}
                        <code>
                          {mappingSuggestions.id_column_suggestion.column || "Manual"}
                        </code>{" "}
                        · {mappingSuggestions.id_column_suggestion.reason}
                      </p>
                      {mappingSuggestions.skipped_columns.length > 0 && (
                        <small style={{ display: "block" }}>
                          Skipped sensitive/key columns:{" "}
                          {mappingSuggestions.skipped_columns
                            .map((c) => c.column)
                            .join(", ")}
                        </small>
                      )}
                    </div>
                  </div>
                )}

                <div className="platform-fields">
                  {fields.map((field, index) => (
                    <div className="platform-field-row" key={index}>
                      <label className="setting-field">
                        <span>Field Key</span>
                        <input
                          value={field.key}
                          onChange={(e) => updateField(index, { key: e.target.value })}
                          required
                        />
                      </label>
                      <label className="setting-field">
                        <span>Source Column</span>
                        {sourceCatalog && sourceColumns.length > 0 ? (
                          <select
                            value={field.source_column}
                            onChange={(e) =>
                              updateField(index, { source_column: e.target.value })
                            }
                            required
                          >
                            {!sourceColumns.some(
                              (column) => column.name === field.source_column,
                            ) && (
                              <option value={field.source_column}>
                                {field.source_column} (custom)
                              </option>
                            )}
                            {sourceColumns.map((column) => (
                              <option key={column.name} value={column.name}>
                                {column.name} · {column.data_type}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <input
                            value={field.source_column}
                            onChange={(e) =>
                              updateField(index, { source_column: e.target.value })
                            }
                            required
                          />
                        )}
                      </label>
                      <label className="setting-field">
                        <span>Display Label</span>
                        <input
                          value={field.label}
                          onChange={(e) => updateField(index, { label: e.target.value })}
                          required
                        />
                      </label>
                      <label className="setting-field">
                        <span>Semantic Role</span>
                        <select
                          value={field.role}
                          onChange={(e) =>
                            updateField(index, {
                              role: e.target.value as PlatformFieldRole,
                            })
                          }
                        >
                          {ROLE_OPTIONS.map((role) => (
                            <option key={role} value={role}>
                              {role} ({ROLE_LEXICAL_BOOSTS[role]}x boost)
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="setting-field">
                        <span>Field Weight (0–100)</span>
                        <input
                          type="number"
                          min="0"
                          max="100"
                          step="0.5"
                          value={field.weight}
                          onChange={(e) =>
                            updateField(index, { weight: Number(e.target.value) })
                          }
                        />
                      </label>
                      <label className="setting-field">
                        <span>Aliases (comma-separated)</span>
                        <input
                          value={field.aliases.join(", ")}
                          onChange={(e) =>
                            updateField(index, {
                              aliases: e.target.value
                                .split(",")
                                .map((x) => x.trim())
                                .filter(Boolean),
                            })
                          }
                        />
                      </label>
                      <label className="setting-field">
                        <span>Data Type</span>
                        <select
                          value={field.data_type ?? "text"}
                          onChange={(e) => {
                            const dataType = e.target
                              .value as PlatformFieldConfig["data_type"];
                            updateField(index, {
                              data_type: dataType,
                              ...(field.query_filter_mode === "required" &&
                              ["integer", "number", "date"].includes(dataType || "")
                                ? { query_filter_mode: "preferred" as const }
                                : {}),
                            });
                          }}
                        >
                          <option value="text">text</option>
                          <option value="keyword">keyword (exact / facet)</option>
                          <option value="integer">integer</option>
                          <option value="number">number</option>
                          <option value="boolean">boolean</option>
                          <option value="date">date / datetime</option>
                        </select>
                      </label>
                      <label className="setting-field">
                        <span>Query Filter Mode</span>
                        <select
                          value={field.query_filter_mode ?? "none"}
                          disabled={!field.filterable}
                          onChange={(e) =>
                            updateField(index, {
                              query_filter_mode: e.target
                                .value as PlatformFieldConfig["query_filter_mode"],
                            })
                          }
                        >
                          <option value="none">none (ranking / explicit filter only)</option>
                          <option value="preferred">
                            preferred (soft boost on value match)
                          </option>
                          <option
                            value="required"
                            disabled={["integer", "number", "date"].includes(
                              field.data_type || "text",
                            )}
                          >
                            required (automatic hard filter)
                          </option>
                        </select>
                      </label>
                      <label className="setting-field">
                        <span>Multi-Value Match (query_match)</span>
                        <select
                          value={field.query_match ?? "all"}
                          disabled={!field.filterable}
                          onChange={(e) =>
                            updateField(index, {
                              query_match: e.target
                                .value as PlatformFieldConfig["query_match"],
                            })
                          }
                        >
                          <option value="all">all (require all matched values)</option>
                          <option value="any">any (match any recognized value)</option>
                        </select>
                      </label>
                      <label className="platform-checkbox">
                        <input
                          type="checkbox"
                          checked={field.searchable}
                          onChange={(e) =>
                            updateField(index, {
                              searchable: e.target.checked,
                              ...(e.target.checked ? {} : { semantic: false }),
                            })
                          }
                        />
                        Searchable
                      </label>
                      <label className="platform-checkbox">
                        <input
                          type="checkbox"
                          checked={field.semantic}
                          disabled={!field.searchable}
                          onChange={(e) =>
                            updateField(index, { semantic: e.target.checked })
                          }
                        />
                        Include in Semantic Vector
                      </label>
                      <label className="platform-checkbox">
                        <input
                          type="checkbox"
                          checked={Boolean(field.filterable)}
                          onChange={(e) =>
                            updateField(index, {
                              filterable: e.target.checked,
                              query_filter_mode: e.target.checked
                                ? field.query_filter_mode || "none"
                                : "none",
                            })
                          }
                        />
                        Allow Result Filters (filterable)
                      </label>
                      <button
                        type="button"
                        className="secondary-button danger-button"
                        onClick={() => removeField(index)}
                        disabled={fields.length <= 1}
                      >
                        Remove Field
                      </button>
                    </div>
                  ))}
                </div>

                <div className="settings-section-title">
                  <div>
                    <h3>3. Category-Local Synonym Groups</h3>
                    <p>
                      One synonym group per line (comma-separated equivalent terms). Each
                      term may belong to only one group.
                    </p>
                  </div>
                  <span className="badge badge-info">
                    {synonymDiagnostics.groups.length} valid groups
                  </span>
                </div>
                <label className="setting-field wide">
                  <span>Synonym Groups (one group per line)</span>
                  <textarea
                    className="platform-json-input"
                    rows={5}
                    value={synonymText}
                    onChange={(e) => setSynonymText(e.target.value)}
                    placeholder={
                      "developer, software developer, software engineer, programmer\nbackend, server side\nmachine learning, ml\nbangalore, bengaluru"
                    }
                  />
                  {synonymDiagnostics.overlaps.length > 0 ? (
                    <small style={{ color: "var(--danger)", fontWeight: 600 }}>
                      ⚠ Overlap detected: {synonymDiagnostics.overlaps.join(" · ")}
                    </small>
                  ) : (
                    <small>
                      Configured synonyms expand lexical queries and score as unified
                      BM25F concepts with length normalization.
                    </small>
                  )}
                </label>

                <div className="settings-section-title">
                  <div>
                    <h3>4. Retrieval, Fusion &amp; Access Rules</h3>
                    <p>
                      Configure BM25F lexical and FAISS semantic retrieval weights and
                      privacy controls.
                    </p>
                  </div>
                </div>
                <div className="platform-form-grid">
                  <label className="setting-field">
                    <span>Minimum Semantic Score (0–100)</span>
                    <input
                      type="number"
                      min="0"
                      max="100"
                      step="0.5"
                      value={minScore}
                      onChange={(e) => setMinScore(Number(e.target.value))}
                    />
                  </label>
                  <label className="setting-field">
                    <span>Semantic High-Confidence Base (0–100)</span>
                    <input
                      type="number"
                      min="0"
                      max="100"
                      step="0.5"
                      value={highConfidenceScore}
                      onChange={(e) => setHighConfidenceScore(Number(e.target.value))}
                    />
                    <small>
                      No-overlap semantic candidates require score ≥ max(90, base + 10).
                    </small>
                  </label>
                  <label className="setting-field">
                    <span>Semantic Candidate Limit (1–200)</span>
                    <input
                      type="number"
                      min="1"
                      max="200"
                      value={candidateLimit}
                      onChange={(e) => setCandidateLimit(Number(e.target.value))}
                    />
                  </label>
                  <label className="setting-field">
                    <span>Lexical RRF Weight (0–1)</span>
                    <input
                      type="number"
                      min="0"
                      max="1"
                      step="0.05"
                      value={lexicalWeight}
                      onChange={(e) => setLexicalWeight(Number(e.target.value))}
                    />
                  </label>
                  <label className="setting-field">
                    <span>Semantic RRF Weight (0–1)</span>
                    <input
                      type="number"
                      min="0"
                      max="1"
                      step="0.05"
                      value={semanticWeight}
                      onChange={(e) => setSemanticWeight(Number(e.target.value))}
                    />
                  </label>
                  <div className="setting-field">
                    <span>Engine Flags</span>
                    <label className="platform-checkbox">
                      <input
                        type="checkbox"
                        checked={engineActive}
                        onChange={(e) => setEngineActive(e.target.checked)}
                      />
                      Engine Active
                    </label>
                    <label className="platform-checkbox">
                      <input
                        type="checkbox"
                        checked={lexicalEnabled}
                        onChange={(e) => setLexicalEnabled(e.target.checked)}
                      />
                      Enable BM25F Lexical Retrieval
                    </label>
                    <label className="platform-checkbox">
                      <input
                        type="checkbox"
                        checked={semanticEnabled}
                        onChange={(e) => setSemanticEnabled(e.target.checked)}
                      />
                      Enable FAISS Semantic Retrieval
                    </label>
                    <label className="platform-checkbox">
                      <input
                        type="checkbox"
                        checked={publicEnabled}
                        onChange={(e) => setPublicEnabled(e.target.checked)}
                      />
                      Allow Unauthenticated Public Search (Keep OFF for People)
                    </label>
                  </div>
                  <label className="setting-field wide">
                    <span>Change Reason (Audit Log)</span>
                    <input
                      value={changeReason}
                      onChange={(e) => setChangeReason(e.target.value)}
                      maxLength={1000}
                      placeholder="Document why this configuration change is being saved"
                    />
                  </label>
                </div>

                <div className="settings-actions">
                  <span className="action-spacer" />
                  {editingVersion !== null && (
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={() => {
                        setShowEditorForm(false);
                        setEditingVersion(null);
                      }}
                    >
                      Cancel
                    </button>
                  )}
                  <button
                    type="submit"
                    className="primary-button"
                    disabled={
                      saving ||
                      fields.length === 0 ||
                      synonymDiagnostics.overlaps.length > 0 ||
                      (sourceType === "sqlserver" && !connectionEnv)
                    }
                  >
                    {saving
                      ? "Saving…"
                      : editingVersion === null
                        ? "Create Search Engine"
                        : `Save Configuration (v${editingVersion} → v${editingVersion + 1})`}
                  </button>
                </div>
              </form>

              {sourceType === "push" && editingVersion !== null && (
                <div className="platform-history" style={{ marginTop: 24 }}>
                  <div className="settings-section-title">
                    <div>
                      <h3>Push Document Ingestion ({categoryId})</h3>
                      <p>
                        Replace indexed documents for this push-backed engine via{" "}
                        <code>POST /api/admin/platform/categories/{categoryId}/ingest</code>.
                      </p>
                    </div>
                  </div>
                  <form onSubmit={(event) => void ingest(event)}>
                    <label className="setting-field">
                      <span>Push Normalized Documents (JSON Array)</span>
                      <textarea
                        className="platform-json-input"
                        rows={7}
                        value={rawDocuments}
                        onChange={(e) => setRawDocuments(e.target.value)}
                        spellCheck={false}
                      />
                    </label>
                    <div className="settings-actions">
                      <span className="action-spacer" />
                      <button type="submit" className="primary-button" disabled={ingesting}>
                        {ingesting ? "Ingesting…" : "Replace Category Documents"}
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {categoryHistory.length > 0 && (
                <div className="platform-history" style={{ marginTop: 24 }}>
                  <div className="settings-section-title">
                    <div>
                      <h3>Configuration Version History ({categoryId})</h3>
                      <p>
                        Immutable audit trail stored in{" "}
                        <code>searchai.SearchCategoryHistory</code>.
                      </p>
                    </div>
                  </div>
                  {categoryHistory.map((item) => {
                    const isCurrentVersion = editingVersion === item.config_version;
                    return (
                      <article className="platform-history-item" key={item.history_id}>
                        <strong>v{item.config_version}</strong>
                        <div>
                          <span>
                            {item.changed_by || "admin"} ·{" "}
                            <span className="badge badge-info">{item.status}</span>
                            {item.rolled_back_from_version ? (
                              <>
                                {" "}
                                ·{" "}
                                <span className="badge badge-warn">
                                  Rolled back from v{item.rolled_back_from_version}
                                </span>
                              </>
                            ) : null}{" "}
                            · {formatDate(item.changed_at_utc)}
                          </span>
                          <small style={{ display: "block", marginTop: 4 }}>
                            {item.change_reason || "No change reason provided"}
                          </small>
                        </div>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <button
                            type="button"
                            className="secondary-button"
                            onClick={() => {
                              setFields(item.config.fields.map(normalizeLoadedFieldConfig));
                              setSynonymText(
                                (item.config.synonyms || [])
                                  .map((g) => g.terms.join(", "))
                                  .join("\n"),
                              );
                              setChangeReason(
                                `Restored field/synonym settings from config v${item.config_version}`,
                              );
                              setNotice(
                                `Loaded fields and synonyms from v${item.config_version} into the editor draft. Click Save Configuration to persist as a new version.`,
                              );
                            }}
                          >
                            Load into Draft
                          </button>
                          <button
                            type="button"
                            className="secondary-button"
                            disabled={
                              isCurrentVersion ||
                              editingVersion === null ||
                              rollingBackVersion !== null
                            }
                            onClick={() => startRollbackForVersion(item)}
                          >
                            {rollingBackVersion === item.config_version
                              ? "Rolling back…"
                              : isCurrentVersion
                                ? "Active Version"
                                : `Rollback to v${item.config_version}`}
                          </button>
                        </div>
                      </article>
                    );
                  })}
                  {pendingRollbackItem && editingVersion !== null && (
                    <div
                      className="rollback-confirm-box"
                      role="region"
                      aria-label="Confirm Configuration Rollback"
                    >
                      <div>
                        <strong>
                          Confirm rollback of <code>{categoryId}</code> from v{editingVersion}{" "}
                          to v{pendingRollbackItem.config_version}
                        </strong>
                        <p className="panel-intro" style={{ marginTop: 4, marginBottom: 10 }}>
                          Restores stored snapshot v{pendingRollbackItem.config_version} as a
                          new configuration version (v{editingVersion + 1}), preserves all
                          history, and invalidates this category&apos;s worker cache via an
                          authenticated Admin request.
                        </p>
                      </div>
                      <label className="setting-field">
                        <span>Audit Reason (Required)</span>
                        <input
                          type="text"
                          value={rollbackReasonInput}
                          maxLength={900}
                          onChange={(e) => setRollbackReasonInput(e.target.value)}
                          placeholder="Document why this version is being restored"
                          disabled={rollingBackVersion !== null}
                        />
                      </label>
                      <div className="settings-actions" style={{ marginTop: 10 }}>
                        <span className="action-spacer" />
                        <button
                          type="button"
                          className="secondary-button"
                          disabled={rollingBackVersion !== null}
                          onClick={() => {
                            setPendingRollbackItem(null);
                            setRollbackReasonInput("");
                          }}
                        >
                          Cancel
                        </button>
                        <button
                          type="button"
                          className="primary-button"
                          disabled={
                            rollingBackVersion !== null || !rollbackReasonInput.trim()
                          }
                          onClick={() => void confirmRollbackToHistoryVersion()}
                        >
                          {rollingBackVersion !== null
                            ? "Rolling back…"
                            : `Confirm Rollback to v${pendingRollbackItem.config_version}`}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </section>
          )}
        </>
      )}

      {showTestingSection && (
        <section className="panel platform-test-panel">
          <div className="panel-title-row">
            <div>
              <span className="section-kicker">GENERAL SEARCH PLATFORM · ENGINE TESTING</span>
              <h2>Generic Search Engine Testing</h2>
            </div>
            <span className="method-badge">POST · /api/admin/platform/search</span>
          </div>
          <p className="panel-intro">
            Select any configured search engine, execute generic queries with optional typed
            field filters, and inspect the deterministic query plan, BM25F lexical scores,
            FAISS semantic scores, RRF fusion signals, and engine version metadata.
          </p>

          <div className="platform-form-grid">
            <label className="setting-field">
              <span>Target Search Engine</span>
              <select
                value={selectedCategory}
                onChange={(e) => {
                  selectEngine(e.target.value, {
                    notifyParent: true,
                    clearNotices: true,
                    resetTesting: true,
                  });
                }}
              >
                <option value="">Select a configured search engine</option>
                {categories.map((item) => (
                  <option key={item.config.category_id} value={item.config.category_id}>
                    {item.config.display_name} ({item.config.category_id} ·{" "}
                    {(item.document_count ?? 0).toLocaleString()} docs · cfg v
                    {item.config_version} / idx v{item.index_version})
                  </option>
                ))}
              </select>
            </label>
            <div className="setting-field">
              <span>Selected Engine Metadata &amp; Access Scope</span>
              <small>
                {selectedRecord ? (
                  <>
                    <strong>{selectedRecord.config.display_name}</strong>{" "}
                    <code className="code-pill">{selectedRecord.config.category_id}</code>
                    {" · "}
                    <strong>{selectedRecord.config.source.type.toUpperCase()}</strong>
                    {selectedRecord.config.source.type === "sqlserver"
                      ? ` · [${selectedRecord.config.source.schema}].[${selectedRecord.config.source.table}]`
                      : " · Push Ingestion API"}{" "}
                    · cfg v{selectedRecord.config_version} / idx v
                    {selectedRecord.index_version} ·{" "}
                    {selectedRecord.config.public_search_enabled
                      ? "Public Search Enabled"
                      : "Admin-Only (Public 403 Protected)"}
                  </>
                ) : (
                  "Select a configured search engine above to inspect its schema and run test queries."
                )}
              </small>
            </div>
          </div>

          {selectedRecord?.config.source.type === "push" && (
            <form onSubmit={(event) => void ingest(event)} style={{ marginTop: 14 }}>
              <label className="setting-field">
                <span>Push Normalized Documents (JSON Array)</span>
                <textarea
                  className="platform-json-input"
                  rows={7}
                  value={rawDocuments}
                  onChange={(e) => setRawDocuments(e.target.value)}
                  spellCheck={false}
                />
              </label>
              <div className="settings-actions">
                <span className="action-spacer" />
                <button type="submit" className="primary-button" disabled={ingesting}>
                  {ingesting ? "Ingesting…" : "Replace Category Documents"}
                </button>
              </div>
            </form>
          )}

          <form onSubmit={(event) => void runTestSearch(event)} style={{ marginTop: 14 }}>
            <div className="platform-form-grid">
              <label className="setting-field wide">
                <span>Search Query</span>
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  required
                  placeholder="Enter a search query or exact document ID for the selected engine…"
                />
              </label>
            </div>

            {selectedRecord && (
              <div className="settings-section-title" style={{ marginTop: 14 }}>
                <div>
                  <h3>Optional Typed Result Filters</h3>
                  <p>
                    Filterable fields configured on{" "}
                    <strong>{selectedRecord.config.display_name}</strong>:{" "}
                    {selectedRecord.config.fields
                      .filter((f) => f.filterable)
                      .map((f) => `${f.key} (${f.data_type || "text"})`)
                      .join(", ") || "None"}
                  </p>
                </div>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={addSearchFilter}
                >
                  + Add Result Filter
                </button>
              </div>
            )}

            {searchFilters.map((filter, index) => {
              const filterableFields =
                selectedRecord?.config.fields.filter((field) => field.filterable) ?? [];
              const selectedField =
                filterableFields.find((field) => field.key === filter.field) ??
                filterableFields[0];
              const type = selectedField?.data_type || "text";
              const operators =
                type === "text" || type === "keyword"
                  ? ["eq", "ne", "in", "contains", "is_null", "not_null"]
                  : type === "boolean"
                    ? ["eq", "ne", "in", "is_null", "not_null"]
                    : [
                        "eq",
                        "ne",
                        "in",
                        "gte",
                        "lte",
                        "between",
                        "is_null",
                        "not_null",
                      ];
              return (
                <div className="platform-filter-row" key={index}>
                  <label className="setting-field">
                    <span>Filterable Field</span>
                    <select
                      value={filter.field}
                      onChange={(e) =>
                        updateSearchFilter(index, {
                          field: e.target.value,
                          operator: "eq",
                          value: "",
                          values: [],
                        })
                      }
                    >
                      {filterableFields.map((field) => (
                        <option key={field.key} value={field.key}>
                          {field.label} ({field.key} · {field.data_type || "text"})
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="setting-field">
                    <span>Operator</span>
                    <select
                      value={filter.operator}
                      onChange={(e) =>
                        updateSearchFilter(index, {
                          operator: e.target.value as PlatformSearchFilter["operator"],
                          value: "",
                          values: [],
                        })
                      }
                    >
                      {operators.map((operator) => (
                        <option key={operator} value={operator}>
                          {operator}
                        </option>
                      ))}
                    </select>
                  </label>
                  {filter.operator !== "is_null" && filter.operator !== "not_null" ? (
                    <label className="setting-field">
                      <span>
                        {filter.operator === "between"
                          ? "Lower, upper values"
                          : filter.operator === "in"
                            ? "Comma-separated values"
                            : "Filter Value"}
                      </span>
                      <input
                        value={
                          filter.operator === "in" || filter.operator === "between"
                            ? (filter.values || []).join(", ")
                            : String(filter.value ?? "")
                        }
                        onChange={(e) => {
                          if (filter.operator === "in" || filter.operator === "between") {
                            updateSearchFilter(index, {
                              values: e.target.value
                                .split(",")
                                .map((value) => value.trim())
                                .filter(Boolean),
                            });
                          } else {
                            updateSearchFilter(index, { value: e.target.value });
                          }
                        }}
                        placeholder={
                          type === "boolean"
                            ? "true or false"
                            : type === "date"
                              ? "YYYY-MM-DD"
                              : "Enter value"
                        }
                      />
                    </label>
                  ) : (
                    <div className="setting-field">
                      <span>Value</span>
                      <small>No value required</small>
                    </div>
                  )}
                  <button
                    type="button"
                    className="secondary-button danger-button"
                    onClick={() =>
                      setSearchFilters((current) => current.filter((_, i) => i !== index))
                    }
                  >
                    Remove
                  </button>
                </div>
              );
            })}

            <div className="settings-actions">
              <label className="control-field" style={{ width: 150 }}>
                <select
                  value={testPageSize}
                  onChange={(e) => setTestPageSize(Number(e.target.value))}
                >
                  <option value={10}>10 per page</option>
                  <option value={20}>20 per page</option>
                  <option value={50}>50 per page</option>
                </select>
              </label>
              <span className="action-spacer" />
              <button
                type="submit"
                className="primary-button"
                disabled={!selectedCategory || searching}
              >
                {searching ? "Searching…" : "⌕ Execute Engine Search"}
              </button>
            </div>
          </form>

          {activeSearchResult && (
            <PlatformSearchResults
              key={selectedCategory}
              searchResult={activeSearchResult}
              selectedRecord={selectedRecord}
              searchDurationMs={searchDurationMs}
              showQueryPlanJson={showQueryPlanJson}
              onToggleQueryPlanJson={() => setShowQueryPlanJson((v) => !v)}
              expandedDocRawIds={expandedDocRawIds}
              onToggleDocRawJson={(docId) =>
                setExpandedDocRawIds((prev) => ({
                  ...prev,
                  [docId]: !prev[docId],
                }))
              }
              testPage={testPage}
              totalTestPages={totalTestPages}
              searching={searching}
              onPageChange={(nextPage) => void executeTestSearch(nextPage)}
            />
          )}
        </section>
      )}

      {showFeedbackSection && (
        <section className="panel platform-test-panel">
          <div className="panel-title-row">
            <div>
              <span className="section-kicker">RELEVANCE FEEDBACK &amp; EVALUATION LOG</span>
              <h2>Human Relevance Judgments &amp; Audit Trail</h2>
            </div>
            <button
              type="button"
              className="secondary-button"
              onClick={() => void loadAllCategoriesFeedback(categories)}
            >
              ↻ Refresh Feedback
            </button>
          </div>
          <p className="panel-intro">
            Relevance feedback is stored in <code>searchai.SearchFeedback</code> with
            configuration and index version metadata for offline IR evaluation
            (Precision@K, Recall@K, MRR@K, MAP@K, nDCG@K). Remember: feedback records do
            not automatically fine-tune the pretrained <code>all-MiniLM-L6-v2</code>{" "}
            embedding model.
          </p>

          <div className="engine-kpi-row" style={{ marginBottom: 16 }}>
            <div className="engine-kpi">
              <span>Total Judgments</span>
              <strong>{feedbackTotals.total}</strong>
            </div>
            <div className="engine-kpi">
              <span>Relevant Labels</span>
              <strong style={{ color: "var(--ok)" }}>{feedbackTotals.relevant}</strong>
            </div>
            <div className="engine-kpi">
              <span>Not Relevant Labels</span>
              <strong style={{ color: "var(--danger)" }}>
                {feedbackTotals.notRelevant}
              </strong>
            </div>
            <div className="engine-kpi">
              <span>Distinct Evaluated Queries</span>
              <strong>{feedbackTotals.distinctQueries}</strong>
            </div>
          </div>

          <div className="platform-form-grid" style={{ marginBottom: 16 }}>
            <label className="setting-field">
              <span>Filter by Search Engine</span>
              <select
                value={feedbackFilterCategory}
                onChange={(e) => setFeedbackFilterCategory(e.target.value)}
              >
                <option value="all">All Search Engines</option>
                {categories.map((c) => (
                  <option key={c.config.category_id} value={c.config.category_id}>
                    {c.config.display_name} ({c.config.category_id})
                  </option>
                ))}
              </select>
            </label>
            <label className="setting-field">
              <span>Filter by Verdict</span>
              <select
                value={feedbackFilterVerdict}
                onChange={(e) =>
                  setFeedbackFilterVerdict(
                    e.target.value as "all" | "relevant" | "not_relevant",
                  )
                }
              >
                <option value="all">All Verdicts</option>
                <option value="relevant">Relevant Only</option>
                <option value="not_relevant">Not Relevant Only</option>
              </select>
            </label>
            <label className="setting-field wide">
              <span>Search by Query Text or Document ID</span>
              <input
                value={feedbackFilterQuery}
                onChange={(e) => setFeedbackFilterQuery(e.target.value)}
                placeholder="Filter feedback by query or document UUID…"
              />
            </label>
          </div>

          {combinedFeedbackItems.length === 0 ? (
            <p className="panel-intro">
              No relevance feedback records match the current filter.
            </p>
          ) : (
            <div className="table-scroll-wrap">
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Engine</th>
                    <th>Verdict</th>
                    <th>Query</th>
                    <th>Document ID</th>
                    <th>Rank / Score</th>
                    <th>Version</th>
                    <th>Comment &amp; Actor</th>
                  </tr>
                </thead>
                <tbody>
                  {combinedFeedbackItems.map((item) => (
                    <tr key={`${item.category_id}-${item.feedback_id}`}>
                      <td>#{item.feedback_id}</td>
                      <td>
                        <code>{item.category_id}</code>
                      </td>
                      <td>
                        <span
                          className={`badge ${item.is_relevant ? "badge-ok" : "badge-danger"}`}
                        >
                          {item.is_relevant ? "Relevant" : "Not Relevant"}
                        </span>
                      </td>
                      <td>
                        <strong>{item.query}</strong>
                      </td>
                      <td>
                        <code className="doc-id-code">{item.document_id}</code>
                      </td>
                      <td>
                        {item.result_rank ? `#${item.result_rank}` : "—"}
                        {item.result_score !== null && item.result_score !== undefined
                          ? ` (${item.result_score.toFixed(1)} pts)`
                          : ""}
                      </td>
                      <td>
                        cfg v{item.config_version ?? "—"} · idx v
                        {item.index_version ?? "—"}
                      </td>
                      <td>
                        {item.comment ? <div>{item.comment}</div> : null}
                        <small>
                          {item.created_by || "admin"} · {formatDate(item.created_at_utc)}
                        </small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {feedbackSummary && mode === "all" && (
            <small className="settings-footnote">
              Showing {combinedFeedbackItems.length} judgment records across configured
              engines.
            </small>
          )}
        </section>
      )}
    </div>
  );
}
