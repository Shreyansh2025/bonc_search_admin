import type {
  PlatformCategoryRecord,
  PlatformSearchFilter,
  PlatformSearchResponse,
} from "./search-api.ts";

export interface EngineTestingContextState {
  selectedCategory: string;
  searchFilters: PlatformSearchFilter[];
  searchResult: PlatformSearchResponse | null;
  searchDurationMs: number | null;
  searching: boolean;
  testPage: number;
  showQueryPlanJson: boolean;
  expandedDocRawIds: Record<string, boolean>;
}

export function createInitialTestingContext(
  initialCategoryId = "",
): EngineTestingContextState {
  return {
    selectedCategory: initialCategoryId,
    searchFilters: [],
    searchResult: null,
    searchDurationMs: null,
    searching: false,
    testPage: 1,
    showQueryPlanJson: false,
    expandedDocRawIds: {},
  };
}

/**
 * Produce a clean engine-testing context when switching to another search engine.
 * Clears previous engine-specific filters, results, latency, pagination, and raw-JSON
 * inspection state so no data from the previous engine leaks into the newly selected engine.
 */
export function transitionTestingEngine(
  _previous: EngineTestingContextState,
  nextCategoryId: string,
): EngineTestingContextState {
  return createInitialTestingContext(nextCategoryId);
}

/**
 * Look up the active engine's full configuration record from the loaded category registry.
 */
export function resolveSelectedEngineRecord(
  categories: PlatformCategoryRecord[],
  selectedCategoryId: string,
): PlatformCategoryRecord | null {
  if (!selectedCategoryId) return null;
  return (
    categories.find((item) => item.config.category_id === selectedCategoryId) ?? null
  );
}

/**
 * Determine which engine should remain selected after loading or refreshing the registry.
 * An existing valid selection always takes precedence over `initialCategoryId` so
 * background/manual refreshes cannot snap the dropdown back to an older initial engine.
 */
export function resolveCategoryAfterRefresh(params: {
  categories: PlatformCategoryRecord[];
  currentSelectedCategory: string;
  initialCategoryId?: string;
  userClearedSelection?: boolean;
}): string {
  const hasCategory = (id: string | undefined): id is string =>
    Boolean(id && params.categories.some((item) => item.config.category_id === id));

  if (hasCategory(params.currentSelectedCategory)) {
    return params.currentSelectedCategory;
  }
  if (params.userClearedSelection && params.currentSelectedCategory === "") {
    return "";
  }
  if (hasCategory(params.initialCategoryId)) {
    return params.initialCategoryId;
  }
  return params.categories[0]?.config.category_id || "";
}

/**
 * Guard that guarantees rendered search results strictly belong to the active engine.
 */
export function isSearchResultForActiveEngine(
  searchResult: PlatformSearchResponse | null,
  activeCategoryId: string,
): searchResult is PlatformSearchResponse {
  if (!searchResult || !activeCategoryId) return false;
  return (
    searchResult.category.trim().toLowerCase() ===
    activeCategoryId.trim().toLowerCase()
  );
}

export function isAbortError(error: unknown): boolean {
  return (
    (typeof DOMException !== "undefined" &&
      error instanceof DOMException &&
      error.name === "AbortError") ||
    (error instanceof Error && error.name === "AbortError")
  );
}

export interface ScopedRequestToken {
  readonly requestId: number;
  readonly categoryId: string;
  readonly signal: AbortSignal;
}

/**
 * Coordinates engine-scoped async requests (search, history, feedback), aborting
 * superseded in-flight requests and rejecting stale responses or errors from a
 * previously selected engine even if a transport resolves late.
 */
export class EngineRequestCoordinator {
  private seq = 0;
  private activeCategoryId: string;
  private activeController: AbortController | null = null;

  constructor(initialCategoryId = "") {
    this.activeCategoryId = initialCategoryId;
  }

  getActiveCategory(): string {
    return this.activeCategoryId;
  }

  setActiveCategory(categoryId: string): void {
    if (categoryId !== this.activeCategoryId) {
      this.invalidate();
      this.activeCategoryId = categoryId;
    }
  }

  invalidate(): void {
    this.seq += 1;
    if (this.activeController) {
      this.activeController.abort();
      this.activeController = null;
    }
  }

  begin(categoryId: string): ScopedRequestToken {
    this.invalidate();
    this.activeCategoryId = categoryId;
    const controller = new AbortController();
    this.activeController = controller;
    return {
      requestId: this.seq,
      categoryId,
      signal: controller.signal,
    };
  }

  isCurrent(token: ScopedRequestToken): boolean {
    return (
      token.requestId === this.seq &&
      !token.signal.aborted &&
      token.categoryId === this.activeCategoryId
    );
  }
}
