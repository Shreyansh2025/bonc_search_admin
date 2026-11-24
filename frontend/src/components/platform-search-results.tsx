import type {
  PlatformCategoryRecord,
  PlatformSearchResponse,
} from "../lib/search-api";
import { buildResultFieldEntries } from "../lib/search-result-format";

export interface PlatformSearchResultsProps {
  searchResult: PlatformSearchResponse;
  selectedRecord?: PlatformCategoryRecord | null;
  searchDurationMs: number | null;
  showQueryPlanJson: boolean;
  onToggleQueryPlanJson: () => void;
  expandedDocRawIds: Record<string, boolean>;
  onToggleDocRawJson: (docId: string) => void;
  testPage: number;
  totalTestPages: number;
  searching: boolean;
  onPageChange: (page: number) => void;
}

function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export default function PlatformSearchResults({
  searchResult,
  selectedRecord,
  searchDurationMs,
  showQueryPlanJson,
  onToggleQueryPlanJson,
  expandedDocRawIds,
  onToggleDocRawJson,
  testPage,
  totalTestPages,
  searching,
  onPageChange,
}: PlatformSearchResultsProps) {
  const configuredFields = selectedRecord?.config.fields;

  return (
    <div className="platform-results">
      <div className="platform-result-summary">
        <div className="platform-result-summary-meta">
          <strong>
            {searchResult.total_count.toLocaleString()}{" "}
            {searchResult.total_count === 1 ? "match" : "matches"}
          </strong>
          <span className="platform-result-summary-detail">
            in <code className="code-pill">{searchResult.category}</code>
            {selectedRecord ? ` (${selectedRecord.config.display_name})` : ""}
            {" · "}config v{searchResult.config_version}
            {" · "}index v{searchResult.index_version}
            {searchDurationMs !== null ? ` · ${searchDurationMs} ms` : ""}
          </span>
        </div>
        <button
          type="button"
          className="secondary-button"
          aria-expanded={showQueryPlanJson}
          onClick={onToggleQueryPlanJson}
        >
          {showQueryPlanJson ? "Hide Plan JSON" : "Inspect Raw Query Plan"}
        </button>
      </div>

      <div className="query-plan-box">
        <div className="query-plan-header">
          <strong>Query Understanding &amp; Execution Plan</strong>
          <span
            className={`badge ${searchResult.query_plan.query_type === "field_guided" ? "badge-ok" : "badge-info"}`}
          >
            {searchResult.query_plan.query_type}
          </span>
        </div>
        <p className="query-plan-explanation">
          {searchResult.query_plan.explanation}
        </p>
        <div className="query-plan-grid">
          <div className="query-plan-cell">
            <span>Normalised Query</span>
            <code>{searchResult.query_understanding.normalised_query}</code>
          </div>
          <div className="query-plan-cell">
            <span>Lexical Query</span>
            <code>{searchResult.query_plan.lexical_query}</code>
          </div>
          <div className="query-plan-cell">
            <span>Expanded Lexical Query</span>
            <code>{searchResult.query_plan.expanded_lexical_query}</code>
          </div>
          <div className="query-plan-cell">
            <span>Candidates &amp; Eligibility</span>
            <code>
              eligible: {searchResult.query_plan.eligible_document_count ?? "—"} · lex:{" "}
              {searchResult.query_plan.lexical_candidates ?? "—"} · sem kept:{" "}
              {searchResult.query_plan.semantic_candidates_kept ?? "—"} (rejected:{" "}
              {searchResult.query_plan.semantic_candidates_rejected ?? 0})
            </code>
          </div>
        </div>

        {Object.keys(searchResult.query_plan.matched_aliases || {}).length > 0 && (
          <div className="query-plan-tags">
            <span>Matched Aliases:</span>
            {Object.entries(searchResult.query_plan.matched_aliases).map(
              ([field, aliases]) => (
                <span className="badge badge-info" key={field}>
                  {field}: {aliases.join(", ")}
                </span>
              ),
            )}
          </div>
        )}
        {Object.keys(searchResult.query_plan.matched_values || {}).length > 0 && (
          <div className="query-plan-tags">
            <span>Recognized Field Values:</span>
            {Object.entries(searchResult.query_plan.matched_values).map(
              ([field, vals]) => (
                <span className="badge badge-ok" key={field}>
                  {field}: {vals.join(", ")}
                </span>
              ),
            )}
          </div>
        )}
        {(searchResult.query_plan.synonym_expansions || []).length > 0 && (
          <div className="query-plan-tags">
            <span>Synonym Expansions:</span>
            {searchResult.query_plan.synonym_expansions.map((exp) => (
              <span className="badge badge-warn" key={exp.matched_term}>
                {exp.matched_term} → {exp.alternatives.join(", ")}
              </span>
            ))}
          </div>
        )}
        {showQueryPlanJson && (
          <pre className="raw-json">{pretty(searchResult.query_plan)}</pre>
        )}
      </div>

      {searchResult.data.length > 0 ? (
        <div className="platform-result-list" role="list" aria-label="Search Results">
          {searchResult.data.map((item, idx) => {
            const rank = (searchResult.page - 1) * searchResult.page_size + idx + 1;
            const sig = item.ranking_signals;
            const showRawDoc = Boolean(expandedDocRawIds[item.id]);
            const fieldEntries = buildResultFieldEntries(
              item.fields,
              configuredFields,
              item.matched_fields,
            );

            return (
              <article
                className="platform-result-item"
                key={item.id}
                role="listitem"
              >
                <div className="platform-result-body">
                  <div className="platform-result-top">
                    <div className="platform-result-header">
                      <span className="rank-badge" aria-label={`Rank ${rank}`}>
                        #{rank}
                      </span>
                      <div className="platform-result-title-group">
                        <h3 className="platform-result-title">
                          {item.title || "(Untitled Document)"}
                        </h3>
                        <div className="platform-result-id-row">
                          <span className="doc-id-label">Document ID</span>
                          <code className="doc-id-code">{item.id}</code>
                        </div>
                      </div>
                    </div>

                    <div className="platform-score-col" aria-label={`Final Score ${item.score.toFixed(1)}`}>
                      <strong className="platform-score-value">
                        {item.score.toFixed(1)}
                      </strong>
                      <span className="platform-score-label">Final Score</span>
                    </div>
                  </div>

                  <div className="platform-diagnostics">
                    <div className="signal-pills-row">
                      <span className="badge badge-info">
                        Matched Fields:{" "}
                        {item.exact_identifier_match
                          ? "document_id (Exact ID)"
                          : item.matched_fields.join(", ") || "Semantic Only"}
                      </span>
                      <span className="badge badge-muted">
                        Lexical: {item.lexical_score.toFixed(1)} pts (rank #
                        {sig?.lexical_rank ?? "—"})
                      </span>
                      <span className="badge badge-muted">
                        Semantic: {item.semantic_score.toFixed(1)} pts (rank #
                        {sig?.semantic_rank ?? "—"})
                      </span>
                      {sig && (
                        <>
                          <span className="badge badge-muted">
                            BM25F Raw: {sig.bm25f_raw.toFixed(2)}
                          </span>
                          <span className="badge badge-muted">
                            Coverage: {(sig.query_term_coverage * 100).toFixed(0)}%
                          </span>
                          <span className="badge badge-muted">
                            Fused RRF: {sig.rank_fusion_score.toFixed(1)}
                          </span>
                        </>
                      )}
                      {item.preferred_filter_bonus ? (
                        <span className="badge badge-ok">
                          Constraint Boost: +{item.preferred_filter_bonus.toFixed(1)}
                        </span>
                      ) : null}
                    </div>

                    {sig &&
                      (sig.matched_terms.length > 0 || sig.missing_terms.length > 0) && (
                        <div className="term-evidence-row">
                          <span className="term-evidence-label">Term Evidence</span>
                          {sig.matched_terms.map((t) => (
                            <span className="badge badge-ok" key={`m-${t}`}>
                              ✓ {t}
                            </span>
                          ))}
                          {sig.missing_terms.map((t) => (
                            <span className="badge badge-warn" key={`x-${t}`}>
                              ✗ missing: {t}
                            </span>
                          ))}
                        </div>
                      )}
                  </div>

                  {fieldEntries.length > 0 ? (
                    <dl className="doc-fields-grid">
                      {fieldEntries.map((entry) => (
                        <div
                          className={`doc-field-cell${entry.isWide ? " doc-field-cell-wide" : ""}${entry.isMatched ? " doc-field-cell-matched" : ""}`}
                          key={entry.key}
                        >
                          <dt className="doc-field-key" title={entry.key}>
                            <span>{entry.label}</span>
                            {entry.isMatched && (
                              <span className="doc-field-match-tag">Matched</span>
                            )}
                          </dt>
                          <dd className="doc-field-val">{entry.value}</dd>
                        </div>
                      ))}
                    </dl>
                  ) : (
                    <div className="doc-fields-empty">
                      No displayable document fields returned for this result.
                    </div>
                  )}

                  <div className="platform-feedback-actions">
                    <span className="platform-result-engine-meta">
                      Engine: <code className="code-pill">{item.category}</code>
                    </span>
                    <button
                      type="button"
                      className="secondary-button platform-raw-toggle-btn"
                      aria-expanded={showRawDoc}
                      onClick={() => onToggleDocRawJson(item.id)}
                    >
                      {showRawDoc ? "Hide Raw JSON" : "Raw JSON"}
                    </button>
                  </div>

                  {showRawDoc && <pre className="raw-json">{pretty(item)}</pre>}
                </div>
              </article>
            );
          })}
        </div>
      ) : (
        <div className="empty-state compact">
          <h3>No Matching Documents</h3>
          <p>No matching documents returned for this query and filter combination.</p>
        </div>
      )}

      {totalTestPages > 1 && (
        <div className="results-footer">
          <span>
            Page {testPage} of {totalTestPages} (
            {searchResult.total_count.toLocaleString()} total matches)
          </span>
          <div className="pagination-controls">
            <button
              type="button"
              className="secondary-button"
              disabled={testPage <= 1 || searching}
              onClick={() => onPageChange(testPage - 1)}
            >
              ← Previous
            </button>
            <button
              type="button"
              className="secondary-button"
              disabled={testPage >= totalTestPages || searching}
              onClick={() => onPageChange(testPage + 1)}
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
