# Curated supplement batch registry

This registry records the semantic review decision for supplemental batches.
Only rows marked `APPROVED` may be included by the canonical dataset builder.
Model-sample counts refer to rows produced for CodeBERT; an accepted function
pair normally produces one vulnerable `before` row and one safe `after` row.

| CWE | Batch | Decision | Selected function pairs | Expected model samples | Reason |
| --- | --- | --- | ---: | ---: | --- |
| CWE-22 | New batch | MONITOR | 0 | 0 | The canonical dataset already has 124 samples. Add only a new repository or a materially new path-traversal source/sink pattern. |
| CWE-78 | Pillow CVE-2026-55798 | APPROVED | 1 | 2 | Windows-specific `shell=True` command injection; direct before/after fix. |
| CWE-78 | Modoboa CVE-2026-27602 | APPROVED | 1 | 2 | `exec_cmd` directly changes the unsafe `shell=True` default. |
| CWE-78 | MLflow CVE-2026-0596 | APPROVED | 1 | 2 | `get_cmd` changes unquoted `model_uri` interpolation in an MLServer shell command to `shlex.quote(model_uri)`; production Python pair fits CodeBERT. |
| CWE-78 | OctoPrint CVE-2025-58180 | APPROVED | 1 | 2 | Keep only `sanitize_filename`; redundant overlapping patch context is excluded so the batch has one vulnerable and one safe chunk. |
| CWE-78 | CAI CVE-2026-25130 | HOLD | 0 | 0 | The patch uses a denylist while retaining `shell=True`; the fixed sample is not strong enough for a `SAFE` label. |
| CWE-79 | New batch | MONITOR | 0 | 0 | The canonical dataset already has 156 samples. Prioritize repository diversity instead of adding more similar template-escaping examples. |
| CWE-89 | SciTokens CVE-2026-32714 | APPROVED | 2 | 4 | Two distinct SQLite sinks replace string formatting with parameter binding. |
| CWE-89 | Parsl CVE-2026-21892 | APPROVED | 2 | 4 | Two production visualization routes replace interpolated workflow IDs with bound SQL parameters; patch-aware chunks contain the source and sink. |
| CWE-89 | WsgiDAV CVE-2026-55509 | REJECTED | 0 | 0 | The vulnerable provider is explicitly sample/example code, excluded by the production-code gate. |
| CWE-287 | Flask-HTTPAuth CVE-2026-34531 | APPROVED | 1 | 2 | The fix prevents missing or empty tokens from entering the verification callback. |
| CWE-287 | pytonapi CVE-2026-54635 | APPROVED | 1 | 2 | Manual review keeps one exact AST-valid prefix pair containing default-only token registration before and per-custom-path token registration after; redundant subscription-only tail chunks are excluded. |
| CWE-287 | Prefect CVE-2026-7722 | APPROVED | 1 | 2 | API middleware changes a suffix-based health-check bypass to exact path matching; one before/after patch chunk retains the authorization guard. |
| CWE-287 | django-allauth CVE-2025-65431 | HOLD | 0 | 0 | Okta and NetIQ pairs are code duplicates; the remaining 34–60-token extractor omits the authentication decision context needed for reliable model training. |
| CWE-78 | Dulwich CVE-2026-42563 | HOLD | 0 | 0 | The changed function is 1107 tokens before the fix, and automatic chunking could not preserve a complete paired patch; manual source-preserving review is required. |
| CWE-78 | LlamaIndex CLI CVE-2025-1753 | HOLD | 0 | 0 | `RagCLI.handle_cli` contains the vulnerable `os.system` and quoting fix, but is 3358 tokens; automatic patch-aware chunking produced no safe paired training chunks. |
| CWE-78 | pgAdmin 4 CVE-2025-12763 | HOLD | 0 | 0 | Automatic chunks include the Windows `shell` change but cut off the `Popen` call, so the full command sink and executable AST are not retained; do not train on these chunks. |
| CWE-78 | Chainlit CVE-2026-45018 | HOLD | 0 | 0 | The fix is a broad MCP transport refactor; client-controlled command, server configuration and subprocess sink span large functions, with no clean isolated before/after function pair yet. |
| CWE-798 | New batch | HOLD | 0 | 0 | Recent candidates are multi-CWE or do not show the hardcoded credential literal inside a clean paired function. Keep searching rather than weaken the label. |
| CWE-798 | Crawl4AI CVE-2026-56265 | APPROVED | 1 module block | 2 | Reviewed single-CWE advisory and single-parent fix commit. A CWE-798-only AST extractor isolates the module-level `SECRET_KEY` fallback and its direct remediation in production `deploy/docker/auth.py`; both variants are AST-valid and 24/503 CodeBERT tokens. No new duplicate or label conflict. Other security fixes in the commit are excluded. |
| CWE-798 | Feast CVE-2026-92787 | REJECTED for current Python-only pipeline | 0 | 0 | Single-parent fix `7a9866057375fdd57ca56c87c6e7b91ac11469cc` verified, but the hardcoded `intra-server-communication` value is in the Helm deployment template, not a Python literal credential pair. The Python fix also changes signature verification; do not mislabel an isolated Python pair as hardcoded credential removal. |
| CWE-798 | AstrBot CVE-2025-55449 | HOLD | 0 | 0 | Reviewed advisory and single-parent fix `d03e9fb90a0921a1bd10cf480bdacc9aaa246472` verified. Advisory has CWE-321/CWE-345/CWE-798 and the hardcoded `WEBUI_SK` is removed from a module while use sites change in other files, so it does not yield the required isolated paired source unit under the current schema. |
| CWE-798 | PraisonAI CVE-2026-57148 | HOLD — not merged | 0 | 0 | Verified the reviewed multi-CWE advisory and single-parent fix `e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747`; extracted only the production `auth_service.py` module-level `JWT_SECRET` block (51/504 CodeBERT tokens). The fixed version is safer by default, but explicitly setting `PLATFORM_ENV=dev` still assigns the public `dev-secret-change-me` key. Therefore the paired `after` is not unambiguously SAFE for this single-label dataset. The batch is retained under `data/supplement/cwe-798/batches/praisonai-cve-2026-57148/processed/manual_review.jsonl`; canonical data is unchanged. |
| CWE-798 | IBM ContextForge CVE-2026-53709 | HOLD — not merged | 0 | 0 | Project advisory lists 1.0.2 as patched, but the release's production `mcpgateway/config.py` still contains `jwt_secret_key: SecretStr = Field(default=SecretStr("changeme"))`. A later change uses a rejected placeholder instead. Do not treat the claimed patched release as a verified SAFE negative or count it as an independent case until the exact remediation commit and behavior are reconciled. |
| CWE-798 | Ogham MCP GHSA-8pqq-224h-x875 | REJECTED | 0 | 0 | The published credentials were in a Makefile and a test fixture, not production Python code. |

## Required gates

Every approved batch must have a reviewed advisory and one isolated training CWE,
production Python code, a public single-parent fix commit, traceable repository / commit /
file / function provenance, valid before-and-after ASTs, direct semantic evidence,
an actually remediated `after` version, exact CodeBERT token counts (or validated
patch-aware chunks), and no new duplicate or label conflict in the canonical build.
For multi-CWE advisories, the extractor has a narrow CWE-798-only opt-in:
record all advisory CWEs, whitelist one production Python file and module binding,
and document why this source unit isolates the credential defect. Extraction alone
never implies acceptance. All top-level overwrites of the binding are retained;
the filter sends any residual hardcoded credential in `after` to manual review.

## Current readiness (2026-09-24)

The canonical build has 421 model rows: CWE-22 124, CWE-78 48, CWE-79 156,
CWE-89 42, CWE-287 45, and CWE-798 6. Four CWE-798 rows are overlapping
before/after chunks from one D-Tale function; the other two rows are one
Crawl4AI module-block pair. This is two independent cases, not six.
`prepare_smoke_test.py` excludes CWE-798 because it has fewer than three
independent commit groups. Therefore the six-CWE pilot is **not ready** even
though the five-CWE smoke pipeline runs. Do not count chunk rows as distinct
vulnerabilities or add unsupported candidates simply to fill the label.
