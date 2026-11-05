# DocVault — Phase 4 Secure Document Management Plan

**Status:** Planning document; no Phase 4 implementation is represented here.
**Planning basis:** Repository source and documentation inspected on 5 November 2026, including the original five-page course specification PDF.
**Scope label:** This plan uses “Phase 4” for document management as requested in the current project brief. The older v2.0 architecture labels Kubernetes work “Phase 4”; its numbering is a roadmap mismatch, not a reason to defer document management.

## 1. Purpose and evidence boundaries

This plan defines a minimal, reviewable implementation of secure document workflows on the existing FastAPI/PostgreSQL/authentication foundation. It distinguishes requirements stated in the course specification and architecture documents from capabilities verified in the current repository and from proposed design decisions. Nothing below claims that document features or their tests already exist.

The course specification and architecture baseline are proposed project documents subject to instructor approval. The original specification defines an application milestone; it does not require that this implementation phase also deliver a browser frontend. Accordingly, the proposed work is API-only. A frontend may consume these endpoints in a later phase.

## 2. Findings from repository inspection

### Existing implementation

- The repository has a FastAPI app with authentication, health/readiness, and administrator user-management routers. There are no document routes, document services, document models, sharing tables, or document-specific tests.
- SQLAlchemy uses a shared declarative `Base`; current models are `User`, `Role`, and `AuthSession`. Alembic has one revision, `0001_identity_sessions`.
- The authenticated user and role are resolved from a server-side session. Authenticated state-changing routes use the synchronizer CSRF token. The API uses PostgreSQL application credentials; the one-shot migration service uses separate migration credentials.
- `backend/app/audit.py` emits structured stdout JSON with a small allow-list (`event`, `outcome`, actor/target IDs, source IP, and reason). It currently covers identity/security events, not document operations.
- `compose.yaml` gives the API a read-only root filesystem and a 16 MiB `/tmp` tmpfs. There is no document-storage volume. The container runs as UID/GID 10001.
- Runtime requirements do not currently include a multipart parsing package. Existing tests mostly use SQLite and direct route/service calls; Phase 3 documentation says Starlette/httpx `TestClient` hangs in the execution environment. The reported Phase 3 total is 39 automated tests and 35/35 separately supplied manual HTTP checks. PostgreSQL advisory-lock concurrency remains deferred and unverified.
- No `.env` file was read. No environment secrets were inspected.

### Relevant project requirements

The original course PDF, [DocVault_Project_Specifications.pdf](../DocVault_Project_Specifications.pdf), requires a working backend/database application with User and Administrator roles and these document capabilities: upload, list, view/download, delete, controlled sharing, database metadata, files in a controlled separate storage location, and server-side permission checks on every document operation. It also calls for relevant audit events without logging passwords, tokens, or document contents. The document-management section does not mandate file formats, a specific size threshold, version history, malware scanning, per-user quotas, or a browser UI in this milestone.

The v2.0 architecture baseline strengthens the file controls: validate extension, MIME type, magic bytes, and maximum size; use random server-side storage names; store outside the public web root; check ownership/permissions server-side for every operation; never trust browser-supplied IDs, owners, roles, or permissions; and avoid logging credentials or file contents. Its role model says owners may share/revoke and recipients may access shared documents. Its threat scenarios call out IDOR, unsafe uploads, path traversal, resource exhaustion, and stored XSS in metadata.

The v2.1 STRIDE draft maps T-03/T-04 to IDOR and unauthorized delete/share, T-06/T-07 to misleading uploads and filename traversal, T-08 to storage exhaustion, and T-11/T-12 to audit accountability and log confidentiality. It proposes multi-user authorization checks and crafted-upload evidence. The v2.1 document is a companion draft, not proof that any of these controls or tests have been implemented.

### Supporting project records

- [README](../README.md) — current status and explicitly unimplemented document workflows.
- [Technical Architecture and Project Baseline v2.0](../DocVault_Technical_Architecture_and_Project_Baseline-v2.md) — scope, roles, security requirements, vulnerability scenarios, and audit expectations.
- [v2.1 Changelog and STRIDE Threat Model](../DocVault%20v2.1%20%E2%80%94%20Changelog%20and%20STRIDE%20Threat%20Model.md) — document threats and proposed validation evidence.
- [Project Execution Log](PROJECT_EXECUTION_LOG.md) — current evidence record and phase boundaries.
- [Phase 0](PHASE_0_ENVIRONMENT_AUDIT.md), [Phase 1B](PHASE_1_DOCKER_INSTALLATION.md), [Phase 1C](PHASE_1_COMPOSE_VALIDATION.md), [Phase 2A](PHASE_2A_DEVELOPMENT_ENVIRONMENT.md), [Phase 2B](PHASE_2B_POSTGRESQL_DEPLOYMENT.md), [Phase 2C](PHASE_2C_FASTAPI_BACKEND.md), and [Phase 3](PHASE_3_AUTHENTICATION_AND_USER_MANAGEMENT.md) — implementation history and validation limits.

## 3. Objectives and scope

Deliver authenticated API operations to store, list, download, delete, grant, and revoke access to fictional documents. Keep metadata in PostgreSQL and file bytes in a private filesystem location. Every operation must derive the actor from the existing session and make its authorization decision on the server.

The work should reuse existing FastAPI, SQLAlchemy, Alembic, PostgreSQL, CSRF, request-scoped database sessions, and structured security events. It should not introduce a public file server, browser frontend, cloud storage, antivirus service, document conversion, full-text indexing, document versioning, or a new authorization role.

## 4. Requirements classification

| Capability/control | Source status | Phase 4 treatment |
|---|---|---|
| Upload, list, view/download, delete documents | Explicit original-spec requirement | Implement API operations. |
| Store document metadata in DB and file content separately in controlled storage | Explicit original-spec requirement | Implement with a private persistent volume. |
| User and administrator roles; users access owned or explicitly shared documents | Explicit original-spec requirement | Preserve existing roles; owner/sharee access only. No implicit administrator access to user files. |
| Owner can grant/revoke sharing; each operation checks current permission on the server | Explicit original-spec requirement | Implement owner-only share management and checks on read/write operations. |
| Extension, declared MIME, magic bytes, size limit, random storage name, storage outside web root | Architecture security requirement | Implement a strict allow-list and bounded streaming validation; final allowed format and limit are proposed decisions below. |
| Audit upload, download, deletion, sharing, denied access, rejected uploads without secrets/content | Architecture and threat-model requirement | Extend the structured allow-list and test emitted fields. |
| Filename policy, record schema, endpoint paths/statuses, file allow-list, max size, storage path, share representation | Not specified exactly | Proposed design choices; confirm during implementation review. |
| Malware scanning, per-user quotas, frontend, document versioning, external object storage, public cloud | Optional or absent from the initial document-management requirement | Defer; do not imply malware scanning or quota enforcement. |

The project specification’s broader architecture mentions a simple web interface, but does not assign it to this document-management milestone. This plan therefore does not implement or specify frontend files. The course specification calls the project team-based while the current project context is individual; that scope decision is already noted in the Phase 0 record and is not changed here.

## 5. Functional requirements

1. A signed-in active user uploads a permitted document. The server assigns ownership from the authenticated session, validates and stores bytes privately, and returns a safe document representation.
2. A user lists only documents they own or that have been explicitly shared with them. Listing returns metadata only, never file bytes or internal storage paths.
3. An owner or active sharee downloads the document through an authenticated API route. The response is an attachment with a safe display filename and a server-determined media type.
4. An owner can delete their document. A sharee cannot delete it.
5. An owner can grant access to another active user and revoke that access. Only the owner may manage shares; a sharee may read/download but cannot re-share or delete.
6. An administrator does not gain document access solely through the administrator role. If the owner explicitly shares with an administrator, the ordinary share rule applies.
7. Invalid/missing identifiers, inactive users, inaccessible documents, invalid share targets, and missing file records fail with safe responses and no path or secret disclosure.

## 6. Security requirements and risk controls

### IDOR / Broken Object Level Authorization

- Authenticate every endpoint using the existing `get_current_auth` dependency. Use its database-resolved user ID, not request-supplied owner/actor IDs.
- Query authorization together with the requested object: owner match or an active `DocumentShare` row for reads; owner match only for delete and share management. Do not fetch a row by ID and assume an opaque UUID is authorization.
- Use UUID document identifiers to fit the current model convention and reduce guessability; UUIDs are identifiers, never permissions. Return the same not-found response for nonexistent and unauthorized document IDs to reduce object-existence disclosure.
- Write tests with at least two users, one owner, one explicit sharee, and a third unrelated user. Cover list/read/download/delete/share/revoke as well as guessed IDs and role spoofing.

### Path traversal, symlinks, and filenames

- Keep the client filename entirely separate from storage addressing: never concatenate, resolve, or otherwise use it in any filesystem operation. Store it only as bounded, sanitized display metadata and use it only in safely encoded `Content-Disposition` output.
- Open the configured storage root once as a directory file descriptor after validating the trusted mount and its ownership/mode. Perform later file operations relative to that descriptor using server-generated single-component keys only; do not use a `resolve()`-then-open sequence as the security boundary.
- Where supported, use descriptor-relative operations (`openat`/`dir_fd`, `renameat`/`dir_fd`, and `unlinkat`/`dir_fd`) with `O_NOFOLLOW`, `O_DIRECTORY`, `O_CLOEXEC`, and `O_CREAT|O_EXCL` as appropriate. Validate key syntax as a generated UUID with no separators. Open existing files with no-follow behavior and verify the opened descriptor with `fstat`; do not follow symlinks for metadata checks. Rename temporary and final names within the already-open root directory.
- These constraints anchor operations to the opened directory and avoid path-component substitution between a check and use. Do not rely on a string-prefix check or a prior canonicalization alone. If the platform lacks a required no-follow/descriptor-relative primitive, fail closed or use a reviewed equivalent; do not silently fall back to following paths. Never expose the root or storage key to clients.

### Malicious or misleading uploads

- Treat filename extension, request `Content-Type`, and all other client metadata as untrusted. Require them to agree with a server-side allow-list and inspect file signature/content before promotion to permanent storage.
- Proposed initial format decision: PDF only (`.pdf`, `application/pdf`, PDF signature). This is a narrow first supported format, not a specification mandate. Do not describe signature checks as malware scanning or proof that a PDF is harmless. Store and serve as an attachment with `X-Content-Type-Options: nosniff`; do not inline-render uploads.
- Proposed initial maximum: 10 MiB per upload, configurable through validated application settings. The course documents require a size limit but do not set its number. Count actual bytes while streaming and reject at `limit + 1`; do not trust `Content-Length` or buffer a whole file in process memory.
- Multipart spooling is part of the request path, not avoided by later copying `UploadFile` in chunks. The repository lock pins Starlette 1.10.0. That version’s multipart parser creates a `SpooledTemporaryFile` with a 1 MiB in-memory threshold. The Starlette package is not installed in the current inspection shell, so this is based on the versioned upstream source/docs, not a local runtime experiment. Once that threshold is crossed, the spool rolls to the system temporary directory (currently `/tmp`). FastAPI's `UploadFile` endpoint receives this parsed/spooled file only after multipart parsing. Starlette documents that `max_part_size` limits non-file fields, not uploaded file parts; it is not the 10 MiB file-size control. See the [Starlette 1.10.0 multipart parser](https://github.com/Kludex/starlette/blob/1.10.0/starlette/formparsers.py) and [request file documentation](https://github.com/Kludex/starlette/blob/1.10.0/docs/requests.md).
- A 10 MiB file therefore occupies approximately 10 MiB in `/tmp` after rollover (the initial in-memory bytes are copied to the rolled file), plus bounded parser/request overhead. The current 16 MiB `/tmp` can accommodate one maximum upload with a margin, but two simultaneous maximum uploads could require about 20 MiB before overhead and exhaust it. A later `UploadFile.read()` loop does not reclaim that parser spool while the form/file remains open.
- Initial concurrency policy: acquire a non-queuing upload-admission slot in ASGI middleware before the request body is consumed or Starlette parses the multipart form; allow one active upload and reject additional upload attempts immediately with `429` and `Retry-After`. Keep the API at one Uvicorn worker for this 16 MiB tmpfs configuration. A process-local slot does not constrain additional workers or replicas; if those are introduced, require a shared admission control or size `/tmp` and the concurrency budget for the total simultaneous parser spools before deployment. Do not add an unbounded waiting queue.
- Before parser invocation, enforce a streaming whole-request body cap of 10 MiB plus a small fixed multipart-overhead allowance (proposed 64 KiB); stop consuming and reject with `413` above it. Also set parser limits to one file, no unnecessary form fields, and bounded multipart part/header counts/sizes supported by the pinned version. Validate actual file bytes again while copying from the spool into private storage. The body cap bounds parser disk use even when a client omits or lies about `Content-Length`.
- Add and pin the multipart parser dependency only when implementing upload, then verify these limits and cleanup behavior against the locked Starlette version. Do not install it during this planning task.
- Reject zero-byte files, oversized files, extension/type/signature mismatches, malformed multipart requests, and unsupported formats. Clean up partial files on every rejection.

### Storage confidentiality and integrity

- Proposed local storage root: `/var/lib/docvault/documents`, mounted as a dedicated named volume at the API container. It must not be served by FastAPI static-file routes or a web server. PostgreSQL continues to store metadata only; the existing database volume remains separate.
- Prepare the mount point for UID/GID 10001 and check the actual mounted volume is writable only by the API process. Retain the API’s read-only root filesystem, non-root identity, dropped capabilities, and `no-new-privileges`.
- Store under server-generated keys, use restrictive directory/file modes, and avoid following symlinks. A digest may be stored as metadata for corruption checking, but is not required by the original specification; treat it as an optional design choice rather than an access-control mechanism.
- Compose persistence is not a backup. Backup/restore, encryption at rest, and Kubernetes PVC design remain outside this milestone unless explicitly added later.

### Database/filesystem consistency and races

- File bytes and PostgreSQL metadata cannot participate in one atomic transaction. Stage each upload in a random temporary file relative to the open storage-root descriptor, validate while writing, then rename within that directory to a random final key. Insert metadata in a DB transaction; if that transaction fails normally, unlink the promoted key relative to the same descriptor. Test each failure path. A process crash between filesystem promotion and DB commit can still leave an orphan file; no cross-resource atomicity is claimed.
- Use the explicit deletion lifecycle below. It commits an inaccessible tombstone before touching file bytes; normal filesystem failures leave that tombstone for a safe retry rather than restoring access.
- Serialize owner mutations for a document using a PostgreSQL row lock where applicable and database uniqueness constraints for shares. Avoid check-then-act without constraints. Define the behavior for concurrent delete/download/share/revoke and add isolated PostgreSQL tests for races that SQLite cannot represent. As with the existing final-admin test, a present test harness is not evidence until it has run.
- **Deletion lifecycle:** add a non-null lifecycle state constrained to `active`/`deleting`; every list, metadata, download, and share authorization query must require `active`. The owner-only DELETE first locks/rechecks the row and commits `deleting` (and disables/removes effective shares) before unlinking. After that commit, no new API operation may disclose metadata or open file bytes. Open a descriptor relative to the storage-root FD and unlink the generated key without following symlinks; then delete the row/share records in a separate DB transaction. This ordering is intentionally not atomic across PostgreSQL and the filesystem.
- **Ordinary failures:** if the initial DB transition fails, do not touch the file and leave the document active. If unlink fails, keep the committed `deleting` tombstone inaccessible and return a safe retryable server error; do not reactivate it. If unlink succeeds but final DB cleanup fails, keep the tombstone; a retry treats an already-missing file as already removed and finishes DB cleanup. A repeated owner DELETE resumes this lifecycle idempotently.
- **Process crashes:** before the tombstone commit, the document remains active and the file is untouched. After tombstone commit but before unlink, it stays inaccessible with private bytes retained; retrying DELETE resumes removal. After unlink but before row cleanup, it stays inaccessible and retry completes the DB cleanup. If no retry occurs, a tombstone/file may remain because automatic reconciliation is deferred. These are recoverable crash states, not ordinary rollback compensation. Never restore `active` after the tombstone has committed.
- A download that acquired authorization and opened its file descriptor before deletion committed may finish from that descriptor. Coordinate the row lock and descriptor-open order so a request cannot authorize against `active` and open the file only after the tombstone commits. Record this in tests and the Phase 4 results report.

### Logging and metadata safety

- Use lowercase dotted event names in `<operation>.<outcome>` form. Preserve the STRIDE document's exact required `upload.rejected` event name for crafted/invalid upload rejection; use `upload.accepted`, `download.allowed`, `download.denied`, `delete.started`, `delete.completed`, `delete.failed`, `share.granted`, `share.revoked`, and `access.denied` for the corresponding outcomes. Keep outcome in the existing `outcome` field as well. This matches the existing `auth.*` operation/outcome style where practical while retaining the exact threat-model evidence name.
- Include actor UUID, document UUID when known, timestamp, and a fixed bounded reason code. Events must never contain filenames, file content, secrets, passwords, session or CSRF tokens, or filesystem paths. Never add attacker-controlled exception text.
- Continue to treat stdout/database logs as non-tamper-proof, as documented in Phase 3 and the threat model. External log shipping and tamper-proof audit retention are deferred.

## 7. Proposed architecture and request flow

1. FastAPI route validates request shape and obtains `AuthContext` through the existing session dependency. Mutating routes additionally require `require_csrf`.
2. A document service owns database authorization and lifecycle operations. Routes do not trust client role/owner fields and do not implement authorization as a UI-only check.
3. Upload streams the file to a temporary file under the private volume, counting bytes and calculating validation data. It sanitizes display metadata, checks the format policy, and only then promotes the file and records metadata.
4. Listing and download queries apply owner/share authorization in SQL. Download streams the private file; it never returns a storage path.
5. Delete/share/revoke operations verify ownership in the service, update DB/storage with the documented consistency behavior, and emit an allow-listed event.
6. Compose runs the API with the dedicated document volume. PostgreSQL remains on its existing internal network and no database port or file path becomes public.

The existing `docvault_app` account has DML privileges on database objects, and the migration account owns schema objects. A migration-created document table/share table should follow the existing grant/default-privilege pattern. No PostgreSQL role changes should be needed unless implementation inspection demonstrates otherwise.

## 8. Database models and migration

Proposed Alembic revision: `0002_documents` after `0001_identity_sessions`.

| Model/table | Proposed fields and constraints |
|---|---|
| `Document` / `documents` | UUID primary key; `owner_id` FK to users with restrictive or explicit lifecycle handling; non-null lifecycle state (`active`/`deleting`) with a check constraint; sanitized display filename; detected media type; byte size; opaque server-generated storage key with unique constraint; created timestamp; optional content digest. Never persist client-supplied filesystem paths. |
| `DocumentShare` / `document_shares` | Composite or UUID key; document FK; recipient user FK; created timestamp; unique `(document_id, recipient_user_id)`; indexes for document and recipient lookups. A deleted document must not leave effective shares. |

Use explicit foreign-key delete behavior consistent with the deletion service; avoid an accidental cascade that deletes audit history. Require recipient accounts to exist and be active at grant time. Authorization still checks current account/session status on requests. A schema rule preventing sharing to the owner may be enforced in the service; DB constraints should cover uniqueness and referential integrity.

Update `backend/app/models/__init__.py` so Alembic metadata includes these models, and add migration tests that upgrade a clean SQLite schema and verify key constraints/idempotent downgrade behavior where applicable. A SQLite migration check does not establish PostgreSQL locking or privilege correctness; validate migration and grants in an isolated PostgreSQL database during implementation.

## 9. API endpoints and behavior

Proposed prefix: `/api/v1/documents`. Exact names are design decisions, not original-spec literals.

| Method and path | Auth / CSRF | Behavior and proposed response |
|---|---|---|
| `POST /api/v1/documents` | Active session + CSRF | Multipart upload. Server assigns owner. Return `201` and safe metadata (`id`, display filename, media type, size, created time), with `Cache-Control: private, no-store`. Reject invalid/oversized format with `413` for size and `422` for unsupported/malformed content; no bytes/path in response. |
| `GET /api/v1/documents` | Active session | List only owned and explicitly shared active-document metadata, with an ownership/access indicator if useful. No file bytes or internal storage keys. Set `Cache-Control: private, no-store` on success and error responses. |
| `GET /api/v1/documents/{document_id}` | Active session | Return safe active-document metadata when caller owns or is shared; otherwise `404`. Set `Cache-Control: private, no-store` on success and error responses. |
| `GET /api/v1/documents/{document_id}/download` | Active session | Owner/sharee only. Stream as attachment; server media type, safe `Content-Disposition`, `X-Content-Type-Options: nosniff`, and `Cache-Control: private, no-store` on success and error responses; inaccessible/missing file returns safe `404` and emits a denial/integrity event. |
| `DELETE /api/v1/documents/{document_id}` | Active session + CSRF | Owner only. Remove shares and file under the defined lifecycle behavior. Return `204`; non-owner gets `404`. |
| `GET /api/v1/documents/{document_id}/shares` | Active session | Owner only; list active recipients as safe IDs or usernames. No document content. Set `Cache-Control: private, no-store` on success and error responses. |
| `PUT /api/v1/documents/{document_id}/shares/{recipient_user_id}` | Active session + CSRF | Owner grants read/download access to an active user; idempotent behavior or duplicate `409` must be selected and tested. |
| `DELETE /api/v1/documents/{document_id}/shares/{recipient_user_id}` | Active session + CSRF | Owner revokes recipient access; choose and document idempotent `204` or missing-share `404`. |

All document endpoints should set `Cache-Control: private, no-store`, including authorization/not-found errors; this is especially required for user-specific metadata and file responses. All writes use the current synchronizer CSRF mechanism. Reject unknown request fields as existing schemas do. Do not accept owner ID, storage key, media type, permissions, or role from upload JSON/form fields. UUID parse errors may return FastAPI’s sanitized `422`; a syntactically valid but unavailable/inaccessible object uses indistinguishable `404` behavior.

## 10. File validation and lifecycle strategy

1. Enforce authentication and CSRF before accepting a mutating request body as practical in the selected FastAPI/multipart flow.
2. Apply an overall request-size boundary and stream actual file chunks to exclusive temporary storage. Count bytes independently of `Content-Length` and stop immediately above the configured limit.
3. Permit only the initial PDF format; compare the sanitized `.pdf` extension and declared media type with a server-side signature check. Reject mismatches and malformed/truncated content. The file signature check is a format gate, not a complete PDF parser or malware scan.
4. Generate a random storage UUID unrelated to the client filename. Use root-directory-FD-relative exclusive creation and same-directory rename with no-follow flags where supported; restrict permissions and record only the opaque key in the database.
5. For download, check active state and authorization, then open the generated basename relative to the storage-root FD with no-follow behavior and verify the opened descriptor. Set attachment, `nosniff`, and private/no-store cache headers, then stream without logging bytes.
6. On upload errors, close and remove temporary/final files relative to the root FD and roll back the DB transaction. For delete, commit `deleting` first, then unlink, then finalize DB cleanup. Apply the separate ordinary-failure and process-crash retry behavior described in §6; never reactivate a committed tombstone.

The initial implementation should not parse or render user PDFs in a browser, run converters, unzip archives, or invoke external scanners. Malware scanning and richer supported formats are deferred capabilities, not implied security guarantees.

## 11. Authorization rules

| Operation | Owner | Explicit sharee | Other user | Administrator role alone |
|---|---:|---:|---:|---:|
| List/metadata read | Yes | Yes | No | No |
| Download | Yes | Yes | No | No |
| Upload | Creates own document | Creates own document | Creates own document | Creates own document |
| Delete | Yes | No | No | No |
| List/manage shares | Yes | No | No | No |
| Grant/revoke share | Yes | No | No | No |

The table is a proposed minimum policy grounded in the original role description. The specification gives administrators user/platform administration but does not grant them blanket access to document contents. Never trust a request-supplied role or owner identifier. Use current session identity and DB relations for every decision. Return `404` for cross-user object access to limit enumeration; log the internal denial with actor and object IDs.

## 12. Audit-event design

Extend, rather than replace, `record_security_event` with a typed or otherwise bounded document-event interface. Use the event names defined in §6: `upload.accepted`, the exact threat-model name `upload.rejected`, `download.allowed`, `download.denied`, `delete.started`, `delete.completed`, `delete.failed`, `share.granted`, `share.revoked`, and `access.denied`. The existing STRIDE draft explicitly names `upload.rejected`; its denied-access wording is descriptive rather than an exact event token. The remaining names follow the same lowercase dotted operation/outcome convention and do not replace the STRIDE-required upload event.

Record actor, target document ID, outcome, timestamp, and a small constant reason code. For share changes, a recipient UUID may be recorded as a target if necessary; do not log full request data. Tests must assert captured records contain no filenames, file bytes, auth cookies, CSRF tokens, passwords/secrets, filesystem paths, or exception text. Logging an ordinary list request is optional; defer it unless the report identifies an accountability need.

## 13. Likely file changes

The following is a planning inventory, not a statement that files exist or have been changed.

| File | Likely change |
|---|---|
| `backend/app/models/document.py` (new) | Document metadata model. |
| `backend/app/models/document_share.py` (new) | Owner-granted read-share model. |
| `backend/app/models/__init__.py` | Export/register new models for Alembic metadata. |
| `backend/app/api/schemas.py` | Safe document/share request and response schemas, or split into `backend/app/api/document_schemas.py` if clearer. |
| `backend/app/api/routes/documents.py` (new) | Upload/list/metadata/download/delete/share endpoints. |
| `backend/app/api/routes/__init__.py` (if it exports routers) and `backend/app/main.py` | Mount the document router. |
| `backend/app/services/documents.py` (new) | Authorization-aware queries and transactional document/share lifecycle. |
| `backend/app/services/document_storage.py` (new) | Private path handling, staged writes, atomic promotion, streaming reads, and removal. |
| `backend/app/security/document_validation.py` (new) | Filename, size, extension/media/signature validation. |
| `backend/app/core/config.py` | Validated storage root and maximum upload setting; do not add credentials. |
| `backend/app/audit.py` | Allow-listed document event helpers/fields without sensitive values. |
| `backend/migrations/versions/0002_documents.py` (new) | Document and share schema after identity migration. |
| `backend/Dockerfile` | Create/own the storage mount point as UID/GID 10001 if needed; optionally install a multipart dependency through locked requirements, not an unpinned ad hoc install. |
| `compose.yaml` | Add a dedicated persistent document volume to the API only and verify writable mount ownership. Maintain read-only root and existing network isolation. |
| `requirements.txt`, `requirements-lock.txt` | Add and lock multipart parser only if selected upload handling requires it. |
| `backend/tests/test_documents.py` (new) | Service, schema, upload validation, lifecycle, and audit tests. |
| `backend/tests/test_document_authorization.py` (new) | Multi-user BOLA/IDOR matrix, role spoofing, share and revoke behavior. |
| `backend/tests/test_document_storage.py` (new) | Traversal, symlink, cleanup, path containment, and atomic-write failure tests using temporary directories. |
| `backend/tests/test_migrations.py` | Extend schema migration checks, while retaining the existing identity assertions. |
| `scripts/phase4_document_runtime_test.py` (new, proposed) | Repeatable manual HTTP checks against an isolated running application; use fake users/files and no real data. |
| `README.md`, `docs/PROJECT_EXECUTION_LOG.md` | Update implementation status, actual validation, limitations, evidence links, and commit after Phase 4 is implemented and published. |

No frontend file is proposed for Phase 4. No existing phase report should be edited as part of planning; after implementation, create a separate Phase 4 results report if required by the project record convention.

## 14. Automated test plan

Tests should be added before or alongside each implementation slice. Use temporary filesystem roots and synthetic users; do not use real documents or credentials.

### Functional and schema tests

- Migration creates document/share tables, foreign keys, indexes, and uniqueness constraints; migration metadata imports all models.
- Owner upload records correct owner and safe metadata; client cannot supply owner, storage path, storage key, or media type.
- Listing includes owned and shared documents only and does not return storage internals or file bytes.
- Owner/sharee metadata and download work; an unshared user gets indistinguishable `404` for a valid other-user ID.
- Owner delete succeeds; sharee/other-user/admin-only delete is denied. Revocation removes subsequent access. Only owners can list/grant/revoke shares.
- Inactive/nonexistent recipient handling and duplicate/self-share policy match the chosen contract.

### Security and failure-path tests

- Cross-user read/download/delete/grant/revoke and forged owner/role values are rejected; state remains unchanged.
- `..`, absolute paths, slash/backslash, NUL, CR/LF, overlong and Unicode edge-case filenames cannot influence storage paths or response headers.
- Reject unsupported extension, mismatched MIME, mismatched magic/signature, empty, malformed, and over-limit files; confirm no partial/final orphan remains on ordinary upload failure. Test crash-recovery states for deletion separately from ordinary compensation.
- Test the pinned Starlette spool behavior: one request crossing the 1 MiB spool threshold rolls to `/tmp`; assert the complete file spool is bounded by the 10 MiB file cap and the request body cap. Verify one active upload is admitted before multipart parsing and a second receives `429` without body consumption. Verify `max_files`, form-field, and request-body caps against the exact Starlette 1.10.0 dependency installed for implementation; no runtime behavior is claimed by this plan.
- Large input is consumed in bounded chunks and fails at the configured limit without buffering the complete upload into application memory.
- Verify storage key is random/server generated; path remains inside root; symlink attempts cannot read/write outside the volume; files are not reachable via a static/public route.
- Inject failures at upload staging/promotion/metadata insertion and verify cleanup/compensation. Inject deletion unlink/final-DB-cleanup failures and verify the committed tombstone stays inaccessible and retryable; test process-crash boundaries separately.
- Exercise concurrent share grant uniqueness and download/revoke/delete behavior in isolated PostgreSQL tests; SQLite-only results do not prove PostgreSQL race semantics.
- Audit tests assert expected success/rejection/denial events and assert secret/file/path/filename values are absent.
- Cookie-authenticated state-changing operations without CSRF or with an invalid CSRF token return `403`; reads still require authentication.

Automated direct-route tests are useful but should not be described as end-to-end HTTP transport tests. Resolve the existing TestClient limitation or provide the proposed HTTP runtime script/manual checks to validate multipart parsing, headers, streaming, and cookies over the actual API path.

## 15. Manual verification plan

Run only in the isolated project environment with fictional accounts/files. Record exact commands, commit, environment/software versions, response status, and redacted outputs; never capture `.env` or print secrets.

1. Apply the new migration through the documented migration service against an isolated disposable PostgreSQL database; inspect schema and application/migration grants. Do not use production or the persistent project database for destructive migration experiments.
2. Build/recreate the API only after implementation review; confirm `/ready`, mount ownership, API UID, read-only root, and document volume persistence after API container replacement. Do not remove the volume during cleanup.
3. Create users A, B, and C through existing controlled administration. A uploads an allowed fictional PDF; inspect response metadata, file permissions, generated key format (redacted), and volume location without exposing the content.
4. Verify A and an explicitly shared B can list/metadata-read/download; C cannot. Verify B/C cannot delete or change sharing. Verify administrator role alone does not bypass the document policy.
5. Run crafted upload cases: renamed non-PDF, MIME mismatch, invalid signature, empty file, traversal-looking filename, CR/LF/control characters, and limit-plus-one payload. Check status codes, absence of residual files/records, and safe rejection logs.
6. Verify owner deletion and share revoke. Confirm deletion first enters inaccessible `deleting` state; inject unlink and final-DB-cleanup failures; restart the API between each lifecycle boundary and verify retry resumes without exposing bytes. Repeat denied access after revoke. Attempt concurrent revoke/download and duplicate share operations in isolated PostgreSQL and record exact semantics.
7. Inspect metadata and download responses for `Cache-Control: private, no-store`; inspect downloads for attachment disposition, safe filename encoding, detected media type, and `X-Content-Type-Options: nosniff`. Confirm no public/static file route serves the content.
8. Review redacted security logs for upload/rejection, download, deletion, sharing/revocation, and denied IDOR events. Search for a unique dummy marker used in a test file and verify neither file bytes nor raw filename, cookie, CSRF value, path, or password appears.
9. Repeat the complete test suite and static validation. Report failures as failures and distinguish automated tests, manual HTTP checks, static checks, and deferred concurrency/runtime work.

## 16. Academic evidence expected

Reserve real artifacts as they are captured; do not invent filenames or imply that planned evidence exists.

- Migration/schema and least-privilege grant evidence with credentials redacted.
- Test report showing upload validation and bounded spool/concurrency behavior, owner/sharee authorization, denied IDOR attempts, sharing/revocation, deletion tombstone/failure/crash-retry behavior, cache headers, and cleanup.
- Manual HTTP transcript or screenshots showing allowed and denied behavior for users A/B/C.
- Safe upload-rejection evidence for misleading extension/MIME/signature, traversal-like filename, and size limit.
- Storage-volume permission and non-root runtime evidence; proof that database and document bytes remain separate.
- Redacted audit-event evidence for a fictional unauthorized access and rejected upload, plus log-content checks showing secrets/document bytes are absent.
- Compose persistence evidence and explicit statement that backup/restore, malware scanning, encryption at rest, and crash reconciliation are outside the verified scope unless separately tested.
- Full Git commit hash, test commands/results, limitations, and residual risks in the Phase 4 report and living [Project Execution Log](PROJECT_EXECUTION_LOG.md).

## 17. Dependencies and implementation order

Dependencies are currently FastAPI, SQLAlchemy, Alembic, psycopg, and existing security/runtime packages. Multipart parsing is missing and is a likely runtime dependency for `UploadFile`; select a supported package, pin it, and update the lock only during implementation. Avoid adding file-type libraries unless built-in checks prove inadequate and the choice is justified. No antivirus or cloud object-store dependency is required for the minimal phase.

1. Review and accept the proposed PDF-only, 10 MiB, private-volume, sharing, deletion, and error-response policies. Adjust any value to instructor/project requirements before coding.
2. Define config and pure filename/file-content validation with boundary tests; establish the actual upload/multipart temp-file behavior and resource limits.
3. Add document/share models and migration; update Alembic model imports and migration tests. Validate the migration in isolated SQLite and PostgreSQL environments.
4. Implement storage service using temporary files, opaque keys, safe permissions, bounded streaming, atomic promotion, and compensating cleanup. Add storage failure tests.
5. Implement authorization-aware service methods and uniqueness/locking rules. Add multi-user tests before exposing routes.
6. Add schemas and API routes, wiring existing session and CSRF dependencies. Add audit events and verify sensitive-field absence.
7. Add and validate the dedicated Compose volume and container mount permissions; confirm the application remains non-root with a read-only root filesystem.
8. Run automated tests/static checks, then the manual HTTP/security matrix and isolated PostgreSQL race checks. Capture evidence and record any deferred tests precisely.
9. Update README, create the Phase 4 results record, and update the execution log only with observed outcomes and the published commit hash.

## 18. Deferred and optional work

- Frontend pages, JavaScript upload/download flows, and stored-XSS browser rendering tests; no frontend currently exists, and this plan is API-only.
- Additional document formats, archive extraction, previews, conversions, OCR/full-text search, tags/folders, versioning, retention/legal hold, and public links.
- Antivirus/content disarm, malware sandboxing, and a claim that PDF signature checks make content safe.
- Per-user quotas and automated storage garbage collection. The 10 MiB file limit alone does not prevent aggregate disk exhaustion; monitor bounded volume capacity and revisit quotas before multi-user deployment.
- Startup orphan reconciliation, durable deletion tombstones/background cleanup, backup/restore, encryption-at-rest guarantees, external object storage, and Kubernetes PVC/NetworkPolicy configuration.
- Tamper-resistant audit storage, external log shipping, log retention policy, and audit-log review UI.
- Production readiness, high availability, and deployment beyond the isolated academic environment.

## 19. Recommended small-step acceptance sequence

Phase 4 is accepted only when each step has code, tests, and recorded evidence; plan text alone does not satisfy acceptance.

1. **Schema and validation foundation:** migration upgrades cleanly on isolated PostgreSQL; metadata/share constraints are present; filename and format/size validators pass boundary and traversal tests; actual locked Starlette spool and pre-parser admission/body limits are exercised.
2. **Private storage foundation:** API writes only beneath the dedicated private volume using descriptor-relative, no-follow operations and server-generated keys; non-root mount permissions work; failed writes clean up; no public/static route exposes files.
3. **Upload and listing:** authenticated owner assignment cannot be forged; valid PDF upload returns safe metadata; owner/shared listing behavior passes; invalid and oversized uploads leave no ordinary failure residue.
4. **Read and download authorization:** owner/sharee can fetch safe metadata and attachment bytes; unrelated users and admin-only access receive the same `404`; metadata/download responses include `Cache-Control: private, no-store`, and downloads retain attachment disposition plus `X-Content-Type-Options: nosniff`.
5. **Sharing and revocation:** owner can grant/revoke only to valid active users; sharee can read/download only; uniqueness and concurrent operations have explicitly tested PostgreSQL semantics.
6. **Deletion and lifecycle:** only owner can delete; the committed tombstone denies access before unlink; ordinary filesystem/DB failures and process crashes follow the distinct retry rules; PostgreSQL/filesystem atomicity is not claimed.
7. **Audit evidence:** `upload.rejected` is emitted exactly as named in the STRIDE draft, and all document events follow the defined dotted operation/outcome convention with no filename, secret, token, path, or document content; denied IDOR and rejected upload events are demonstrated.
8. **Full Phase 4 verification:** automated suite, static checks, manual HTTP matrix, storage/runtime checks, and PostgreSQL concurrency checks have actual recorded outcomes. Deferred results remain labeled; no feature is described as production-ready.

### Phase 4 overall acceptance criteria

- All required upload/list/metadata/download/delete/share/revoke flows work for authenticated fictional users.
- Server-side owner/share authorization is tested for every document operation, including cross-user ID tampering and administrator-only attempts.
- File format, size, filename, storage-path, and private-volume controls have negative tests and manual evidence.
- Database metadata and file bytes are stored separately; the document volume is not publicly served; container hardening remains in force.
- Audit events cover allowed and denied security-relevant document actions without sensitive content.
- Database/filesystem failure handling and concurrent-operation behavior are tested or explicitly listed as deferred with concrete limits.
- Documentation and evidence distinguish the original requirement, implemented design choices, observed validation, and deferred/optional work. No fabricated results or production-readiness claims are made.
