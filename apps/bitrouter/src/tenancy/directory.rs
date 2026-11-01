//! Revision-fenced directory pages; all durable reads run on the authority actor.

use axum::{
    Extension, Json,
    extract::{Query, State, rejection::QueryRejection},
};
use bitrouter_ai::tenancy::{
    directory::{
        DirectoryCursorV1, DirectoryEntryV1, DirectoryPageV1, MAX_DIRECTORY_PAGE_BYTES,
        ManagementAuthorityClassV1, ManagementOwnerV1,
    },
    identity::AuthorityRevision,
    operation::ErrorCode,
    validation::Validate,
};
use serde::Deserialize;
use tokio::{
    sync::{OwnedSemaphorePermit, oneshot},
    time::Instant,
};

use super::{
    MANAGEMENT_TIMEOUT, Service,
    actor::{Job, Worker},
    error::Failure,
    model::{AuthorityClass, Caller},
    store,
    transaction::Control,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageQuery {
    authority_revision: Option<u64>,
    after: Option<DirectoryCursorV1>,
    #[serde(default = "default_limit")]
    limit: u16,
}
fn default_limit() -> u16 {
    100
}

pub(super) struct Read {
    caller: Caller,
    revision: Option<AuthorityRevision>,
    after: Option<DirectoryCursorV1>,
    limit: u16,
    pub deadline: Instant,
    pub permit: OwnedSemaphorePermit,
    pub reply: oneshot::Sender<Result<DirectoryPageV1, Failure>>,
}

fn operator(caller: &Caller) -> Result<(), Failure> {
    if matches!(caller, Caller::Installation(_)) {
        Ok(())
    } else {
        Err(ErrorCode::Forbidden.into())
    }
}

pub(super) async fn http(
    State(service): State<Service>,
    Extension(caller): Extension<Caller>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Json<DirectoryPageV1>, Failure> {
    operator(&caller)?;
    let Query(query) = query.map_err(|_| Failure::from(ErrorCode::InvalidRequest))?;
    let revision = query
        .authority_revision
        .map(AuthorityRevision::try_from)
        .transpose()
        .map_err(|_| Failure::from(ErrorCode::InvalidRequest))?;
    service
        .directory(&caller, revision, query.after, query.limit)
        .await
        .map(Json)
}

impl Service {
    pub(super) async fn directory(
        &self,
        caller: &Caller,
        revision: Option<AuthorityRevision>,
        after: Option<DirectoryCursorV1>,
        limit: u16,
    ) -> Result<DirectoryPageV1, Failure> {
        operator(caller)?;
        if !(1..=100).contains(&limit) || (after.is_some() && revision.is_none()) {
            return Err(ErrorCode::InvalidRequest.into());
        }
        let deadline = Instant::now() + MANAGEMENT_TIMEOUT;
        let permit = self
            .reads
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::from(ErrorCode::CapacityExceeded))?;
        let (reply, receive) = oneshot::channel();
        self.enqueue(
            Job::Directory(Read {
                caller: caller.clone(),
                revision,
                after,
                limit,
                deadline,
                permit,
                reply,
            }),
            false,
        )?;
        let page = match tokio::time::timeout_at(deadline, receive).await {
            Ok(Ok(result)) => result?,
            _ => return Err(ErrorCode::AuthorityUnavailable.into()),
        };
        // Reject a page if another command published after the actor read it.
        // The next request independently authenticates control:tenancy again.
        if self.current()?.revision != page.authority_revision {
            return Err(ErrorCode::RevisionConflict.into());
        }
        Ok(page)
    }
}

impl Worker {
    pub(super) async fn directory(
        &self,
        read: &Read,
        control: &Control,
    ) -> Result<DirectoryPageV1, Failure> {
        operator(&read.caller)?;
        let state = self.current()?;
        if read
            .revision
            .is_some_and(|revision| revision != state.revision)
        {
            return Err(ErrorCode::RevisionConflict.into());
        }
        let bound = usize::from(read.limit) + 1;
        let after = read.after.as_ref();
        let mut entries: Vec<_> = state
            .bindings
            .values()
            .filter(|binding| {
                after.is_none_or(|cursor| {
                    ("binding", binding.tenant.as_str(), binding.id.as_str()) > cursor.key()
                })
            })
            .take(bound)
            .map(|binding| DirectoryEntryV1::Binding {
                tenant_id: binding.tenant.clone(),
                binding_id: binding.id.clone(),
                revision_id: binding.revision.clone(),
                principal_id: binding.principal.clone(),
                role: binding.role,
                scope: binding.scope.clone(),
                expires_at: binding.expires.wire.clone(),
                management_owner: binding.managed_by.as_ref().map(|owner| ManagementOwnerV1 {
                    principal_id: owner.principal.clone(),
                    authority_class: match owner.class {
                        AuthorityClass::Installation => ManagementAuthorityClassV1::Installation,
                        AuthorityClass::Tenant => ManagementAuthorityClassV1::Tenant,
                    },
                }),
            })
            .collect();
        if entries.len() < bound && after.is_none_or(|cursor| cursor.key().0 <= "credential") {
            entries.extend(
                store::directory::credentials(
                    &self.db,
                    state.revision,
                    after,
                    bound - entries.len(),
                    control,
                )
                .await
                .map_err(|error| {
                    if error.is::<super::transaction::ReadExpired>() {
                        Failure::from(ErrorCode::AuthorityUnavailable)
                    } else {
                        self.unavailable(ErrorCode::StorageUnavailable)
                    }
                })?,
            );
        }
        let principals = state
            .principals
            .values()
            .map(|principal| DirectoryEntryV1::Principal {
                principal_id: principal.id.clone(),
                revision_id: principal.revision.clone(),
                issuer: principal.issuer.clone(),
                subject: principal.subject.clone(),
            });
        let tenants = state
            .tenants
            .values()
            .map(|tenant| DirectoryEntryV1::Tenant {
                tenant_id: tenant.id.clone(),
                revision_id: tenant.revision.clone(),
                state: tenant.state,
            });
        entries.extend(
            principals
                .chain(tenants)
                .filter(|entry| after.is_none_or(|cursor| entry.key() > cursor.key()))
                .take(bound - entries.len()),
        );
        let available = entries.len();
        let mut page = DirectoryPageV1 {
            schema_version: 1,
            installation_id: state.installation.clone(),
            authority_revision: state.revision,
            entries: Vec::new(),
            next_after: None,
        };
        let mut selected = Vec::new();
        let mut entry_bytes = 0;
        // Measure each entry once, plus the empty envelope with its proposed
        // cursor. Array commas add exactly one byte per preceding entry. Keep
        // the first entry that does not fit for the next request, without ever
        // serializing an oversized response or repeatedly encoding its prefix.
        for (index, entry) in entries
            .into_iter()
            .take(usize::from(read.limit))
            .enumerate()
        {
            let size = serde_json::to_vec(&entry)
                .map_err(|_| Failure::from(ErrorCode::AuthorityUnavailable))?
                .len();
            page.next_after = (index + 1 < available).then(|| entry.cursor());
            let envelope = serde_json::to_vec(&page)
                .map_err(|_| Failure::from(ErrorCode::AuthorityUnavailable))?;
            if envelope.len() + entry_bytes + size + index > MAX_DIRECTORY_PAGE_BYTES {
                page.next_after = selected.last().map(DirectoryEntryV1::cursor);
                if selected.is_empty() {
                    return Err(ErrorCode::PayloadTooLarge.into());
                }
                break;
            }
            entry_bytes += size;
            selected.push(entry);
        }
        page.entries = selected;
        page.validate()
            .map_err(|_| Failure::from(ErrorCode::AuthorityUnavailable))?;
        Ok(page)
    }
}
