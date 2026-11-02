//! Authenticated profile associations and monotonic route-key protection.
//!
//! Immutable resource definitions are the durable protection record. The
//! authority snapshot derives its bounded index from those authenticated rows;
//! rotation, revocation and later legacy imports cannot remove old definitions.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, ensure};
use bitrouter_ai::{
    tenancy::{
        admission::HealthProfileV1,
        admission_v2::AdmissionProfileV2,
        authority::{ResourceKey, ResourceKind},
        configuration::ResourceRef,
        identity::{OwnerId, ResourceId},
        operation::ErrorCode,
        resources::Definition as PublicDefinition,
        validation::Validate,
    },
    types::ApiProtocol,
};
use sea_orm::ConnectionTrait;

use super::{
    Resources, lifecycle,
    manifest::{Artifact, Definition, Import},
    storage,
};

#[cfg(test)]
mod tests;

pub(in crate::tenancy) mod profile;

use profile::{Profile, View};

/// Index bounded by the existing 4,096 immutable-resource catalog limit.
#[derive(Clone, Default)]
pub(in crate::tenancy) struct State {
    profiles: HashMap<ResourceRef, Profile>,
    group_rules: HashMap<(OwnerId, ResourceId), HealthProfileV1>,
    policy_keys: HashSet<ResourceKey>,
    protected_keys: HashSet<ResourceKey>,
    profiled_routes: HashSet<ResourceRef>,
}

impl State {
    pub(in crate::tenancy) fn protected(&self, route: &ResourceRef) -> bool {
        self.protected_keys.contains(&route.key())
    }

    pub(in crate::tenancy) fn configuration(
        &self,
        routes: &[ResourceRef],
    ) -> std::result::Result<(), ErrorCode> {
        if routes
            .iter()
            .any(|route| self.protected(route) && !self.profiled_routes.contains(route))
        {
            return Err(ErrorCode::CapabilityMismatch);
        }
        Ok(())
    }

    pub(in crate::tenancy) fn profile(&self, reference: &ResourceRef) -> Option<&Profile> {
        self.profiles.get(reference)
    }

    pub(in crate::tenancy) fn validate_put(
        &self,
        key: &ResourceKey,
        definition: &PublicDefinition,
    ) -> std::result::Result<(), ErrorCode> {
        match definition {
            PublicDefinition::AdmissionProfile { profile } => {
                self.validate_profile(key, View::Local(profile))?;
            }
            PublicDefinition::Policy { .. }
                if self
                    .profiles
                    .keys()
                    .any(|reference| reference.key() == *key) =>
            {
                return Err(ErrorCode::InvalidRequest);
            }
            _ => {}
        }
        Ok(())
    }

    pub(in crate::tenancy) fn validate_shared_put(
        &self,
        key: &ResourceKey,
        profile: &AdmissionProfileV2,
    ) -> std::result::Result<(), ErrorCode> {
        self.validate_profile(key, View::Shared(profile))
    }

    fn validate_profile(
        &self,
        key: &ResourceKey,
        profile: View<'_>,
    ) -> std::result::Result<(), ErrorCode> {
        match profile {
            View::Local(profile) => profile.validate(),
            View::Shared(profile) => profile.validate(),
        }
        .map_err(|_| ErrorCode::InvalidRequest)?;
        if self.policy_keys.contains(key)
            || self.profiles.iter().any(|(reference, previous)| {
                reference.key() == *key && !previous.permits_rotation_to(profile)
            })
        {
            return Err(ErrorCode::InvalidRequest);
        }
        if let View::Shared(profile) = profile
            && let (Some(group), Some(rules)) = (&profile.health_group_id, &profile.health)
            && self
                .group_rules
                .get(&(key.owner_id.clone(), group.clone()))
                .is_some_and(|previous| previous != rules)
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }

    fn record_profile(&mut self, reference: &ResourceRef, profile: View<'_>) {
        let retained = match profile {
            View::Local(profile) => Profile::Local(profile.clone()),
            View::Shared(profile) => {
                if let (Some(group), Some(rules)) = (&profile.health_group_id, &profile.health) {
                    // Retained history is never removed on revocation or rotation.
                    self.group_rules
                        .entry((reference.owner_id.clone(), group.clone()))
                        .or_insert_with(|| rules.clone());
                }
                Profile::Shared(profile.clone())
            }
        };
        self.profiles.insert(reference.clone(), retained);
    }

    pub(in crate::tenancy) fn apply_shared_put(
        &mut self,
        reference: &ResourceRef,
        profile: &AdmissionProfileV2,
    ) {
        self.record_profile(reference, View::Shared(profile));
    }

    pub(in crate::tenancy) fn apply_put(
        &mut self,
        reference: &ResourceRef,
        definition: &PublicDefinition,
    ) {
        match definition {
            PublicDefinition::AdmissionProfile { profile } => {
                self.record_profile(reference, View::Local(profile));
            }
            PublicDefinition::ProfiledRoute { .. } => {
                self.protected_keys.insert(reference.key());
                self.profiled_routes.insert(reference.clone());
            }
            PublicDefinition::Policy { .. } => {
                self.policy_keys.insert(reference.key());
            }
            _ => {}
        }
    }

    fn insert(&mut self, artifact: &Artifact) -> Result<()> {
        let reference = &artifact.reference;
        match &artifact.definition {
            Definition::AdmissionProfile { profile } => {
                self.validate_profile(&reference.key(), View::Local(profile))
                    .map_err(|_| anyhow::anyhow!("admission profile immutable rules changed"))?;
                self.record_profile(reference, View::Local(profile));
            }
            Definition::AdmissionProfileV2 { profile } => {
                self.validate_profile(&reference.key(), View::Shared(profile))
                    .map_err(|_| {
                        anyhow::anyhow!("admission profile or shared group immutable rules changed")
                    })?;
                self.record_profile(reference, View::Shared(profile));
            }
            Definition::Policy { .. } => {
                ensure!(
                    !self
                        .profiles
                        .keys()
                        .any(|previous| previous.key() == reference.key()),
                    "admission profile key changes type"
                );
                self.policy_keys.insert(reference.key());
            }
            Definition::ProfiledRoute { .. } => {
                self.protected_keys.insert(reference.key());
                self.profiled_routes.insert(reference.clone());
            }
            _ => {}
        }
        Ok(())
    }
}

impl Resources {
    pub(in crate::tenancy) async fn admission_state(
        &self,
        db: &impl ConnectionTrait,
        lifecycle: &lifecycle::State,
    ) -> Result<State> {
        let mut state = State::default();
        for reference in storage::references(db).await? {
            let artifact = self
                .load(db, &reference)
                .await
                .map_err(|_| anyhow::anyhow!("admission resource unavailable"))?;
            state.insert(&artifact)?;
        }
        for reference in state.profiles.keys() {
            let revision = lifecycle
                .head(&reference.key())
                .context("admission profile has no managed head")?;
            let mut head = reference.clone();
            head.revision_id = revision.clone();
            ensure!(
                state.profiles.contains_key(&head),
                "admission profile head changes type"
            );
        }
        Ok(state)
    }
}

pub(super) fn validate_graph(artifacts: &[Artifact]) -> Result<()> {
    // A retained closure must be internally consistent even when read without
    // a live catalog. The writer additionally checks all historical members.
    let mut profiles = State::default();
    for artifact in artifacts {
        profiles.insert(artifact)?;
    }
    for artifact in artifacts {
        let Definition::ProfiledRoute {
            policy,
            attachments,
            ..
        } = &artifact.definition
        else {
            continue;
        };
        ensure!(policy.is_none(), "profiled route requires a static root");
        let route = artifact
            .envelope
            .as_ref()
            .context("missing profiled route envelope")?;
        ensure!(
            route.policy.is_none() && route.policy_name.is_none(),
            "profiled policy is unsupported"
        );
        ensure!(
            ![
                "previous_response_id",
                "conversation",
                "context_management",
                "cachedContent"
            ]
            .iter()
            .any(|field| route
                .defaults
                .get(*field)
                .is_some_and(|value| !value.is_null())),
            "profiled continuation is unsupported"
        );
        let mut observed = HashSet::new();
        for chain in &route.chains {
            if !matches!(
                chain.inbound,
                ApiProtocol::ChatCompletions | ApiProtocol::Messages | ApiProtocol::Responses
            ) {
                continue;
            }
            ensure!(chain.selector == route.selector, "profiled non-root chain");
            let protocol = super::execution::generation_protocol(&chain.inbound)?;
            for (ordinal, target) in chain.targets.iter().enumerate() {
                let ordinal = u16::try_from(ordinal)?;
                ensure!(
                    observed.insert((protocol, ordinal)),
                    "duplicate profiled root"
                );
                let attachment = attachments
                    .iter()
                    .find(|item| {
                        item.inbound_protocol == protocol && item.candidate_index == ordinal
                    })
                    .context("missing admission attachment")?;
                ensure!(
                    attachment.credential == target.credential,
                    "admission credential association mismatch"
                );
                let profile = artifacts
                    .iter()
                    .find(|item| item.reference == attachment.profile)
                    .context("missing pinned admission profile")?;
                ensure!(
                    profile.definition.is_admission_profile(),
                    "admission association references another policy type"
                );
                super::execution::qualify_profiled_target(&target.target)?;
                if let Some(credential) = artifacts
                    .iter()
                    .find(|item| item.reference == target.credential)
                {
                    ensure!(matches!(&credential.definition, Definition::Credential {
                        credential: crate::gateway::providers::auth::credentials::Credential::ApiKey { .. }, oauth: None, oauth_generation: 0,
                    }), "profiled route requires static credentials");
                }
            }
        }
        ensure!(
            !observed.is_empty() && observed.len() == attachments.len(),
            "foreign admission attachment"
        );
    }
    Ok(())
}

pub(super) async fn preflight_import(
    resources: &Resources,
    db: &impl ConnectionTrait,
    imported: &[Import],
) -> Result<()> {
    if !imported.iter().any(|item| {
        item.definition.is_profiled() || matches!(item.definition, Definition::Policy { .. })
    }) {
        return Ok(());
    }
    let retained = storage::references(db).await?;
    let mut state = State::default();
    for reference in &retained {
        if reference.resource_kind == ResourceKind::Policy {
            state.insert(
                &resources
                    .load(db, reference)
                    .await
                    .map_err(|_| anyhow::anyhow!("retained profile unavailable"))?,
            )?;
        }
    }
    let mut initial = HashMap::new();
    let existing_heads = if imported
        .iter()
        .any(|item| item.definition.is_admission_profile() && retained.contains(&item.reference))
    {
        Some(
            crate::tenancy::store::load_existing(db, chrono::Utc::now())
                .await?
                .resource_lifecycle,
        )
    } else {
        None
    };
    for item in imported {
        if item.definition.is_admission_profile() && retained.contains(&item.reference) {
            ensure!(
                existing_heads
                    .as_ref()
                    .and_then(|heads| heads.head(&item.reference.key()))
                    .is_some(),
                "retained admission profile has no managed head"
            );
        }
        if item.definition.is_admission_profile() && !retained.contains(&item.reference) {
            ensure!(
                !retained
                    .iter()
                    .any(|reference| reference.key() == item.reference.key()),
                "profile rotations require authenticated CAS"
            );
            ensure!(
                initial
                    .insert(item.reference.key(), &item.reference.revision_id)
                    .is_none(),
                "ambiguous initial profile head"
            );
        }
        state.insert(&Artifact {
            reference: item.reference.clone(),
            definition: item.definition.clone(),
            envelope: None,
        })?;
    }
    Ok(())
}

pub(super) async fn initialize_import_heads(
    resources: &Resources,
    db: &impl ConnectionTrait,
    imported: &[Import],
) -> Result<()> {
    if !imported
        .iter()
        .any(|item| item.definition.is_admission_profile())
    {
        return Ok(());
    }
    let state = crate::tenancy::store::load_existing(db, chrono::Utc::now()).await?;
    ensure!(
        state.installation == resources.installation,
        "admission import installation mismatch"
    );
    for item in imported {
        if !item.definition.is_admission_profile() {
            continue;
        }
        if state
            .resource_lifecycle
            .head(&item.reference.key())
            .is_some()
        {
            continue;
        }
        lifecycle::write(
            db,
            &resources.installation,
            &lifecycle::Record {
                reference: item.reference.clone(),
                is_head: true,
                revoked: false,
                authority_revision: state.revision,
            },
        )
        .await?;
    }
    Ok(())
}
