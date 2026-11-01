//! Bounded nonsecret credential history under the authority actor's read custody.

use bitrouter_ai::tenancy::{
    directory::{DirectoryCursorV1, DirectoryEntryV1},
    identity::AuthorityRevision,
};
use sea_orm::sea_query::{Condition, ExprTrait, Order};

use super::*;

pub(in crate::tenancy) async fn credentials(
    db: &DatabaseConnection,
    revision: AuthorityRevision,
    after: Option<&DirectoryCursorV1>,
    limit: usize,
    control: &Control,
) -> Result<Vec<DirectoryEntryV1>> {
    let txn = control.begin(db).await?;
    let result = read(&txn, revision, after, limit, control).await;
    control.rollback(txn).await?;
    result
}

async fn read(
    txn: &DatabaseTransaction,
    revision: AuthorityRevision,
    after: Option<&DirectoryCursorV1>,
    limit: usize,
    control: &Control,
) -> Result<Vec<DirectoryEntryV1>> {
    control.check_read()?;
    let identity = Query::select()
        .column(Alias::new("authority_revision"))
        .from(Alias::new("tenancy_installation"))
        .and_where(Expr::col(Alias::new("singleton")).eq(1_i32))
        .to_owned();
    let row = txn
        .query_one(txn.get_database_backend().build(&identity))
        .await?
        .context("directory authority missing")?;
    ensure!(
        u64::try_from(row.try_get::<i64>("", "authority_revision")?)? == revision.get(),
        "directory authority mismatch"
    );
    control.check_read()?;

    // This authority is exclusively owned SQLite. Explicit BINARY collation
    // preserves ASCII key ordering independently of schema collation defaults.
    // https://www.sqlite.org/datatype3.html#collating_sequences
    let tenant = || Expr::cust("tenant_id COLLATE BINARY");
    let id = || Expr::cust("id COLLATE BINARY");
    let mut query = Query::select();
    query
        .columns(
            [
                "tenant_id",
                "id",
                "revision",
                "principal_id",
                "binding_id",
                "permissions_json",
                "scope_json",
                "expires_at",
                "state",
                "audit_reader",
            ]
            .map(Alias::new),
        )
        .from(Alias::new("tenancy_credentials"))
        .order_by_expr(tenant(), Order::Asc)
        .order_by_expr(id(), Order::Asc)
        .limit(u64::try_from(limit)?);
    if let Some(cursor) = after.filter(|cursor| cursor.key().0 == "credential") {
        let (_, tenant_id, credential_id) = cursor.key();
        query.cond_where(
            Condition::any().add(tenant().gt(tenant_id)).add(
                Condition::all()
                    .add(tenant().eq(tenant_id))
                    .add(id().gt(credential_id)),
            ),
        );
    }
    let rows = txn
        .query_all(txn.get_database_backend().build(&query))
        .await?;
    control.check_read()?;
    rows.iter()
        .map(|row| {
            let entry = DirectoryEntryV1::Credential {
                tenant_id: string(row, "tenant_id")?.try_into()?,
                credential_id: string(row, "id")?.try_into()?,
                revision_id: string(row, "revision")?.try_into()?,
                principal_id: string(row, "principal_id")?.try_into()?,
                binding_id: row
                    .try_get::<Option<String>>("", "binding_id")?
                    .map(TryInto::try_into)
                    .transpose()?,
                permissions: json_from(row, "permissions_json")?,
                scope: json_from(row, "scope_json")?,
                expires_at: string(row, "expires_at")?.try_into()?,
                recorded_state: enum_from(row, "state")?,
                audit_reader: row.try_get("", "audit_reader")?,
            };
            entry.validate()?;
            Ok(entry)
        })
        .collect()
}
