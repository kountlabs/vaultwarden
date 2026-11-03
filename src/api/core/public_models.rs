//! Kount: the request and response models of Bitwarden's public API for members and collections,
//! and the one guarded-write helper the member routes share (apps/vaultwarden-kount/README.md).
//!
//! Shapes follow bitwarden/server `src/Api/AdminConsole/Public/Models` (MemberResponseModel,
//! MemberCreateRequestModel / MemberUpdateRequestModel, AssociationWithPermissions*,
//! CollectionResponseModel / CollectionUpdateRequestModel). Every route is a server-side ACL or
//! membership write; none touches a key.

use diesel::{
    connection::{Connection, TransactionManager},
    prelude::*,
};
use serde_json::Value;

use crate::{
    CONFIG,
    api::ApiResult,
    db::{
        DbConn, DbConnInner,
        models::{
            Collection, CollectionGroup, CollectionId, CollectionUser, Membership, MembershipId, MembershipStatus,
            MembershipType, OrganizationId, SsoUser, TwoFactor, User,
        },
        schema::users_organizations,
    },
    error::MapResult,
};

/// One collection a member may use, with its access flags.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PublicCollectionAccess {
    pub id: CollectionId,
    pub read_only: bool,
    #[serde(default)]
    pub hide_passwords: bool,
    #[serde(default)]
    pub manage: bool,
}

/// `MemberUpdateRequestModel` (and the body of `MemberCreateRequestModel` beside `email`).
/// `groups` and `permissions` are accepted and ignored: groups are not managed through this build,
/// and only type User is ever written (the Kount guard).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PublicMemberUpdate {
    pub r#type: i32,
    pub external_id: Option<String>,
    pub name: Option<String>,
    pub collections: Option<Vec<PublicCollectionAccess>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PublicMemberCreate {
    pub email: String,
    #[serde(flatten)]
    pub member: PublicMemberUpdate,
}

/// `CollectionUpdateRequestModel`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PublicCollectionUpdate {
    pub external_id: Option<String>,
    #[serde(default)]
    pub groups: Vec<Value>,
}

/// The longest display name accepted for an invited person.
pub(super) const NAME_MAX: usize = 200;

/// A body that did not parse is a 400, as Bitwarden's model validation answers.
pub(super) fn bad_body<T>(body: Result<rocket::serde::json::Json<T>, rocket::serde::json::Error<'_>>) -> ApiResult<T> {
    match body {
        Ok(json) => Ok(json.into_inner()),
        Err(e) => err_code!("The request body is not valid.", format!("public API body: {e}"), 400),
    }
}

/// The Kount guard: only members of type User are created or updated through the public API.
pub(super) fn require_user_type(atype: i32) -> ApiResult<()> {
    if atype != MembershipType::User as i32 {
        err_code!("Only members of type User (2) can be written through this API.", 400)
    }
    Ok(())
}

/// Every collection named must belong to the organisation.
pub(super) async fn check_collections(
    org_id: &OrganizationId,
    collections: &[PublicCollectionAccess],
    conn: &DbConn,
) -> ApiResult<()> {
    for access in collections {
        if Collection::find_by_uuid_and_org(&access.id, org_id, conn).await.is_none() {
            err_code!("Collection not found in the organization.", format!("collection {}", access.id), 400)
        }
    }
    Ok(())
}

/// Replace the member's direct collection access in this organisation with `collections`.
pub(super) async fn replace_collections(
    member: &Membership,
    collections: &[PublicCollectionAccess],
    conn: &DbConn,
) -> ApiResult<()> {
    for current in CollectionUser::find_by_organization_and_user_uuid(&member.org_uuid, &member.user_uuid, conn).await {
        current.delete(conn).await?;
    }
    for access in collections {
        CollectionUser::save(
            &member.user_uuid,
            &access.id,
            access.read_only,
            access.hide_passwords,
            access.manage,
            conn,
        )
        .await?;
    }
    Ok(())
}

/// `MemberResponseModel`. The display name is shown once the person has accepted, or while the
/// account is still an invitation stub (the name then came from the inviter) — never an existing
/// account's own name before it joins.
pub(super) async fn member_json(member: &Membership, conn: &DbConn) -> ApiResult<Value> {
    let Some(user) = User::find_by_uuid(&member.user_uuid, conn).await else {
        err!("The member's user record is missing.", format!("membership {}", member.uuid))
    };
    let sso_external_id = match SsoUser::find_by_mail(&user.email, conn).await {
        Some((_, Some(sso))) => Some(sso.identifier.to_string()),
        _ => None,
    };
    let status = if member.status < MembershipStatus::Revoked as i32 {
        MembershipStatus::Revoked as i32
    } else {
        member.status
    };
    let accepted = member.get_unrevoked_status() >= MembershipStatus::Accepted as i32;
    let name = if accepted || user.password_hash.is_empty() {
        Some(user.name.clone())
    } else {
        None
    };
    let collections: Vec<Value> = if member.access_all {
        Vec::new()
    } else {
        CollectionUser::find_by_organization_and_user_uuid(&member.org_uuid, &member.user_uuid, conn)
            .await
            .into_iter()
            .map(|access| {
                json!({
                    "id": access.collection_uuid,
                    "readOnly": access.read_only,
                    "hidePasswords": access.hide_passwords,
                    "manage": access.manage,
                })
            })
            .collect()
    };
    Ok(json!({
        "object": "member",
        "id": member.uuid,
        "userId": member.user_uuid,
        "name": name,
        "email": user.email,
        "twoFactorEnabled": !TwoFactor::find_by_user(&user.uuid, conn).await.is_empty(),
        "status": status,
        "collections": collections,
        "type": member.type_manager_as_custom(),
        "externalId": member.external_id,
        "resetPasswordEnrolled": member.reset_password_key.is_some(),
        "ssoExternalId": sso_external_id,
        "permissions": null,
    }))
}

/// `CollectionResponseModel`. Names are encrypted, so a collection is identified by its id and its
/// plaintext External ID; group access is listed only when groups are enabled.
pub(super) async fn collection_json(collection: &Collection, conn: &DbConn) -> Value {
    let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
        CollectionGroup::find_by_collection(&collection.uuid, conn)
            .await
            .into_iter()
            .map(|access| {
                json!({
                    "id": access.groups_uuid,
                    "readOnly": access.read_only,
                    "hidePasswords": access.hide_passwords,
                    "manage": access.manage,
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    json!({
        "object": "collection",
        "id": collection.uuid,
        "externalId": collection.external_id,
        "groups": groups,
    })
}

pub(super) fn list_json(data: Vec<Value>) -> Value {
    json!({
        "object": "list",
        "data": data,
        "continuationToken": null,
    })
}

/// The connection's own transaction manager: a transaction left open by a panic is then visible
/// to the pool's broken-connection check, unlike a raw `BEGIN`.
type Tm = <DbConnInner as Connection>::TransactionManager;

/// The Kount guarded write: in ONE database transaction, lock the target membership's row, re-read
/// it under that lock, refuse with 404 when it is gone and with 409 when it is not of type User, then
/// run `write`. A vault Owner promoting the member between a caller's read and this write is thereby
/// caught here, at write time. Any error rolls the transaction back.
pub(super) async fn with_user_member<T>(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    conn: &DbConn,
    write: impl AsyncFnOnce(Membership) -> ApiResult<T>,
) -> ApiResult<T> {
    let _: () = conn.run(|c| <Tm as TransactionManager<DbConnInner>>::begin_transaction(c)).await.map_res("Error starting a transaction")?;

    let result = async {
        let (lock_org, lock_member) = (org_id.clone(), member_id.clone());
        let _: () = conn
            .run(move |c| {
                // A no-op update takes the row's write lock (PostgreSQL / MySQL) or the database's
                // (SQLite) until the transaction ends; the re-read below then sees the current row.
                diesel::update(
                    users_organizations::table
                        .filter(users_organizations::uuid.eq(lock_member))
                        .filter(users_organizations::org_uuid.eq(lock_org)),
                )
                .set(users_organizations::atype.eq(users_organizations::atype))
                .execute(c)
            })
            .await
            .map_res("Error locking the membership")?;

        let Some(member) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
            err_code!("Member not found.", format!("membership {member_id}"), 404)
        };
        if member.atype != MembershipType::User as i32 {
            err_code!(
                "Only members of type User (2) can be changed through this API.",
                format!("membership {member_id} is of type {}", member.atype),
                409
            )
        }
        write(member).await
    }
    .await;

    let end: ApiResult<()> = if result.is_ok() {
        conn.run(|c| <Tm as TransactionManager<DbConnInner>>::commit_transaction(c))
            .await
            .map_res("Error committing the transaction")
    } else {
        conn.run(|c| <Tm as TransactionManager<DbConnInner>>::rollback_transaction(c))
            .await
            .map_res("Error rolling back the transaction")
    };
    match (result, end) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(e), _) | (Ok(_), Err(e)) => Err(e),
    }
}
