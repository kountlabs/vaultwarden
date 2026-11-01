//! Request and response models of the Public API's members, collections and policies routes, and the helpers
//! those routes share.
//!
//! The shapes follow Bitwarden's Public API models:
//! - `src/Api/AdminConsole/Public/Models`: `MemberResponseModel`, `MemberCreateRequestModel`,
//!   `MemberUpdateRequestModel`, `AssociationWithPermissionsRequestModel` / `...ResponseModel`, `PolicyResponseModel`
//! - `src/Api/AdminConsole/Models/Public`: `CollectionResponseModel`, `CollectionUpdateRequestModel`
//!
//! Every route is an ACL or membership change made by the server; none of them needs or touches a key.

use std::collections::HashMap;

use serde_json::Value;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult},
    db::{
        DbConn,
        models::{
            Collection, CollectionGroup, CollectionId, CollectionUser, Group, GroupId, GroupUser, Membership,
            MembershipStatus, MembershipType, OrgPolicy, OrganizationId, SsoUser, TwoFactor, User,
        },
    },
};

/// `AssociationWithPermissionsRequestModel`: one collection (or, on a collection, one group) and its access flags.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AssociationWithPermissions<T> {
    pub id: T,
    pub read_only: bool,
    #[serde(default)]
    pub hide_passwords: bool,
    #[serde(default)]
    pub manage: bool,
}

pub(super) type CollectionAccess = AssociationWithPermissions<CollectionId>;
pub(super) type GroupAccess = AssociationWithPermissions<GroupId>;

/// `MemberUpdateRequestModel`. `email` is accepted and ignored: Bitwarden only changes it for a claimed member,
/// which Vaultwarden has no notion of.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MemberUpdateRequest {
    pub r#type: i32,
    pub external_id: Option<String>,
    pub name: Option<String>,
    pub collections: Option<Vec<CollectionAccess>>,
    pub groups: Option<Vec<GroupId>>,
    pub permissions: Option<HashMap<String, Value>>,
}

/// `MemberCreateRequestModel`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MemberCreateRequest {
    pub email: String,
    #[serde(flatten)]
    pub member: MemberUpdateRequest,
}

/// `CollectionUpdateRequestModel`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CollectionUpdateRequest {
    pub external_id: Option<String>,
    pub groups: Option<Vec<GroupAccess>>,
}

/// The longest display name accepted for an invited person.
pub(super) const NAME_MAX: usize = 200;

/// A body that does not parse is a 400, as Bitwarden's model validation answers it.
pub(super) fn parse_body<T>(
    body: Result<rocket::serde::json::Json<T>, rocket::serde::json::Error<'_>>,
) -> ApiResult<T> {
    match body {
        Ok(json) => Ok(json.into_inner()),
        Err(e) => err_code!("The request body is not valid.", format!("Public API request body: {e}"), 400),
    }
}

/// The member type of a request as the organization member routes store it, with the `access_all` flag they derive
/// from it: `MembershipType::from_str` stores Custom (4) as Manager (3), and a Custom member whose three collection
/// permissions are all set gets access to every collection.
pub(super) fn member_type(
    atype: i32,
    permissions: Option<&HashMap<String, Value>>,
) -> ApiResult<(MembershipType, bool)> {
    let Some(new_type) = MembershipType::from_str(&atype.to_string()) else {
        err_code!("Invalid member type.", format!("member type {atype}"), 400)
    };
    let permission = |name: &str| permissions.and_then(|p| p.get(name)) == Some(&json!(true));
    let access_all = new_type >= MembershipType::Admin
        || (atype == 4
            && permission("editAnyCollection")
            && permission("deleteAnyCollection")
            && permission("createNewCollections"));
    Ok((new_type, access_all))
}

/// Every collection named must belong to the organization.
pub(super) async fn check_collections(
    org_id: &OrganizationId,
    collections: &[CollectionAccess],
    conn: &DbConn,
) -> EmptyResult {
    for access in collections {
        if Collection::find_by_uuid_and_org(&access.id, org_id, conn).await.is_none() {
            err_code!("Collection not found in the organization.", format!("collection {}", access.id), 400)
        }
    }
    Ok(())
}

/// Every group named must belong to the organization.
pub(super) async fn check_groups(org_id: &OrganizationId, groups: &[GroupId], conn: &DbConn) -> EmptyResult {
    for group_id in groups {
        if Group::find_by_uuid_and_org(group_id, org_id, conn).await.is_none() {
            err_code!("Group not found in the organization.", format!("group {group_id}"), 400)
        }
    }
    Ok(())
}

/// Replace the member's direct collection access in this organization with `collections`. A member with access to
/// every collection keeps none, as with the organization member routes.
pub(super) async fn replace_member_collections(
    member: &Membership,
    collections: &[CollectionAccess],
    conn: &DbConn,
) -> EmptyResult {
    for current in CollectionUser::find_by_organization_and_user_uuid(&member.org_uuid, &member.user_uuid, conn).await {
        current.delete(conn).await?;
    }
    if member.access_all {
        return Ok(());
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

/// Replace the member's groups with `groups`.
pub(super) async fn replace_member_groups(member: &Membership, groups: &[GroupId], conn: &DbConn) -> EmptyResult {
    GroupUser::delete_all_by_member(&member.uuid, conn).await?;
    for group_id in groups {
        GroupUser::new(group_id.clone(), member.uuid.clone()).save(conn).await?;
    }
    Ok(())
}

/// Replace the groups that can access the collection with `groups`.
pub(super) async fn replace_collection_groups(
    collection: &Collection,
    groups: &[GroupAccess],
    conn: &DbConn,
) -> EmptyResult {
    CollectionGroup::delete_all_by_collection(&collection.uuid, &collection.org_uuid, conn).await?;
    for access in groups {
        CollectionGroup::new(
            collection.uuid.clone(),
            access.id.clone(),
            access.read_only,
            access.hide_passwords,
            access.manage,
        )
        .save(&collection.org_uuid, conn)
        .await?;
    }
    Ok(())
}

/// `MemberResponseModel`. The name is shown once the person has accepted, or while the account is still an
/// invitation stub (the name then came from the inviter), never an existing account's own name before it joins.
pub(super) async fn member_json(member: &Membership, conn: &DbConn) -> ApiResult<Value> {
    let Some(user) = User::find_by_uuid(&member.user_uuid, conn).await else {
        err!("The member's user record is missing.", format!("membership {}", member.uuid))
    };
    let sso_external_id = match SsoUser::find_by_mail(&user.email, conn).await {
        Some((_, Some(sso))) => Some(sso.identifier.to_string()),
        _ => None,
    };
    // A revoked member's stored status encodes the status it held before; Bitwarden reports it as Revoked.
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
    let member_type = member.type_manager_as_custom();
    // As the organization member routes do: a Custom member with access to every collection reports the three
    // collection permissions that grant it.
    let permissions = if member_type == 4 {
        json!({
            "accessEventLogs": false,
            "accessImportExport": false,
            "accessReports": false,
            "createNewCollections": member.access_all,
            "editAnyCollection": member.access_all,
            "deleteAnyCollection": member.access_all,
            "manageGroups": false,
            "managePolicies": false,
            "manageSso": false,
            "manageUsers": false,
            "manageResetPassword": false,
            "manageScim": false,
        })
    } else {
        Value::Null
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
        "type": member_type,
        "externalId": member.external_id,
        "resetPasswordEnrolled": member.reset_password_key.is_some(),
        "ssoExternalId": sso_external_id,
        "permissions": permissions,
    }))
}

/// `CollectionResponseModel`. A collection's name is encrypted, so it is identified by its id and its plain-text
/// External ID; group access is listed when groups are enabled.
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

/// `PolicyResponseModel`.
pub(super) fn policy_json(policy: &OrgPolicy) -> Value {
    json!({
        "object": "policy",
        "id": policy.uuid,
        "type": policy.atype,
        "enabled": policy.enabled,
        "data": serde_json::from_str::<Value>(&policy.data).unwrap_or(Value::Null),
    })
}

/// `ListResponseModel`.
pub(super) fn list_json(data: &[Value]) -> Value {
    json!({
        "object": "list",
        "data": data,
        "continuationToken": null,
    })
}
