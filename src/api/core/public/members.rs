//! The Public API's members routes, after Bitwarden's `MembersController`
//! (bitwarden/server `src/Api/AdminConsole/Public/Controllers/MembersController.cs`).
//!
//! `GET /public/members`, `GET /public/members/<id>`, `POST /public/members`, `PUT /public/members/<id>`,
//! `POST /public/members/<id>/revoke`, `.../restore` and `.../reinvite`, authorized by the organization API key.
//! Each write applies the same checks as the matching organization member route.

use rocket::{Route, serde::json::Json};

use super::{
    PublicToken,
    models::{
        MemberCreateRequest, MemberUpdateRequest, NAME_MAX, check_collections, check_groups, list_json, member_json,
        member_type, parse_body, replace_member_collections, replace_member_groups,
    },
    public_event,
};
use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::ClientIp,
    db::{
        DbConn,
        models::{
            EventType, Invitation, Membership, MembershipId, MembershipStatus, MembershipType, OrgPolicy, Organization,
            User,
        },
    },
    mail,
};

pub(super) fn routes() -> Vec<Route> {
    routes![list_members, get_member, create_member, update_member, revoke_member, restore_member, reinvite_member]
}

/// A display name from a request body: trimmed, not empty, at most `NAME_MAX` characters.
fn clean_name(name: Option<&str>) -> Option<String> {
    let name = name?.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.chars().take(NAME_MAX).collect())
}

#[get("/public/members")]
async fn list_members(token: PublicToken, conn: DbConn) -> JsonResult {
    let mut data = Vec::new();
    for member in Membership::find_by_org(&token.0, &conn).await {
        data.push(member_json(&member, &conn).await?);
    }
    Ok(Json(list_json(&data)))
}

#[get("/public/members/<member_id>")]
async fn get_member(member_id: MembershipId, token: PublicToken, conn: DbConn) -> JsonResult {
    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &token.0, &conn).await else {
        err_code!("Member not found.", format!("membership {member_id}"), 404)
    };
    Ok(Json(member_json(&member, &conn).await?))
}

/// Invite a person to the organization, as `POST /organizations/<org_id>/users/invite` does: a new address gets an
/// invitation stub (carrying the request's `name`) and, with mail enabled, the invitation mail.
#[post("/public/members", data = "<body>")]
async fn create_member(
    body: Result<Json<MemberCreateRequest>, rocket::serde::json::Error<'_>>,
    token: PublicToken,
    ip: ClientIp,
    conn: DbConn,
) -> JsonResult {
    let org_id = token.0;
    let body = parse_body(body)?;
    let (new_type, access_all) = member_type(body.member.r#type, body.member.permissions.as_ref())?;
    let email = body.email.trim().to_lowercase();
    if !crate::util::is_valid_email(&email) {
        err_code!("The email address is not valid.", 400)
    }
    let collections = body.member.collections.unwrap_or_default();
    check_collections(&org_id, &collections, &conn).await?;
    let groups = body.member.groups.unwrap_or_default();
    check_groups(&org_id, &groups, &conn).await?;
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err_code!("Organization not found.", 404)
    };
    let name = clean_name(body.member.name.as_deref());

    let mut member_status = MembershipStatus::Invited as i32;
    let (mut user, user_created) = if let Some(user) = User::find_by_mail(&email, &conn).await {
        if Membership::find_by_user_and_org(&user.uuid, &org_id, &conn).await.is_some() {
            err_code!("This user has already been invited.", 400)
        }
        if !CONFIG.mail_enabled() {
            if user.password_hash.is_empty() {
                Invitation::new(&email).save(&conn).await?;
            } else {
                // Automatically accept existing users if mail is disabled
                member_status = MembershipStatus::Accepted as i32;
            }
        }
        (user, false)
    } else {
        if !CONFIG.invitations_allowed() {
            err_code!("Invitations are not allowed.", 400)
        }
        if !CONFIG.is_email_domain_allowed(&email) {
            err_code!("Email domain not eligible for invitations.", 400)
        }
        if !CONFIG.mail_enabled() {
            Invitation::new(&email).save(&conn).await?;
        }
        let mut user = User::new(&email, name.clone());
        user.save(&conn).await?;
        (user, true)
    };
    // An invitation stub's name is the inviter's to set; an existing account keeps its own.
    if !user_created
        && user.password_hash.is_empty()
        && let Some(name) = &name
        && &user.name != name
    {
        user.name = name.clone();
        user.save(&conn).await?;
    }

    let mut member = Membership::new(user.uuid.clone(), org_id.clone(), Some(org.billing_email.clone()));
    member.set_external_id(body.member.external_id);
    member.access_all = access_all;
    member.atype = new_type as i32;
    member.status = member_status;
    member.save(&conn).await?;

    let written = async {
        replace_member_collections(&member, &collections, &conn).await?;
        replace_member_groups(&member, &groups, &conn).await?;
        if CONFIG.mail_enabled() {
            mail::send_invite(&user, org_id.clone(), member.uuid.clone(), &org.name, Some(org.billing_email.clone()))
                .await?;
        }
        Ok::<(), crate::error::Error>(())
    }
    .await;
    if let Err(e) = written {
        // Upon error delete the user, invite and org member records when needed, as the invite route does
        if user_created {
            user.delete(&conn).await?;
        } else {
            member.delete(&conn).await?;
        }
        return Err(e);
    }

    public_event(EventType::OrganizationUserInvited, &member.uuid, &org_id, &ip, &conn).await;
    Ok(Json(member_json(&member, &conn).await?))
}

/// Update a member, as `PUT /organizations/<org_id>/users/<member_id>` does: its type, External ID, collections and
/// groups. As in Bitwarden, an omitted or null `externalId` clears it, the request's `collections` replace the
/// member's direct collections and its `groups` replace the member's groups, and an absent `collections` or `groups`
/// keeps them. A revoked member stays revoked.
#[put("/public/members/<member_id>", data = "<body>")]
async fn update_member(
    member_id: MembershipId,
    body: Result<Json<MemberUpdateRequest>, rocket::serde::json::Error<'_>>,
    token: PublicToken,
    ip: ClientIp,
    conn: DbConn,
) -> JsonResult {
    let org_id = token.0;
    let body = parse_body(body)?;
    let (new_type, access_all) = member_type(body.r#type, body.permissions.as_ref())?;
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!("Member not found.", format!("membership {member_id}"), 404)
    };
    if let Some(collections) = &body.collections {
        check_collections(&org_id, collections, &conn).await?;
    }
    if let Some(groups) = &body.groups {
        check_groups(&org_id, groups, &conn).await?;
    }

    if member.atype == MembershipType::Owner
        && new_type != MembershipType::Owner
        && member.status == MembershipStatus::Confirmed as i32
        && Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1
    {
        err_code!("Can't delete the last owner.", 400)
    }

    let access_changed = member.access_all != access_all;
    member.access_all = access_all;
    member.atype = new_type as i32;
    member.set_external_id(body.external_id);
    // The organization member routes check this after changing the type, since Admins are exempt.
    OrgPolicy::check_user_allowed(&member, "modify", &conn).await?;

    if let Some(collections) = &body.collections {
        replace_member_collections(&member, collections, &conn).await?;
    } else if access_changed && member.access_all {
        replace_member_collections(&member, &[], &conn).await?;
    }
    if let Some(groups) = &body.groups {
        replace_member_groups(&member, groups, &conn).await?;
    }
    if let Some(name) = clean_name(body.name.as_deref())
        && let Some(mut user) = User::find_by_uuid(&member.user_uuid, &conn).await
        && user.password_hash.is_empty()
        && user.name != name
    {
        user.name = name;
        user.save(&conn).await?;
    }
    member.save(&conn).await?;

    public_event(EventType::OrganizationUserUpdated, &member.uuid, &org_id, &ip, &conn).await;
    Ok(Json(member_json(&member, &conn).await?))
}

/// Revoke a member, as `PUT /organizations/<org_id>/users/<member_id>/revoke` does.
#[post("/public/members/<member_id>/revoke")]
async fn revoke_member(member_id: MembershipId, token: PublicToken, ip: ClientIp, conn: DbConn) -> EmptyResult {
    let org_id = token.0;
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!("Member not found.", format!("membership {member_id}"), 404)
    };
    if member.status <= MembershipStatus::Revoked as i32 {
        err_code!("The member is already revoked.", 400)
    }
    if member.atype == MembershipType::Owner
        && Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1
    {
        err_code!("Organization must have at least one confirmed owner.", 400)
    }
    member.revoke();
    member.save(&conn).await?;

    public_event(EventType::OrganizationUserRevoked, &member.uuid, &org_id, &ip, &conn).await;
    Ok(())
}

/// Restore a revoked member to the status it held before, as `PUT /organizations/<org_id>/users/<member_id>/restore`
/// does, after the same policy checks; a refusal answers 400 with the policy's message.
#[post("/public/members/<member_id>/restore")]
async fn restore_member(member_id: MembershipId, token: PublicToken, ip: ClientIp, conn: DbConn) -> EmptyResult {
    let org_id = token.0;
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!("Member not found.", format!("membership {member_id}"), 404)
    };
    if !member.restore() {
        err_code!("The member is not revoked.", 400)
    }
    // This check needs to be done after restoring to work with the correct status
    OrgPolicy::check_user_allowed(&member, "restore", &conn).await?;
    member.save(&conn).await?;

    public_event(EventType::OrganizationUserRestored, &member.uuid, &org_id, &ip, &conn).await;
    Ok(())
}

/// Send the invitation again to a member that is still invited, as
/// `POST /organizations/<org_id>/users/<member_id>/reinvite` does.
#[post("/public/members/<member_id>/reinvite")]
async fn reinvite_member(member_id: MembershipId, token: PublicToken, conn: DbConn) -> EmptyResult {
    let org_id = token.0;
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!("Member not found.", format!("membership {member_id}"), 404)
    };
    if member.status != MembershipStatus::Invited as i32 {
        err_code!("The member is already accepted or confirmed to the organization.", 400)
    }
    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        err!("The member's user record is missing.", format!("membership {member_id}"))
    };
    if !CONFIG.invitations_allowed() && user.password_hash.is_empty() {
        err_code!("Invitations are not allowed.", 400)
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err_code!("Organization not found.", 404)
    };

    if CONFIG.mail_enabled() {
        mail::send_invite(&user, org_id, member.uuid, &org.name, Some(org.billing_email)).await?;
    } else if user.password_hash.is_empty() {
        Invitation::new(&user.email).save(&conn).await?;
    } else {
        Invitation::take(&user.email, &conn).await;
        member.status = MembershipStatus::Accepted as i32;
        member.save(&conn).await?;
    }
    Ok(())
}
