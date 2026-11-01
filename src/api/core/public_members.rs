//! Kount: Bitwarden's public members API (apps/vaultwarden-kount/README.md § The routes).
//!
//! `GET /public/members`, `GET /public/members/<id>`, `POST /public/members`,
//! `PUT /public/members/<id>`, `POST /public/members/<id>/revoke`, `…/restore`, `…/reinvite`, all
//! under the organisation API key's token (`PublicToken`). Two Kount deviations, never filed
//! upstream: only type User is created or written (400 for another type in a body, 409 when the
//! TARGET is not a User, checked inside the write's own transaction), and the
//! `KOUNT_PUBLIC_MEMBER_AUTO_ACCEPT` flag (off by default).

use rocket::{Route, serde::json::Json};

use super::{
    PublicToken,
    public_models::{
        NAME_MAX, PublicMemberCreate, PublicMemberUpdate, bad_body, check_collections, list_json, member_json,
        replace_collections, require_user_type, with_user_member,
    },
};
use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    db::{
        DbConn,
        models::{Invitation, Membership, MembershipId, MembershipStatus, MembershipType, OrgPolicy, Organization, SsoUser, User},
    },
    mail,
};

pub(super) fn routes() -> Vec<Route> {
    routes![
        list_members,
        get_member,
        create_member,
        update_member,
        revoke_member,
        restore_member,
        reinvite_member
    ]
}

/// A display name from a body: trimmed, non-empty, at most NAME_MAX characters.
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
    Ok(Json(list_json(data)))
}

#[get("/public/members/<member_id>")]
async fn get_member(member_id: MembershipId, token: PublicToken, conn: DbConn) -> JsonResult {
    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &token.0, &conn).await else {
        err_code!("Member not found.", format!("membership {member_id}"), 404)
    };
    Ok(Json(member_json(&member, &conn).await?))
}

/// Invite a person as a User with the given collections. A new address gets an invitation stub
/// carrying the body's `name`; with mail on, the invitation mail is sent. Under
/// `KOUNT_PUBLIC_MEMBER_AUTO_ACCEPT`, an existing user who already has an SSO link lands as
/// Accepted (after the accept-time policy checks) and no mail is sent.
#[post("/public/members", data = "<body>")]
async fn create_member(
    body: Result<Json<PublicMemberCreate>, rocket::serde::json::Error<'_>>,
    token: PublicToken,
    conn: DbConn,
) -> JsonResult {
    let org_id = token.0;
    let body = bad_body(body)?;
    require_user_type(body.member.r#type)?;
    let email = body.email.trim().to_lowercase();
    if !crate::util::is_valid_email(&email) {
        err_code!("The email address is not valid.", 400)
    }
    let collections = body.member.collections.unwrap_or_default();
    check_collections(&org_id, &collections, &conn).await?;
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err_code!("Organization not found.", 404)
    };
    let name = clean_name(body.member.name.as_deref());

    let existing = SsoUser::find_by_mail(&email, &conn).await;
    if let Some((user, _)) = &existing
        && Membership::find_by_user_and_org(&user.uuid, &org_id, &conn).await.is_some()
    {
        err_code!("This user is already a member of the organization.", 400)
    }
    let (mut user, sso_linked, user_created) = match existing {
        Some((user, sso)) => (user, sso.is_some(), false),
        None => {
            if !CONFIG.invitations_allowed() {
                err_code!("Invitations are not allowed.", 400)
            }
            if !CONFIG.is_email_domain_allowed(&email) {
                err_code!("Email domain not eligible for invitations.", 400)
            }
            let mut user = User::new(&email, name.clone());
            user.save(&conn).await?;
            if !CONFIG.mail_enabled() {
                Invitation::new(&email).save(&conn).await?;
            }
            (user, false, true)
        }
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

    let auto_accept = CONFIG.kount_public_member_auto_accept() && sso_linked;
    let status = if auto_accept || (!CONFIG.mail_enabled() && !user.password_hash.is_empty()) {
        MembershipStatus::Accepted as i32
    } else {
        MembershipStatus::Invited as i32
    };

    let mut member = Membership::new(user.uuid.clone(), org_id.clone(), Some(org.billing_email.clone()));
    member.set_external_id(body.member.external_id);
    member.access_all = false;
    member.atype = MembershipType::User as i32;
    member.status = status;
    if auto_accept {
        // The checks upstream applies when an invitation is accepted (2FA, SingleOrg).
        OrgPolicy::check_user_allowed(&member, "join", &conn).await?;
    }
    member.save(&conn).await?;
    if let Err(e) = replace_collections(&member, &collections, &conn).await {
        undo_create(user, member, user_created, &conn).await?;
        return Err(e);
    }

    if status == MembershipStatus::Invited as i32
        && CONFIG.mail_enabled()
        && let Err(e) = mail::send_invite(&user, org_id, member.uuid.clone(), &org.name, Some(org.billing_email)).await
    {
        undo_create(user, member, user_created, &conn).await?;
        err!(format!("Error sending invite: {e:?}"))
    }

    Ok(Json(member_json(&member, &conn).await?))
}

/// Upstream's clean-up after a failed invite: the stub user if this call made it, else the membership.
async fn undo_create(user: User, member: Membership, user_created: bool, conn: &DbConn) -> EmptyResult {
    if user_created {
        user.delete(conn).await
    } else {
        member.delete(conn).await
    }
}

/// Replace the member's external id and collections (Bitwarden's semantics: the body's
/// `collections` replace the member's direct collections; an absent `collections` keeps them).
/// Accepted on a Revoked member, which stays Revoked with its prior status kept for `restore`.
#[put("/public/members/<member_id>", data = "<body>")]
async fn update_member(
    member_id: MembershipId,
    body: Result<Json<PublicMemberUpdate>, rocket::serde::json::Error<'_>>,
    token: PublicToken,
    conn: DbConn,
) -> JsonResult {
    let conn = &conn;
    let org_id = token.0;
    let body = bad_body(body)?;
    require_user_type(body.r#type)?;
    if let Some(collections) = &body.collections {
        check_collections(&org_id, collections, conn).await?;
    }
    let name = clean_name(body.name.as_deref());
    let (external_id, collections) = (body.external_id, body.collections);
    let member = with_user_member(&org_id, &member_id, conn, async move |mut member| {
        member.set_external_id(external_id);
        member.access_all = false;
        member.save(conn).await?;
        if let Some(collections) = &collections {
            replace_collections(&member, collections, conn).await?;
        }
        if let Some(name) = name
            && let Some(mut user) = User::find_by_uuid(&member.user_uuid, conn).await
            && user.password_hash.is_empty()
            && user.name != name
        {
            user.name = name;
            user.save(conn).await?;
        }
        Ok(member)
    })
    .await?;
    Ok(Json(member_json(&member, conn).await?))
}

#[post("/public/members/<member_id>/revoke")]
async fn revoke_member(member_id: MembershipId, token: PublicToken, conn: DbConn) -> EmptyResult {
    let conn = &conn;
    with_user_member(&token.0, &member_id, conn, async move |mut member| {
        if !member.revoke() {
            err_code!("The member is already revoked.", 400)
        }
        member.save(conn).await
    })
    .await
}

/// Restore a Revoked member to the status it held when revoked, after the policy checks every
/// upstream restore path runs; a refusal answers 400 with the policy's message.
#[post("/public/members/<member_id>/restore")]
async fn restore_member(member_id: MembershipId, token: PublicToken, conn: DbConn) -> EmptyResult {
    let conn = &conn;
    with_user_member(&token.0, &member_id, conn, async move |mut member| {
        if !member.restore() {
            err_code!("The member is not revoked.", 400)
        }
        OrgPolicy::check_user_allowed(&member, "restore", conn).await?;
        member.save(conn).await
    })
    .await
}

/// Send the invitation again to a member still Invited (upstream's reinvite rules). With mail on,
/// the mail goes out after the guarded transaction commits; with mail off, the database writes
/// upstream makes instead happen inside it.
#[post("/public/members/<member_id>/reinvite")]
async fn reinvite_member(member_id: MembershipId, token: PublicToken, conn: DbConn) -> EmptyResult {
    let conn = &conn;
    let org_id = token.0;
    let Some(org) = Organization::find_by_uuid(&org_id, conn).await else {
        err_code!("Organization not found.", 404)
    };
    let (member, user) = with_user_member(&org_id, &member_id, conn, async move |mut member| {
        if member.status != MembershipStatus::Invited as i32 {
            err_code!("The member is not in the Invited state.", 400)
        }
        let Some(user) = User::find_by_uuid(&member.user_uuid, conn).await else {
            err!("The member's user record is missing.")
        };
        if !CONFIG.invitations_allowed() && user.password_hash.is_empty() {
            err_code!("Invitations are not allowed.", 400)
        }
        if !CONFIG.mail_enabled() {
            if user.password_hash.is_empty() {
                Invitation::new(&user.email).save(conn).await?;
            } else {
                Invitation::take(&user.email, conn).await;
                member.status = MembershipStatus::Accepted as i32;
                member.save(conn).await?;
            }
        }
        Ok((member, user))
    })
    .await?;
    if CONFIG.mail_enabled() {
        mail::send_invite(&user, org_id, member.uuid, &org.name, Some(org.billing_email)).await?;
    }
    Ok(())
}
