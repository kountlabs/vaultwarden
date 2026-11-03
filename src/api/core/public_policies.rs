//! Kount: Bitwarden's public policies API (apps/vaultwarden-kount/README.md § The routes; plan D24).
//!
//! `GET /public/policies`, `GET /public/policies/<type>`, `PUT /public/policies/<type>`, under the organisation
//! API key's token. One Kount deviation, never filed upstream: `PUT` writes only ActivateAutofill (11) and
//! ResetPassword (8). Upstream's Owner policy route has enforcement side effects this route would skip —
//! enabling 2FA or SingleOrg revokes members — and Kount Protect needs only these two.

use rocket::{Route, serde::json::Json};
use serde_json::Value;

use super::{
    PublicToken,
    public_models::{bad_body, list_json},
};
use crate::{
    CONFIG,
    api::JsonResult,
    db::{
        DbConn,
        models::{OrgPolicy, OrgPolicyType},
    },
};

pub(super) fn routes() -> Vec<Route> {
    routes![list_policies, get_policy, put_policy]
}

/// `PolicyUpdateRequestModel`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicPolicyUpdate {
    enabled: bool,
    data: Option<Value>,
}

/// `PolicyResponseModel`.
fn policy_json(policy: &OrgPolicy) -> Value {
    json!({
        "object": "policy",
        "id": policy.uuid,
        "type": policy.atype,
        "enabled": policy.enabled,
        "data": serde_json::from_str::<Value>(&policy.data).unwrap_or(Value::Null),
    })
}

#[get("/public/policies")]
async fn list_policies(token: PublicToken, conn: DbConn) -> JsonResult {
    let data = OrgPolicy::find_by_org(&token.0, &conn).await.iter().map(policy_json).collect();
    Ok(Json(list_json(data)))
}

/// Any stored type is readable, matched by its integer (a row of a type this build no longer knows included).
#[get("/public/policies/<pol_type>")]
async fn get_policy(pol_type: i32, token: PublicToken, conn: DbConn) -> JsonResult {
    let Some(policy) = OrgPolicy::find_by_org(&token.0, &conn).await.into_iter().find(|p| p.atype == pol_type) else {
        err_code!("Policy not found.", format!("policy type {pol_type}"), 404)
    };
    Ok(Json(policy_json(&policy)))
}

#[put("/public/policies/<pol_type>", data = "<body>")]
async fn put_policy(
    pol_type: i32,
    body: Result<Json<PublicPolicyUpdate>, rocket::serde::json::Error<'_>>,
    token: PublicToken,
    conn: DbConn,
) -> JsonResult {
    let org_id = token.0;
    // The Kount guard: only the two policies Kount Protect sets, before any read or write.
    let pol_type_enum = match pol_type {
        8 => OrgPolicyType::ResetPassword,
        11 => OrgPolicyType::ActivateAutofill,
        _ => err_code!("Only policies 8 (ResetPassword) and 11 (ActivateAutofill) can be written through this API.", 400),
    };
    let body = bad_body(body)?;

    let data = match pol_type_enum {
        OrgPolicyType::ResetPassword => {
            let auto_enroll = body.data.as_ref().and_then(|d| d.get("autoEnrollEnabled")).and_then(Value::as_bool);
            if body.enabled && auto_enroll.is_none() {
                err_code!("Policy 8 needs data.autoEnrollEnabled (a boolean).", 400)
            }
            // The Owner route's prerequisite, when the operator turned it on.
            if body.enabled && CONFIG.enforce_single_org_with_reset_pw_policy() {
                let single_org = OrgPolicy::find_by_org_and_type(&org_id, OrgPolicyType::SingleOrg, &conn).await;
                if !single_org.is_some_and(|p| p.enabled) {
                    err_code!(
                        "Single Organization policy is not enabled. It is mandatory for this policy to be enabled.",
                        400
                    )
                }
            }
            json!({ "autoEnrollEnabled": auto_enroll.unwrap_or(false) })
        }
        _ => Value::Null,
    };

    let mut policy = match OrgPolicy::find_by_org_and_type(&org_id, pol_type_enum, &conn).await {
        Some(p) => p,
        None => OrgPolicy::new(org_id.clone(), pol_type_enum, false, "null".to_owned()),
    };
    policy.enabled = body.enabled;
    policy.data = serde_json::to_string(&data)?;
    policy.save(&conn).await?;
    Ok(Json(policy_json(&policy)))
}
