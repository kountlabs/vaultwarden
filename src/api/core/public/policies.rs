//! The Public API's policies routes, after Bitwarden's `PoliciesController`
//! (bitwarden/server `src/Api/AdminConsole/Public/Controllers/PoliciesController.cs`).
//!
//! `GET /public/policies`, `GET /public/policies/<type>` and `PUT /public/policies/<type>`, authorized by the
//! organization API key. `PUT` goes through the same checks and side effects as
//! `PUT /organizations/<org_id>/policies/<type>` (Bitwarden's public route also uses its `SavePolicyCommand`).

use rocket::{Route, serde::json::Json};

use super::{
    ACTING_PUBLIC_API_USER, PUBLIC_API_DEVICE_TYPE, PublicToken,
    models::{list_json, parse_body, policy_json},
};
use crate::{
    api::{
        JsonResult,
        core::organizations::{PolicyData, save_policy},
    },
    auth::ClientIp,
    db::{DbConn, models::OrgPolicy},
};

pub(super) fn routes() -> Vec<Route> {
    routes![list_policies, get_policy, put_policy]
}

#[get("/public/policies")]
async fn list_policies(token: PublicToken, conn: DbConn) -> JsonResult {
    let data: Vec<_> = OrgPolicy::find_by_org(&token.0, &conn).await.iter().map(policy_json).collect();
    Ok(Json(list_json(&data)))
}

#[get("/public/policies/<pol_type>")]
async fn get_policy(pol_type: i32, token: PublicToken, conn: DbConn) -> JsonResult {
    let Some(policy) = OrgPolicy::find_by_org(&token.0, &conn).await.into_iter().find(|p| p.atype == pol_type) else {
        err_code!("Policy not found.", format!("policy type {pol_type}"), 404)
    };
    Ok(Json(policy_json(&policy)))
}

/// Enable or disable a policy and set its data (`PolicyUpdateRequestModel`: `enabled`, `data`). As in Bitwarden, an
/// omitted `data` resets it.
#[put("/public/policies/<pol_type>", data = "<body>")]
async fn put_policy(
    pol_type: i32,
    body: Result<Json<PolicyData>, rocket::serde::json::Error<'_>>,
    token: PublicToken,
    ip: ClientIp,
    conn: DbConn,
) -> JsonResult {
    let data = parse_body(body)?;
    let policy =
        save_policy(&token.0, pol_type, data, &ACTING_PUBLIC_API_USER.into(), PUBLIC_API_DEVICE_TYPE, &ip.ip, &conn)
            .await?;
    Ok(Json(policy_json(&policy)))
}
