//! The Public API's collections routes, after Bitwarden's `CollectionsController`
//! (bitwarden/server `src/Api/AdminConsole/Public/Controllers/CollectionsController.cs`).
//!
//! `GET /public/collections`, `GET /public/collections/<id>` and `PUT /public/collections/<id>`, authorized by the
//! organization API key. A collection's name is encrypted with the organization key, which the server does not
//! have, so these routes read and write only its External ID and its group access.

use rocket::{Route, serde::json::Json};

use super::{
    PublicToken,
    models::{
        CollectionUpdateRequest, check_groups, collection_json, list_json, parse_body, replace_collection_groups,
    },
    public_event,
};
use crate::{
    api::JsonResult,
    auth::ClientIp,
    db::{
        DbConn,
        models::{Collection, CollectionId, EventType},
    },
};

pub(super) fn routes() -> Vec<Route> {
    routes![list_collections, get_collection, update_collection]
}

#[get("/public/collections")]
async fn list_collections(token: PublicToken, conn: DbConn) -> JsonResult {
    let mut data = Vec::new();
    for collection in Collection::find_by_organization(&token.0, &conn).await {
        data.push(collection_json(&collection, &conn).await);
    }
    Ok(Json(list_json(&data)))
}

#[get("/public/collections/<collection_id>")]
async fn get_collection(collection_id: CollectionId, token: PublicToken, conn: DbConn) -> JsonResult {
    let Some(collection) = Collection::find_by_uuid_and_org(&collection_id, &token.0, &conn).await else {
        err_code!("Collection not found.", format!("collection {collection_id}"), 404)
    };
    Ok(Json(collection_json(&collection, &conn).await))
}

/// Set the collection's External ID (an omitted or null `externalId` clears it, as in Bitwarden) and, when the
/// request has `groups`, replace the groups that can access it.
#[put("/public/collections/<collection_id>", data = "<body>")]
async fn update_collection(
    collection_id: CollectionId,
    body: Result<Json<CollectionUpdateRequest>, rocket::serde::json::Error<'_>>,
    token: PublicToken,
    ip: ClientIp,
    conn: DbConn,
) -> JsonResult {
    let org_id = token.0;
    let body = parse_body(body)?;
    let Some(mut collection) = Collection::find_by_uuid_and_org(&collection_id, &org_id, &conn).await else {
        err_code!("Collection not found.", format!("collection {collection_id}"), 404)
    };
    if let Some(groups) = &body.groups {
        let group_ids: Vec<_> = groups.iter().map(|g| g.id.clone()).collect();
        check_groups(&org_id, &group_ids, &conn).await?;
    }

    collection.set_external_id(body.external_id);
    collection.save(&conn).await?;
    if let Some(groups) = &body.groups {
        replace_collection_groups(&collection, groups, &conn).await?;
    }

    public_event(EventType::CollectionUpdated, &collection.uuid, &org_id, &ip, &conn).await;
    Ok(Json(collection_json(&collection, &conn).await))
}
