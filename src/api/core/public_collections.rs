//! Kount: Bitwarden's public collections API (apps/vaultwarden-kount/README.md § The routes).
//!
//! `GET /public/collections`, `GET /public/collections/<id>`, `PUT /public/collections/<id>`, under
//! the organisation API key's token. There is no create (a collection's name is encrypted by the
//! client) and no delete here. A collection is found by its plaintext External ID.

use rocket::{Route, serde::json::Json};

use super::{
    PublicToken,
    public_models::{PublicCollectionUpdate, bad_body, collection_json, list_json},
};
use crate::{
    CONFIG,
    api::JsonResult,
    db::{
        DbConn,
        models::{Collection, CollectionId},
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
    Ok(Json(list_json(data)))
}

#[get("/public/collections/<collection_id>")]
async fn get_collection(collection_id: CollectionId, token: PublicToken, conn: DbConn) -> JsonResult {
    let Some(collection) = Collection::find_by_uuid_and_org(&collection_id, &token.0, &conn).await else {
        err_code!("Collection not found.", format!("collection {collection_id}"), 404)
    };
    Ok(Json(collection_json(&collection, &conn).await))
}

/// Set the collection's External ID. `groups` is accepted and ignored while groups are disabled
/// (the response then lists none); with groups enabled, group access is not written through this
/// build and a non-empty `groups` is refused.
#[put("/public/collections/<collection_id>", data = "<body>")]
async fn update_collection(
    collection_id: CollectionId,
    body: Result<Json<PublicCollectionUpdate>, rocket::serde::json::Error<'_>>,
    token: PublicToken,
    conn: DbConn,
) -> JsonResult {
    let body = bad_body(body)?;
    if CONFIG.org_groups_enabled() && !body.groups.is_empty() {
        err_code!("Group access cannot be changed through this API.", 400)
    }
    let Some(mut collection) = Collection::find_by_uuid_and_org(&collection_id, &token.0, &conn).await else {
        err_code!("Collection not found.", format!("collection {collection_id}"), 404)
    };
    collection.set_external_id(body.external_id);
    collection.save(&conn).await?;
    Ok(Json(collection_json(&collection, &conn).await))
}
