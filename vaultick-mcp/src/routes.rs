use axum::Router;
use axum::extract::{Request, State};
use axum::routing::get;

use crate::models::SharedAppState;
use crate::services;

pub fn router(state: SharedAppState) -> Router {
    Router::new()
        .route("/mcp", get(get_sse).post(post_message).delete(delete_session))
        .with_state(state)
}

async fn get_sse(
    State(state): State<SharedAppState>,
    request: Request<axum::body::Body>,
) -> axum::response::Response {
    services::handle_sse(state, request).await
}

async fn post_message(
    State(state): State<SharedAppState>,
    request: Request<axum::body::Body>,
) -> axum::response::Response {
    services::handle_message(state, request).await
}

async fn delete_session(
    State(state): State<SharedAppState>,
    request: Request<axum::body::Body>,
) -> axum::response::Response {
    services::handle_delete_session(state, request).await
}
