use axum::Router;
use axum::extract::State;
use axum::http::Request;
use axum::routing::any;

use crate::models::SharedAppState;
use crate::services;

pub fn router(state: SharedAppState) -> Router {
    Router::new().fallback(any(proxy_request)).with_state(state)
}

async fn proxy_request(
    State(state): State<SharedAppState>,
    request: Request<axum::body::Body>,
) -> axum::response::Response {
    services::handle_proxy_request(state, request).await
}
