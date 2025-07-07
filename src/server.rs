use axum::{extract::State, middleware::from_fn_with_state, response::Json, routing::get, Router};
use futures::TryFutureExt;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

use crate::{
    config::{AppConfig, ConfigError},
    middleware::{
        jwt_auth_middleware, require_admin_role, require_user_role, JwtService, UserStore,
    },
    models::ApiResponse,
    routes::auth::create_auth_routes,
};
use dbx_adapter::redis::{client::RedisPool, factory::RedisBackendFactory};
use dbx_config::{BackendConfig, DbxConfig, LoadBalancingConfig, RoutingConfig};
use dbx_core::LoadBalancingStrategy;
use dbx_router::{BackendRegistryBuilder, BackendRouter};
use std::collections::HashMap;
