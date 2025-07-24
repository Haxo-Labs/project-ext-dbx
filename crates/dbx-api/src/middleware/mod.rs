pub mod auth;
pub mod rate_limit;

pub use auth::{
    api_key_auth_middleware, flexible_auth_middleware, handle_json_rejection, handle_redis_error,
    jwt_auth_middleware, pagination_middleware, permission_check_middleware, rbac_auth_middleware,
    rbac_permission_check_middleware, require_admin_role, require_readonly_role, require_user_role,
    AuthError, JwtService, PaginationQuery, UserStore, UserStoreOperations,
};

pub use rate_limit::{
    add_rate_limit_headers, extract_identifier_from_request, rate_limit_middleware,
    RateLimitPolicy, RateLimitResult, RateLimitService, SlidingWindowRateLimiter,
};
