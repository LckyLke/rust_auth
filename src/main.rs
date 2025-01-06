use serde::{Deserialize, Serialize};
use::std::sync::Arc;
use::warp::{Filter, Rejection, Reply};

#[derive(Clone)] 
pub struct User{
    pub uid: String,
    pub email: String,
    pub password: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[tokio::main]
async fn main() {
    let users = Arc::new(init_users());


    let login_route = warp::path!("login")
        .and(warp::post())
        .and(with_users(users.clone()))
        .and(warp::body::json())
        .and_then(login_handler);
    
    let user_route = warp::path!("user")
        .and(warp::get())
        .and(with_auth(Role::User))
        .and(with_users(users.clone()))
        .and_then(user_handler);

}
    