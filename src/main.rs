use auth::{with_auth, Role};
use error::Error::*;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use warp::{Filter, Rejection, Reply, reject, reply};
use dotenv::dotenv;
use std::env;
// MongoDB imports
use mongodb::{
    bson::{doc, oid::ObjectId},
    options::ClientOptions,
    Client, Collection,
};

// For generating UUIDs for new user IDs
use uuid::Uuid;

// Bcrypt for password hashing
use bcrypt::{hash, verify, DEFAULT_COST};

mod auth;
mod error;

type Result<T> = std::result::Result<T, error::Error>;
type WebResult<T> = std::result::Result<T, Rejection>;

/// User struct stored in MongoDB.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub uid: String,
    pub email: String,

    /// This is a *hashed* password, not plain text
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

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,

    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "User".to_string()
}

#[tokio::main]
async fn main() {
    // 1) Initialize MongoDB client/collections
    let db = init_db().await.expect("Failed to initialize MongoDB");
    let user_collection = db.collection::<User>("users");

    // 2) Build routes

    // a) Signup route
    let signup_route = warp::path!("signup")
        .and(warp::post())
        .and(with_db(user_collection.clone()))
        .and(warp::body::json())
        .and_then(signup_handler);

    // b) Login route
    let login_route = warp::path!("login")
        .and(warp::post())
        .and(with_db(user_collection.clone()))
        .and(warp::body::json())
        .and_then(login_handler);

    // c) Protected routes
    let user_route = warp::path!("user")
        .and(with_auth(Role::User))
        .and_then(user_handler);

    let admin_route = warp::path!("admin")
        .and(with_auth(Role::Admin))
        .and_then(admin_handler);

    // Combine all routes
    let routes = signup_route
        .or(login_route)
        .or(user_route)
        .or(admin_route)
        .recover(error::handle_rejection);

    // Run server
    warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;
}

/// Initialize the MongoDB client.
async fn init_db() -> mongodb::error::Result<mongodb::Database> {
    dotenv().ok();
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let mut client_options = ClientOptions::parse(db_url).await?;
    client_options.app_name = Some("warp-example".to_string());
    let client = Client::with_options(client_options)?;
    Ok(client.database("warp_example_db"))
}

/// Provide the Mongo collection as a Filter.
fn with_db(
    collection: Collection<User>,
) -> impl Filter<Extract = (Collection<User>,), Error = Infallible> + Clone {
    warp::any().map(move || collection.clone())
}

/// Handler for user signups.
pub async fn signup_handler(
    collection: Collection<User>,
    body: SignupRequest,
) -> WebResult<impl Reply> {
    //Check if user (by email) already exists
    if let Ok(Some(_)) = collection
        .find_one(doc! {"email": &body.email})
        .await
    {
        return Err(reject::custom(UserAlreadyExistsError));
    }

    // 2) Hash the password before storing
    let hashed_password = hash(&body.password, DEFAULT_COST)
        .map_err(|_| reject::custom(HashingError))?;

    // 3) Create new user with hashed password
    let new_user = User {
        id: None,
        uid: Uuid::new_v4().to_string(),
        email: body.email,
        password: hashed_password,
        role: body.role,
    };

    // 4) Insert into the collection
    collection
        .insert_one(&new_user)
        .await
        .map_err(|_| reject::custom(DatabaseInsertError))?;

    Ok(reply::json(&format!(
        "User '{}' created successfully!",
        new_user.uid
    )))
}

/// Handle user login (check email, then verify the password hash).
pub async fn login_handler(
    collection: Collection<User>,
    body: LoginRequest,
) -> WebResult<impl Reply> {
    // 1) Find user by email
    let filter = doc! {"email": &body.email};
    let user = match collection.find_one(filter).await {
        Ok(Some(user)) => user,
        _ => {
            return Err(reject::custom(UserNotFoundError));
        }
    };

    // 2) Verify the hashed password
    //    bcrypt::verify returns true if the hash matches the plain text
    let password_matches = verify(&body.password, &user.password)
        .map_err(|_| reject::custom(HashingError))?;

    if !password_matches {
        return Err(reject::custom(WrongCredentialsError));
    }

    // 3) If password is valid, create a JWT
    let token = auth::create_jwt(&user.uid, &Role::from_str(&user.role))
        .map_err(|e| reject::custom(e))?;

    Ok(reply::json(&LoginResponse { token }))
}

/// Handler for normal "User" role.
pub async fn user_handler(uid: String) -> WebResult<impl Reply> {
    Ok(format!("Hello User {}", uid))
}

/// Handler for "Admin" role.
pub async fn admin_handler(uid: String) -> WebResult<impl Reply> {
    Ok(format!("Hello Admin {}", uid))
}
