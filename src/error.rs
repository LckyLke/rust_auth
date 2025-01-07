use serde::Serialize;
use std::convert::Infallible;
use thiserror::Error;
use warp::{http::StatusCode, Rejection, Reply};

#[derive(Error, Debug)]
pub enum Error{
	#[error("wrong credentials")]
	WrongCredentialsError,
	#[error("jwt token creation error")]
	JWTTokenCreationError,
	#[error("jwt token no valid")]
	JWTTokenError,
	#[error("no auth header")]
	NoAuthHeaderError,
	#[error("invalid auth header")]
	InvalidAuthHeaderError,
	#[error("no permission")]
	NoPermissionError,
	#[error("key not found")]
	KeyNotFoundError,
	#[error("Insertion in DB failed")]
	DatabaseInsertError,
	#[error("User aready exists")]
	UserAlreadyExistsError,
	#[error("Could not hash password")]
	HashingError,
	#[error("Could not find user")]
	UserNotFoundError,

}

#[derive(Serialize,Debug)]
struct ErrorRespone {
	message: String,
	status: String,
}

impl warp::reject::Reject for Error {}

pub async  fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
	let (code, message) = if err.is_not_found() {
		(StatusCode::NOT_FOUND, String::from("Not Found")) 
	} else if let Some(e) = err.find::<Error>() {
		match e {
			Error::WrongCredentialsError => (StatusCode::FORBIDDEN, e.to_string()),
			Error::NoPermissionError => (StatusCode::UNAUTHORIZED, e.to_string()),
			Error::JWTTokenError => (StatusCode::UNAUTHORIZED, e.to_string()),
			Error::JWTTokenCreationError => (
				StatusCode::INTERNAL_SERVER_ERROR, String::from("Internal Server Error!")
			),
			Error::KeyNotFoundError => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
			Error::UserAlreadyExistsError => (StatusCode::BAD_REQUEST, e.to_string()),
			Error::HashingError => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
			Error::DatabaseInsertError => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
			Error::UserNotFoundError => (StatusCode::NOT_FOUND, e.to_string()),
			_ => (StatusCode::BAD_REQUEST, e.to_string()),
		}
	} else if err.find::<warp::reject::MethodNotAllowed>().is_some(){
		(StatusCode::METHOD_NOT_ALLOWED, String::from("Method not allowed"))
	} else {
		eprint!("unhandled error: {:?}", err);
		(StatusCode::INTERNAL_SERVER_ERROR, String::from("Internal Server Error"))
	};

	let json = warp::reply::json(&ErrorRespone{
		status: code.to_string(),
		message
	});
	Ok(warp::reply::with_status(json, code))

}