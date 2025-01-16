use crate::{error::Error, Result, WebResult};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::fs;

use std::fmt;
use warp::{
	filters::header::headers_cloned,
	http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
	reject, Filter, Rejection,
};

const BEARER: &str = "Bearer ";
const PRIVATE_SECRET_PATH: &str = "secret.txt";

fn read_secret() -> Result<String> {
	fs::read_to_string(PRIVATE_SECRET_PATH).map_err(|_| Error::KeyNotFoundError)
}

#[derive(Clone, PartialEq)]
pub enum Role{
	User,
	Admin,
}

impl Role{
pub fn from_str(role: &str) -> Role{
	match role{
		"Admin" => Role::Admin,
		_ => Role::User,
	}

}
}

impl fmt::Display for Role{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
		match self{
			Role::User => write!(f, "User"),
			Role::Admin => write!(f, "Admin"),
		}
	}
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims{
	sub: String,
	role: String,
	exp: usize,
}

pub fn with_auth(role: Role) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
	headers_cloned()
	.map(move | headers: HeaderMap<HeaderValue> | (role.clone(), headers))
	.and_then(authorize)
}

pub fn create_jwt(uid: &str, role: &Role) -> Result<String>{
	let private_key = EncodingKey::from_secret(&read_secret()?.as_ref());
	let expiration = Utc::now().checked_add_signed(chrono::Duration::seconds(60*60)).expect("valid timestamp").timestamp();
	let claims = Claims{
		sub: uid.to_owned(),
		role: role.to_string(),
		exp: expiration as usize,
	};

	
	let header: Header = Header::new(Algorithm::HS512);
	encode(&header, &claims, &private_key)
	.map_err(|_| Error::JWTTokenCreationError)
}

pub fn create_refresh_jwt(uid: &str) -> Result<String> {
	let private_key = EncodingKey::from_secret(&read_secret()?.as_ref());

	let expiration = Utc::now()
		.checked_add_signed(chrono::Duration::days(14))
		.expect("valid timestamp required")
		.timestamp();

	let claims = Claims {
		sub: uid.to_owned(),
		role: "Refresh".to_owned(),
		exp: expiration as usize,
	};

	let header = Header::new(Algorithm::HS512);
	
	encode(&header, &claims, &private_key)
		.map_err(|_| Error::JWTTokenCreationError)
}

async fn authorize((role, headers): (Role, HeaderMap<HeaderValue>)) -> WebResult<String> {
	match jwt_from_header(&headers) {
		Ok(jwt) => {
			let decoded = decode::<Claims>(
				&jwt,
				&DecodingKey::from_base64_secret(&read_secret()?).unwrap(),
				&Validation::new(Algorithm::HS512),
			)
			.map_err(|_| reject::custom(Error::JWTTokenError))?;
		
		if role == Role::Admin && Role::from_str(&decoded.claims.role) != Role::Admin {
			return Err(reject::custom(Error::NoPermissionError));
		}
		Ok(decoded.claims.sub)
		}
		Err(e) => return Err(reject::custom(e))
	}
}
 
fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Result<String>{
	let header = match headers.get(AUTHORIZATION) {
		Some(v) => v, 
		None => return Err(Error::NoAuthHeaderError),
	};

	let auth_header = match std::str::from_utf8(header.as_bytes()) {
		Ok(v) => v,
		Err(_) => return Err(Error::NoAuthHeaderError),
	};
	if !auth_header.starts_with(BEARER) {
		return Err(Error::InvalidAuthHeaderError);
	}
	Ok(auth_header.trim_start_matches(BEARER).to_owned())
}
