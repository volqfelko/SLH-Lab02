pub const HTTP_PORT: u16 = 8080;
pub const ACCESS_TOKEN_EXPIRATION_HOURS: i64 = 1;
pub const REFRESH_TOKEN_EXPIRATION_DAYS: i64 = 7;
pub const VALID_EMAIL: &str = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$";
pub const MIN_STRENGTH_PASSWORD: u8 = 3;
pub const MAX_PASSWORD_LENGTH: usize = 64;
pub const MIN_PASSWORD_LENGTH: usize = 8;