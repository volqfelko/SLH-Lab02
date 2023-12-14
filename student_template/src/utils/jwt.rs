use anyhow::Result;

pub enum Role {
    Access,
    Refresh,
}
/// Verify the validity of a JWT accordingly to its role (access or refresh)
/// Return the email contained in the JWT if its valid
/// Return an error if the JWT is invalid
pub fn verify<T: Into<String>>(jwt: T, role: Role) -> Result<String> {
    todo!()
}
