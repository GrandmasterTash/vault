use rand::Rng;
use tonic::{Request, Response, Status};
use crate::{db, grpc::api, utils::context::ServiceContext};

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const RESET_CODE_LEN: usize = 8;

pub async fn start_reset_password(ctx: &ServiceContext, request: Request<api::StartResetRequest>)
    -> Result<Response<api::StartResetResponse>, Status> {

    // Get the domain-level gRPC request struct.
    let request = request.into_inner();

    // Load the password (hash) from MongoDB - this ensures it exists.
    let password = db::password::load(&request.password_id, ctx.db()).await?;

    // Generate a random reset code, store it on the password with a datetime.
    let reset_code = generate_reset_code();
    db::password::store_reset_code(&password.password_id, &reset_code, ctx).await?;

    // Return the reset code to the caller.
    Ok(Response::new(api::StartResetResponse{ reset_code }))
}

fn generate_reset_code() -> String {
    let mut rng = rand::thread_rng();
    (0..RESET_CODE_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}