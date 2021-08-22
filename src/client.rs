use hello_world::*;


// A testing gRPC client.

pub mod hello_world {
    tonic::include_proto!("vault");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = hello_world::password_service_client::PasswordServiceClient::connect("http://localhost:50011").await?;

    let request = tonic::Request::new(CreatePolicyRequest {
        policy: None,
        activate: false
    });

    let response = client.create_password_policy(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
