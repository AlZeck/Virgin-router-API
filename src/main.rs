mod router_manager;

#[tokio::main]
async fn main() {
    let password = "";
    match router_manager::get_lightring_state(password).await {
        Ok(v) => println!("{}", v),
        Err(e) => println!("{:?}", e),
    };
    match router_manager::set_lightring_state(password, 0).await {
        Ok(_) => println!("Success"),
        Err(e) => println!("{:?}", e),
    };
}
