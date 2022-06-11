mod router_manager;

fn main() {
    println!("Hello, Mundo!");
    router_manager::get_lightring_state();
    router_manager::set_lightring_state(10);
}
