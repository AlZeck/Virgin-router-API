mod router_manager;

#[macro_use]
extern crate rocket;
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket_basicauth::BasicAuth;

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct RouterStatus {
    light_ring: i32,
}

#[get("/")]
async fn get_light_ring(auth: BasicAuth) -> Json<RouterStatus> {
    match router_manager::get_lightring_state(&auth.password[..]).await {
        Ok(v) => Json(RouterStatus { light_ring: v }),
        Err(_) => Json(RouterStatus { light_ring: -1 }),
    }
}

#[post("/", data = "<status>")]
async fn set_light_ring(auth: BasicAuth, status: Json<RouterStatus>) -> Json<RouterStatus> {
    match router_manager::set_lightring_state(&auth.password[..], status.light_ring).await {
        Ok(_) => Json(RouterStatus {
            light_ring: status.light_ring,
        }),
        Err(_) => Json(RouterStatus { light_ring: -1 }),
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![get_light_ring, set_light_ring])
}
