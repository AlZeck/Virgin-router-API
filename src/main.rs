mod router_manager;

#[macro_use]
extern crate rocket;
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket_basicauth::BasicAuth;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct RouterStatus {
    light_ring: u64,
    timestamp: Option<u64>,
}

static LIGHT_RING_STATUS: AtomicU64 = AtomicU64::new(0);
static STATUS_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

#[get("/")]
async fn get_light_ring(auth: BasicAuth) -> Json<RouterStatus> {
    let lrs = LIGHT_RING_STATUS.load(Ordering::SeqCst);
    let tmp = STATUS_TIMESTAMP.load(Ordering::SeqCst);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Clock may have gone backwards")
        .as_secs();

    if tmp + 3600 < now {
        match router_manager::get_lightring_state(&auth.password[..]).await {
            Ok(v) => {
                STATUS_TIMESTAMP.store(now, Ordering::SeqCst);
                LIGHT_RING_STATUS.store(v, Ordering::SeqCst);
                Json(RouterStatus {
                    light_ring: v,
                    timestamp: Some(now),
                })
            }
            Err(_) => Json(RouterStatus {
                light_ring: 1000,
                timestamp: Some(0),
            }),
        }
    } else {
        Json(RouterStatus {
            light_ring: lrs,
            timestamp: Some(tmp),
        })
    }
}

#[post("/", data = "<status>")]
async fn set_light_ring(auth: BasicAuth, status: Json<RouterStatus>) -> Json<RouterStatus> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Clock may have gone backwards")
        .as_secs();
    match router_manager::set_lightring_state(&auth.password[..], status.light_ring).await {
        Ok(_) => {
            STATUS_TIMESTAMP.store(now, Ordering::SeqCst);
            LIGHT_RING_STATUS.store(status.light_ring, Ordering::SeqCst);
            Json(RouterStatus {
                light_ring: status.light_ring,
                timestamp: Some(now),
            })
        }
        Err(_) => Json(RouterStatus {
            light_ring: 1000,
            timestamp: Some(0),
        }),
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![get_light_ring, set_light_ring])
}
