use actix_web::{get, App, HttpServer, Responder, HttpResponse};
use serde::Serialize;

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    service: String,
    message: String,
}

#[get("/api/status")]
async fn get_status() -> impl Responder {
    let response = StatusResponse {
        status: "ok".to_string(),
        service: "rust".to_string(),
        message: "Hello from Rust Backend!".to_string(),
    };
    HttpResponse::Ok().json(response)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(get_status)
    })
    .bind(("0.0.0.0", 8001))?
    .run()
    .await
}
