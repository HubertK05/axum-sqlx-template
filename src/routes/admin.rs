use std::cmp::Ordering;
use crate::routes::EndpointVisits;
use crate::state::RdPool;
use crate::AppRouter;
use axum::extract::State;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use maud::html;

pub fn router() -> AppRouter {
    Router::new().route("/stats/visitors", get(visitors))
}

async fn visitors(State(mut rds): State<RdPool>) -> crate::Result<impl IntoResponse> {
    let mut map: Vec<(String, i32)> = EndpointVisits::get_all(&mut rds).await.unwrap();
    map.sort_unstable_by(|(c, a), (d, b)| {
        let ord = b.partial_cmp(a).unwrap();
        if matches!(ord, Ordering::Equal) {
           d.partial_cmp(c).unwrap() 
        } else {
            ord
        }
    });
    
    Ok(Html(
        html! {
            ul {
                @for (k, v) in map
                {
                    li {(k)" "(v)}
                }
            }
        }
        .into_string(),
    ))
}
