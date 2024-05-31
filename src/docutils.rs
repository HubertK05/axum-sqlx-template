use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use axum::{async_trait, handler::Handler, response::IntoResponse, routing::MethodRouter, Router};

pub trait DocumentedHandler<T, S> {
    fn extract_docs(&self) -> Vec<String>;
}

impl<F, S> DocumentedHandler<((), ), S> for F
where
    F: Handler<((), ), S> {
    fn extract_docs(&self) -> Vec<String> {
        vec![]
    } 
}

impl<F, M, T1, S> DocumentedHandler<(M, T1), S> for F
where
    F: Handler<(M, T1), S> {
    fn extract_docs(&self) -> Vec<String> {
        vec![
            T1::to_open_api(),
        ]
    }
}

impl<F, M, T1, T2, S> DocumentedHandler<(M, T1, T2), S> for F
where
    F: Handler<(M, T1, T2), S> {
    fn extract_docs(&self) -> Vec<String> {
        vec![
            T1::to_open_api(),
            T2::to_open_api(),
        ]
    }
}
pub trait ToOpenApi {
    fn to_open_api() -> String;
}

impl<T> ToOpenApi for T {
    fn to_open_api() -> String {
        "example".to_string()
    }
}

pub struct DocumentedRouter<S> {
    pub docs: HashMap<String, HashMap<String, Vec<String>>>,
    pub router: Router<S>,
}

impl<S> DocumentedRouter<S>
where
    S: Clone + Send + Sync + 'static {
    pub fn new() -> Self {
        Self {
            docs: HashMap::new(),
            router: Router::new(),
        }
    }

    pub fn route(self, path: &str, method_router: MyMethodRouter<S>) -> Self {
        let mut docs = self.docs;
        docs.insert(path.to_string(), method_router.docs);

        Self {
            docs,
            router: self.router.route(path, method_router.method_router),
        }
    }

    pub fn finish_doc(self) -> (Router<S>, HashMap<String, HashMap<String, Vec<String>>>) {
        (self.router, self.docs)
    }
}

pub struct MyMethodRouter<S: Clone + Send + Sync + 'static> {
    pub docs: HashMap<String, Vec<String>>,
    pub method_router: MethodRouter<S>,
}

impl<S: Clone + Send + Sync + 'static> MyMethodRouter<S> {
    pub fn new() -> Self {
        Self {
            docs: HashMap::new(),
            method_router: MethodRouter::new(),
        }
    }

    pub fn get<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert("GET".to_string(), handler.extract_docs());
        
        Self {
            docs,
            method_router: self.method_router.get(handler)
        }
    }

    pub fn post<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert("POST".to_string(), handler.extract_docs());
        
        Self {
            docs,
            method_router: self.method_router.post(handler)
        }
    }
    
    pub fn put<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert("PUT".to_string(), handler.extract_docs());
        
        Self {
            docs,
            method_router: self.method_router.put(handler)
        }
    }
    
    pub fn patch<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert("PATCH".to_string(), handler.extract_docs());
        
        Self {
            docs,
            method_router: self.method_router.patch(handler)
        }
    }

    pub fn delete<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert("DELETE".to_string(), handler.extract_docs());
        
        Self {
            docs,
            method_router: self.method_router.delete(handler)
        }
    }
}
