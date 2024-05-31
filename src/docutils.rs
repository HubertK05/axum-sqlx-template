use std::{collections::{BTreeMap, HashMap}, marker::PhantomData, sync::Arc};

use axum::{async_trait, extract::{Path, Query}, handler::Handler, response::IntoResponse, routing::MethodRouter, Json, Router};
use utoipa::{openapi::{path::{Operation, Parameter, ParameterIn}, request_body::RequestBody, Content, Info, OpenApi, PathItem, PathItemType, PathsBuilder}, IntoParams, ToSchema};

const DEFAULT_BODY_CONTENT_NAME: &str = "Request body";

pub trait DocumentedHandler<T, S> {
    fn extract_docs(&self) -> Vec<RequestPart>;
}

impl<F, S> DocumentedHandler<((), ), S> for F
where
    F: Handler<((), ), S> {
    fn extract_docs(&self) -> Vec<RequestPart> {
        vec![]
    } 
}

impl<F, M, T1, S> DocumentedHandler<(M, T1), S> for F
where
    F: Handler<(M, T1), S>,
    T1: DocExtractor {
    fn extract_docs(&self) -> Vec<RequestPart> {
        vec![
            T1::to_open_api(),
        ]
    }
}

impl<F, M, T1, T2, S> DocumentedHandler<(M, T1, T2), S> for F
where
    F: Handler<(M, T1, T2), S>,
    T1: DocExtractor,
    T2: DocExtractor {
    fn extract_docs(&self) -> Vec<RequestPart> {
        vec![
            T1::to_open_api(),
            T2::to_open_api(),
        ]
    }
}

impl<F, M, T1, T2, T3, S> DocumentedHandler<(M, T1, T2, T3), S> for F
where
    F: Handler<(M, T1, T2, T3), S>,
    T1: DocExtractor,
    T2: DocExtractor,
    T3: DocExtractor {
    fn extract_docs(&self) -> Vec<RequestPart> {
        vec![
            T1::to_open_api(),
            T2::to_open_api(),
            T3::to_open_api(),
        ]
    }
}

pub trait DocExtractor {
    fn to_open_api() -> RequestPart;
}

impl<T> DocExtractor for Path<T>
where T: IntoParams {
    fn to_open_api() -> RequestPart {
        RequestPart::Params(T::into_params(|| { Some(ParameterIn::Path) }))
    }
}

impl<T> DocExtractor for Query<T>
where T: IntoParams {
    fn to_open_api() -> RequestPart {
        RequestPart::Params(T::into_params(|| { Some(ParameterIn::Query) }))
    }
}

impl<'a, T> DocExtractor for Json<T>
where T: ToSchema<'a> {
    fn to_open_api() -> RequestPart {
        let mut body = RequestBody::new();
        let (_, schema) = T::schema();
        let content = Content::new(schema);

        body.content.insert(DEFAULT_BODY_CONTENT_NAME.to_string(), content.clone());

        RequestPart::Body(body)
    }
}

pub enum RequestPart {
    Params(Vec<Parameter>),
    Body(RequestBody),
}

pub struct DocumentedRouter<S> {
    pub docs: HashMap<String, HashMap<PathItemType, Vec<RequestPart>>>,
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

    pub fn finish_doc(self, app_name: &str, app_version: &str) -> (Router<S>, OpenApi) {
        let Self { router, docs } = self;

        let mut res = utoipa::openapi::OpenApi::new(Info::new(app_name, app_version), PathsBuilder::new());
        for (path, path_spec) in docs {
            let mut path_spec = path_spec.into_iter();
            let Some((method, handler_parts)) = path_spec.next() else {
                continue;
            };

            res.paths.paths.insert(path.clone(), PathItem::new(method, into_operation(handler_parts)));

            for (method, handler_parts) in path_spec {
                res.paths.paths.get_mut(&path).unwrap().operations.insert(method, into_operation(handler_parts));
            }
        }

        (router, res)
    }
}

pub fn into_operation(handler_parts: Vec<RequestPart>) -> Operation {
    let mut handler = Operation::new();
    for elem in handler_parts {
        match elem {
            RequestPart::Body(body) => handler.request_body = Some(body),
            RequestPart::Params(params) => {
                let mut temp_vec = handler.parameters.unwrap_or_default();
                temp_vec.extend(params.into_iter());
                handler.parameters = Some(temp_vec);
            }
        }
    }

    handler
}

pub struct MyMethodRouter<S: Clone + Send + Sync + 'static> {
    pub docs: HashMap<PathItemType, Vec<RequestPart>>,
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
        docs.insert(PathItemType::Get, handler.extract_docs());
        
        Self {
            docs,
            method_router: self.method_router.get(handler)
        }
    }

    pub fn post<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert(PathItemType::Post, handler.extract_docs());
        
        Self {
            docs,
            method_router: self.method_router.post(handler)
        }
    }
    
    pub fn put<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert(PathItemType::Put, handler.extract_docs());
        
        Self {
            docs,
            method_router: self.method_router.put(handler)
        }
    }
    
    pub fn patch<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert(PathItemType::Patch, handler.extract_docs());
        
        Self {
            docs,
            method_router: self.method_router.patch(handler)
        }
    }

    pub fn delete<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert(PathItemType::Delete, handler.extract_docs());
        
        Self {
            docs,
            method_router: self.method_router.delete(handler)
        }
    }
}
