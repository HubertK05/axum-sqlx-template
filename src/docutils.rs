use std::{collections::{BTreeMap, HashMap}, marker::PhantomData, sync::Arc};

use axum::{async_trait, extract::{Path, Query}, handler::Handler, response::IntoResponse, routing::MethodRouter, Json, Router};
use regex::Regex;
use utoipa::{openapi::{path::{Operation, Parameter, ParameterIn}, request_body::RequestBody, Components, Content, Info, OpenApi, PathItem, PathItemType, PathsBuilder, Ref, RefOr, Schema}, IntoParams, ToSchema};

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

impl<'a, T> DocExtractor for Path<T>
where T: IntoParams {
    fn to_open_api() -> RequestPart {
        RequestPart::Params(T::into_params(|| { Some(ParameterIn::Path) }))
    }
}

impl<'a, T> DocExtractor for Query<T>
where T: IntoParams {
    fn to_open_api() -> RequestPart {
        RequestPart::Params(T::into_params(|| { Some(ParameterIn::Query) }))
    }
}

impl<'a, T> DocExtractor for Json<T>
where T: ToSchema<'a> {
    fn to_open_api() -> RequestPart {
        let (name, schema) = T::schema();
        RequestPart::Schema(name.to_string(), schema)
    }
}

pub enum RequestPart {
    Params(Vec<Parameter>),
    Schema(String, RefOr<Schema>),
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
        docs.insert(into_document_form(path), method_router.docs);

        Self {
            docs,
            router: self.router.route(path, method_router.method_router),
        }
    }

    pub fn merge<R>(self, other: R) -> Self
    where
        R: Into<DocumentedRouter<S>> {
        let DocumentedRouter { docs: other_docs, router: other_router } = other.into();
        let mut docs = self.docs;
        other_docs.into_iter().for_each(|(uri, path_spec)| {
            docs.insert(uri, path_spec);
        });

        Self {
            docs,
            router: self.router.merge(other_router),
        }
    }

    pub fn nest(self, path: &str, other: DocumentedRouter<S>) -> Self {
        let DocumentedRouter { docs: other_docs, router: other_router } = other.into();
        let mut docs = self.docs;
        
        let doc_path = into_document_form(path);
        other_docs.into_iter().for_each(|(uri, path_spec)| {
            docs.insert(format!("{doc_path}{uri}"), path_spec);
        });

        Self {
            docs,
            router: self.router.nest(path, other_router),
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

            let (operation, schemas) = into_operation(handler_parts);
            res.paths.paths.insert(path.clone(), PathItem::new(method, operation));
            if !schemas.is_empty() {
                if let Some(ref mut components) = res.components {
                    components.schemas.extend(schemas.into_iter());
                } else {
                    let mut components = Components::new();
                    components.schemas.extend(schemas.into_iter());
                    res.components = Some(components);
                }
            }

            for (method, handler_parts) in path_spec {
                let (operation, schemas) = into_operation(handler_parts);
                res.paths.paths.get_mut(&path).unwrap().operations.insert(method, operation);
                
                if !schemas.is_empty() {
                    if let Some(ref mut components) = res.components {
                        components.schemas.extend(schemas.into_iter());
                    } else {
                        let mut components = Components::new();
                        components.schemas.extend(schemas.into_iter());
                        res.components = Some(components);
                    }
                }
            }
        }

        (router, res)
    }
}

pub fn into_operation(handler_parts: Vec<RequestPart>) -> (Operation, Vec<(String, RefOr<Schema>)>) {
    let mut handler = Operation::new();
    let mut schemas = Vec::new();
    for elem in handler_parts {
        match elem {
            RequestPart::Schema(name, schema) => {
                let mut request = RequestBody::new();
                request.content.insert(name.to_string(), Content::new(RefOr::Ref(Ref::from_schema_name(name.clone()))));
                handler.request_body = Some(request);
                schemas.push((name, schema));
            },
            RequestPart::Params(params) => {
                let mut temp_vec = handler.parameters.unwrap_or_default();
                temp_vec.extend(params.into_iter());
                handler.parameters = Some(temp_vec);
            }
        }
    }

    (handler, schemas)
}

pub fn into_document_form(path: &str) -> String {
    let re = Regex::new(r":[0-9A-Za-z-_]*").expect("Failed to build regex");

    let matches = re.find_iter(path);
    let mut path = re.replace_all(path, ":").to_string();

    for elem in matches {
        path = path.replacen(":", &format!("{{{}}}", &elem.as_str()[1..]), 1);
    }

    path
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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("/", "/")]
    #[case("/:user_id", "/{user_id}")]
    #[case("/:transaction_id/books/:book_id/price", "/{transaction_id}/books/{book_id}/price")]
    #[case("/:/foo", "/{}/foo")]
    #[case("/foo/:", "/foo/{}")]
    #[case("/foo/:bar", "/foo/{bar}")]
    #[case("/foo/:Bar-baZ09", "/foo/{Bar-baZ09}")]
    fn path_changes_from_server_to_docs_form(#[case] a: &str, #[case] b: &str) {
        assert_eq!(into_document_form(a), b);
    }
}
