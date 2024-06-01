use std::{collections::{BTreeMap, HashMap}, marker::PhantomData, sync::Arc};

use axum::{async_trait, extract::{Path, Query}, handler::Handler, response::IntoResponse, routing::MethodRouter, Json, Router};
use regex::Regex;
use utoipa::{openapi::{path::{Operation, Parameter, ParameterIn, PathItemBuilder}, request_body::RequestBody, Components, Content, Info, OpenApi, PathItem, PathItemType, Paths, PathsBuilder, Ref, RefOr, Schema}, IntoParams, ToSchema};

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

macro_rules! impl_doc_handler {
    (
        $($ty:ident),*
    ) => {
        #[allow(non_snake_case, unused_mut)]
        impl<F, M, $($ty,)* S> DocumentedHandler<(M, $($ty,)*), S> for F
        where
            F: Handler<(M, $($ty,)*), S>,
            $( $ty: DocExtractor, )*
        {
            fn extract_docs(&self) -> Vec<RequestPart> {
                vec![
                    $(
                        $ty::to_open_api(),
                    )*
                ]
            }
        }
    };
}

impl_doc_handler!(T1);
impl_doc_handler!(T1, T2);
impl_doc_handler!(T1, T2, T3);
impl_doc_handler!(T1, T2, T3, T4);
impl_doc_handler!(T1, T2, T3, T4, T5);
impl_doc_handler!(T1, T2, T3, T4, T5, T6);
impl_doc_handler!(T1, T2, T3, T4, T5, T6, T7);
impl_doc_handler!(T1, T2, T3, T4, T5, T6, T7, T8);
impl_doc_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
impl_doc_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
impl_doc_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
impl_doc_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);
impl_doc_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13);
impl_doc_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14);
impl_doc_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15);
impl_doc_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16);

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

struct AppDocs<'a> {
    app_name: &'a str,
    version: &'a str,
    paths: HashMap<String, PathDocs>,
}

impl<'a> AppDocs<'a> {
    fn new(app_name: &'a str, version: &'a str) -> Self {
        Self {
            app_name,
            version,
            paths: HashMap::new(),
        }
    }

    fn insert_path(&mut self, path: String, path_docs: PathDocs) -> Option<PathDocs> {
        self.paths.insert(path, path_docs)
    }
}

impl<'a> From<AppDocs<'a>> for OpenApi {
    fn from(val: AppDocs) -> Self {
        let mut res = OpenApi::new(Info::new(val.app_name, val.version), Paths::new());

        for (uri, path_spec) in val.paths {
            let Some((path_openapi, collected_schemas)) = path_spec.collect() else {
                continue;
            };

            res.paths.paths.insert(uri, path_openapi);

            if !collected_schemas.is_empty() {
                let components = res.components.get_or_insert(Components::new());
                components.schemas.extend(collected_schemas);
            }
        };

        res
    }
}

struct PathDocs(HashMap<PathItemType, HandlerData>);

impl PathDocs {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn insert(&mut self, method: PathItemType, handler_data: HandlerData) -> Option<HandlerData> {
        self.0.insert(method, handler_data)
    }

    fn collect(self) -> Option<(PathItem, BTreeMap<String, RefOr<Schema>>)> {
        if self.0.is_empty() {
            return None
        }

        let mut res = PathItemBuilder::new();
        let mut schema_map = BTreeMap::new();

        for (method, handler) in self.0 {
            let (operation, schema) = handler.collect();
            res = res.operation(method, operation);
            schema_map.extend(schema.into_iter());
        }

        Some((res.build(), schema_map))
    }
}

struct HandlerData {
    params: Vec<Parameter>,
    schema: Option<(String, RefOr<Schema>)>,
}

impl HandlerData {
    fn new() -> Self {
        Self {
            params: Vec::new(),
            schema: None,
        }
    }

    fn collect(self) -> (Operation, Option<(String, RefOr<Schema>)>) {
        let mut res = Operation::new();
        res.parameters = Some(self.params);
        if let Some((ref schema_name, _)) = self.schema {
            let mut body = RequestBody::new();
            let content = Content::new(RefOr::Ref(Ref::from_schema_name(schema_name.clone())));
            body.content = BTreeMap::from([(schema_name.clone(), content)]);
            res.request_body = Some(body);
        }
        
        (res, self.schema)
    }
}

impl From<Vec<RequestPart>> for HandlerData {
    fn from(val: Vec<RequestPart>) -> Self {
        let mut res = HandlerData::new();

        for elem in val {
            match elem {
                RequestPart::Params(params) => res.params.extend(params),
                RequestPart::Schema(name, schema) => {
                    res.schema = Some((name, schema));
                },
            }
        }
        
        res
    }
}

pub struct DocumentedRouter<'a, S> {
    docs: AppDocs<'a>,
    router: Router<S>,
}

impl<'a, S> DocumentedRouter<'a, S>
where
    S: Clone + Send + Sync + 'static {
    pub fn new(app_name: &'a str, version: &'a str) -> Self {
        Self {
            docs: AppDocs::new(app_name, version),
            router: Router::new(),
        }
    }

    pub fn route(self, path: &str, method_router: MyMethodRouter<S>) -> Self {
        let mut docs = self.docs;
        docs.insert_path(into_document_form(path), method_router.docs);

        Self {
            docs,
            router: self.router.route(path, method_router.method_router),
        }
    }

    pub fn merge<R>(self, other: R) -> Self
    where
        R: Into<DocumentedRouter<'a, S>> {
        let DocumentedRouter { docs: other_docs, router: other_router } = other.into();
        let mut docs = self.docs;
        other_docs.paths.into_iter().for_each(|(uri, path_spec)| {
            docs.insert_path(uri, path_spec);
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
        other_docs.paths.into_iter().for_each(|(uri, path_spec)| {
            docs.insert_path(format!("{doc_path}{uri}"), path_spec);
        });

        Self {
            docs,
            router: self.router.nest(path, other_router),
        }
    }

    pub fn finish_doc(self) -> (Router<S>, OpenApi) {
        let Self { router, docs } = self;

        (router, OpenApi::from(docs))
    }
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
    docs: PathDocs,
    method_router: MethodRouter<S>,
}

impl<S: Clone + Send + Sync + 'static> MyMethodRouter<S> {
    pub fn new() -> Self {
        Self {
            docs: PathDocs::new(),
            method_router: MethodRouter::new(),
        }
    }

    pub fn get<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert(PathItemType::Get, handler.extract_docs().into());
        
        Self {
            docs,
            method_router: self.method_router.get(handler)
        }
    }

    pub fn post<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert(PathItemType::Post, handler.extract_docs().into());
        
        Self {
            docs,
            method_router: self.method_router.post(handler)
        }
    }
    
    pub fn put<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert(PathItemType::Put, handler.extract_docs().into());
        
        Self {
            docs,
            method_router: self.method_router.put(handler)
        }
    }
    
    pub fn patch<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert(PathItemType::Patch, handler.extract_docs().into());
        
        Self {
            docs,
            method_router: self.method_router.patch(handler)
        }
    }

    pub fn delete<H: Handler<T, S> + DocumentedHandler<T, S>, T: 'static>(self, handler: H) -> Self {
        let mut docs = self.docs;
        docs.insert(PathItemType::Delete, handler.extract_docs().into());
        
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
