use std::{collections::{BTreeMap, HashMap}, fmt::Display, future::Future};

use axum::{extract::{Path, Query}, handler::Handler, response::{Html, IntoResponse, IntoResponseParts}, routing::MethodRouter, Json, Router};
use axum_extra::extract::CookieJar;
use regex::Regex;
use utoipa::{openapi::{path::{Operation, Parameter, ParameterIn, PathItemBuilder}, request_body::RequestBody, Components, Content, Info, Object, ObjectBuilder, OneOf, OpenApi, PathItem, PathItemType, Paths, Ref, RefOr, Response, ResponseBuilder, Responses, Schema}, IntoParams, ToSchema};
use axum::http::StatusCode;

pub trait DocHandler<T, S> {
    fn extract_docs(&self) -> Vec<RequestPart>;
    fn response_docs(&self) -> Option<(String, ContentType, RefOr<Schema>)>;
}

impl<F, S, Fut, R> DocHandler<((), ), S> for F
where
    F: Handler<((), ), S> + FnOnce() -> Fut,
    Fut: Future<Output = R>,
    R: IntoResponse + DocResponse {
    fn extract_docs(&self) -> Vec<RequestPart> {
        vec![]
    }

    fn response_docs(&self) -> Option<(String, ContentType, RefOr<Schema>)> {
        R::doc_response()
    }
}

macro_rules! impl_doc_handler {
    (
        $($ty:ident),*
    ) => {
        #[allow(non_snake_case, unused_mut)]
        impl<F, M, $($ty),*, S, Fut, R> DocHandler<(M, $($ty),*), S> for F
        where
            F: Handler<(M, $($ty),*), S> + FnOnce($($ty),*) -> Fut,
            Fut: Future<Output = R>,
            R: IntoResponse + DocResponse,
            $( $ty: DocExtractor, )*
        {
            fn extract_docs(&self) -> Vec<RequestPart> {
                let mut res = Vec::new();
                $(
                    res.extend($ty::doc_extractor());
                )*
                res
            }

            fn response_docs(&self) -> Option<(String, ContentType, RefOr<Schema>)> {
                R::doc_response()
            }
        }
    };
}

macro_rules! impl_method_router {
    ($ty:ident, $en:ident) => {
        pub fn $ty<H: Handler<T, S> + DocHandler<T, S>, T: 'static>(self, handler: H) -> Self {
            let mut docs = self.docs;
            docs.insert(PathItemType::$en, HandlerDocs::from_signature(handler.clone()));
            
            Self {
                docs,
                curr_method: PathItemType::$en,
                method_router: self.method_router.$ty(handler)
            }
        }
    }
}

macro_rules! impl_method_router_start {
    ($ty:ident, $en:ident) => {
        pub fn $ty<H: Handler<T, S> + DocHandler<T, S>, T: 'static, S: Clone + Send + Sync + 'static>(handler: H) -> DocMethodRouter<S> {
            let mut docs = PathDocs::new();
            docs.insert(PathItemType::$en, HandlerDocs::from_signature(handler.clone()));
            
            DocMethodRouter {
                docs,
                curr_method: PathItemType::$en,
                method_router: axum::routing::$ty(handler)
            }
        }
    }
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
    fn doc_extractor() -> Option<RequestPart> {
        None
    }
}

impl<'a, T> DocExtractor for Path<T>
where T: IntoParams {
    fn doc_extractor() -> Option<RequestPart> {
        Some(RequestPart::Params(T::into_params(|| { Some(ParameterIn::Path) })))
    }
}

impl<'a, T> DocExtractor for Query<T>
where T: IntoParams {
    fn doc_extractor() -> Option<RequestPart> {
        Some(RequestPart::Params(T::into_params(|| { Some(ParameterIn::Query) })))
    }
}

impl<'a, T> DocExtractor for Json<T>
where T: ToSchema<'a> {
    fn doc_extractor() -> Option<RequestPart> {
        let (name, schema) = T::schema();
        Some(RequestPart::Schema(name.to_string(), ContentType::Json, schema))
    }
}

impl DocExtractor for axum_extra::extract::cookie::CookieJar {}
impl<T> DocExtractor for axum::extract::State<T> {}

pub trait DocResponse {
    fn doc_response() -> Option<(String, ContentType, RefOr<Schema>)> {
        None
    }
}

impl<'a, T> DocResponse for Json<T>
where T: ToSchema<'a> {
    fn doc_response() -> Option<(String, ContentType, RefOr<Schema>)> {
        let (name, schema) = T::schema();
        Some((name.to_string(), ContentType::Json, schema))
    }
}

impl<T> DocResponse for Html<T> {
    fn doc_response() -> Option<(String, ContentType, RefOr<Schema>)> {
        let schema = Schema::Object(ObjectBuilder::new().schema_type(utoipa::openapi::SchemaType::String).build());

        Some(("Html".to_string(), ContentType::Html, RefOr::T(schema)))
    }
}

impl DocResponse for () {}
impl DocResponse for axum_extra::extract::cookie::CookieJar {}
impl DocResponse for axum::response::Redirect {}

impl<R> DocResponse for (R,)
where
    R: DocResponse {
    fn doc_response() -> Option<(String, ContentType, RefOr<Schema>)> {
        R::doc_response()
    }
}

macro_rules! impl_doc_response {
    ($($ty:ident),*) => {
        impl<$($ty),*, R> DocResponse for ($($ty),*, R)
        where
            $(
                $ty: IntoResponseParts,
            )*
            R: IntoResponse + DocResponse {
            fn doc_response() -> Option<(String, ContentType, RefOr<Schema>)> {
                R::doc_response()
            }
        }
    }
}

impl_doc_response!(T1);
impl_doc_response!(T1, T2);
impl_doc_response!(T1, T2, T3);
impl_doc_response!(T1, T2, T3, T4);
impl_doc_response!(T1, T2, T3, T4, T5);
impl_doc_response!(T1, T2, T3, T4, T5, T6);
impl_doc_response!(T1, T2, T3, T4, T5, T6, T7);
impl_doc_response!(T1, T2, T3, T4, T5, T6, T7, T8);
impl_doc_response!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
impl_doc_response!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
impl_doc_response!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
impl_doc_response!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);
impl_doc_response!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13);
impl_doc_response!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14);
impl_doc_response!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15);
impl_doc_response!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16);

impl<T, E> DocResponse for Result<T, E>
where
    T: DocResponse {
    fn doc_response() -> Option<(String, ContentType, RefOr<Schema>)> {
        T::doc_response()
    }
}

#[derive(Clone, Copy)]
pub enum ContentType {
    Json,
    Html,
}

impl Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ContentType::Json => "application/json",
            ContentType::Html => "text/html",
        };

        write!(f, "{s}")
    }
}

pub enum RequestPart {
    Params(Vec<Parameter>),
    Schema(String, ContentType, RefOr<Schema>),
}

struct AppDocs {
    paths: HashMap<String, PathDocs>,
}

impl AppDocs {
    fn new() -> Self {
        Self {
            paths: HashMap::new(),
        }
    }

    fn insert_path(&mut self, path: impl Into<String>, path_docs: PathDocs) -> Option<PathDocs> {
        self.paths.insert(path.into(), path_docs)
    }

    fn to_openapi(self, app_name: String, version: String) -> OpenApi {
        let mut res = OpenApi::new(Info::new(app_name, version), Paths::new());

        for (uri, path_spec) in self.paths {
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

struct PathDocs(HashMap<PathItemType, HandlerDocs>);

impl PathDocs {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn insert(&mut self, method: PathItemType, handler_data: HandlerDocs) -> Option<HandlerDocs> {
        self.0.insert(method, handler_data)
    }

    /// Tries to add response metadata to a given method handler.
    /// Returns the same metadata as `Some()` variant if it fails to find the given method, `None` otherwise.
    fn try_add_response_metadata(&mut self, method: PathItemType, metadata: ResponseMetadata) -> Option<ResponseMetadata> {
        let Some(handler) = self.0.get_mut(&method) else {
            return Some(metadata)
        };

        handler.response_metadata.push(metadata);
        None
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

struct HandlerDocs {
    params: Vec<Parameter>,
    schema: Option<(String, ContentType, RefOr<Schema>)>,
    response_schema: Option<(String, ContentType, RefOr<Schema>)>,
    response_metadata: Vec<ResponseMetadata>,
}

impl HandlerDocs {
    fn from_signature<T, S>(handler: impl DocHandler<T, S>) -> Self {
        let mut res = Self {
            params: Vec::new(),
            schema: None,
            response_schema: None,
            response_metadata: Vec::new(),
        };
        
        for elem in handler.extract_docs() {
            match elem {
                RequestPart::Params(params) => res.params.extend(params),
                RequestPart::Schema(name, content_type, schema) => {
                    res.schema = Some((name, content_type, schema));
                },
            }
        }

        res.response_schema = handler.response_docs();

        res
    }

    fn collect(mut self) -> (Operation, Vec<(String, RefOr<Schema>)>) {
        let mut res = Operation::new();

        if !self.params.is_empty() {
            res.parameters = Some(self.params);
        }
        
        res.request_body = self
            .schema
            .as_ref()
            .map(|(name, content_type, _)| to_req_body(name, *content_type));
        
        let mut schemas = Vec::new();
        schemas.extend(self.schema.map(|x| (x.0, x.2)));
        
        if self.response_metadata.is_empty() && self.response_schema.is_none() {
            return (res, schemas)
        };
        
        self.response_metadata.reverse();
        
        let first_metadata = self.response_metadata.pop().unwrap_or(ResponseMetadata::default_success());

        let first_response = match self.response_schema.as_ref() {
            Some((schema_name, content_type, _)) => to_response(schema_name, *content_type, first_metadata.description),
            None => Response::new(first_metadata.description),
        };
        
        res.responses.responses.insert(first_metadata.status.as_u16().to_string(), RefOr::T(first_response));
        while let Some(meta) = self.response_metadata.pop() {
            res.responses.responses.insert(meta.status.as_u16().to_string(), RefOr::T(Response::new(meta.description)));
        }
        
        schemas.extend(self.response_schema.map(|x| (x.0, x.2)));
        
        (res, schemas)
    }
}

fn to_req_body(schema_name: impl Into<String>, content_type: ContentType) -> RequestBody {
    let mut body = RequestBody::new();
    let content = Content::new(RefOr::Ref(Ref::from_schema_name(schema_name.into())));
    body.content = BTreeMap::from([(content_type.to_string(), content)]);
    body
}

fn to_response(schema_name: impl Into<String>, content_type: ContentType, description: String) -> Response {
    let content = Content::new(RefOr::Ref(Ref::from_schema_name(schema_name.into())));
    ResponseBuilder::new().description(description).content(content_type.to_string(), content).build()
}

pub struct DocRouter<S> {
    docs: AppDocs,
    router: Router<S>,
}

impl<S> DocRouter<S>
where
    S: Clone + Send + Sync + 'static {
    pub fn new() -> Self {
        Self {
            docs: AppDocs::new(),
            router: Router::new(),
        }
    }

    pub fn route(self, path: &str, method_router: DocMethodRouter<S>) -> Self {
        let mut docs = self.docs;
        docs.insert_path(into_document_form(path), method_router.docs);

        Self {
            docs,
            router: self.router.route(path, method_router.method_router),
        }
    }

    pub fn merge<R>(self, other: R) -> Self
    where
        R: Into<DocRouter<S>> {
        let DocRouter { docs: other_docs, router: other_router } = other.into();
        let mut docs = self.docs;
        other_docs.paths.into_iter().for_each(|(uri, path_spec)| {
            docs.insert_path(uri, path_spec);
        });

        Self {
            docs,
            router: self.router.merge(other_router),
        }
    }

    pub fn nest(self, path: &str, other: DocRouter<S>) -> Self {
        let DocRouter { docs: other_docs, router: other_router } = other.into();
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

    pub fn finish_doc(self, app_name: impl Into<String>, version: impl Into<String>) -> (Router<S>, OpenApi) {
        let Self { router, docs } = self;

        (router, docs.to_openapi(app_name.into(), version.into()))
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

pub struct ResponseMetadata {
    status: StatusCode,
    description: String,
}

impl ResponseMetadata {
    pub fn default_success() -> Self {
        ResponseMetadata {
            status: StatusCode::OK,
            description: "Successful response".to_string(),
        }
    }

    pub fn new(status: StatusCode, description: String) -> Self {
        Self {
            status,
            description,
        }
    }
}

pub struct DocMethodRouter<S: Clone + Send + Sync + 'static> {
    docs: PathDocs,
    curr_method: PathItemType,
    method_router: MethodRouter<S>,
}

impl<S: Clone + Send + Sync + 'static> DocMethodRouter<S> {
    pub fn response(mut self, status: StatusCode, description: impl Into<String>) -> Self {
        let metadata = ResponseMetadata::new(status, description.into());

        let res = self.docs.try_add_response_metadata(self.curr_method.clone(), metadata);
        debug_assert!(res.is_none());
        
        self
    }

    impl_method_router!(get, Get);
    impl_method_router!(post, Post);
    impl_method_router!(put, Put);
    impl_method_router!(patch, Patch);
    impl_method_router!(delete, Delete);
}

impl_method_router_start!(get, Get);
impl_method_router_start!(post, Post);
impl_method_router_start!(put, Put);
impl_method_router_start!(patch, Patch);
impl_method_router_start!(delete, Delete);

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
