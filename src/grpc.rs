use tonic::{Request, Response, Status};
use crate::grpc::hello_world::greeter_server::Greeter;
use crate::grpc::hello_world::{HelloReply, HelloRequest};

pub mod hello_world {
    tonic::include_proto!("helloworld"); // The string specified here must match the proto package name
}
#[derive(Debug, Default)]
pub struct MyGreeter;

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(&self, request: Request<HelloRequest>) -> Result<Response<HelloReply>, Status> {
        trace!("Got a request: {:?}", request);

        let reply = HelloReply { message: format!("Hello {}!", request.into_inner().name) };

        Ok(Response::new(reply))
    }
}