
mod rtsp;
use crate::rtsp::*;

struct Program  {
	//httpPort   int          //web 服务端口
	//httpServer *http.Server //web 服务句柄
	rtspPort   : i32,          //rtsp 服务端口
	rtspServer : rtsp::rtsp_server::Server //web 服务句柄
}


fn main() {
    println!("Hello, world!");
}
