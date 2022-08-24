


use super::rtsp_client::RTSPClient;

pub struct UDPServer {
	//*Session
	//rtspClient   : RTSPClient,

	APort        :i32,
	//AConn        *net.UDPConn
	AControlPort : i32,
	//AControlConn *net.UDPConn
	VPort        :i32,
	//VConn        *net.UDPConn
	VControlPort :i32,
	//VControlConn *net.UDPConn

	Stoped       :bool,
}