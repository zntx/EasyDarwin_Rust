

use std::time;
use super::pack::*;
use super::udp_server::UDPServer;

pub struct RTSPClient {
	//Server *Server
	//SessionLogger
	Stoped               : bool,
	Status               : String,
	URL                  : String,
	Path                 : String,
	CustomPath           : String, //custom path for pusher
	ID                   : String,
	//Conn                 *RichConn
	Session              : String,
	Seq                  : i32,
	//connRW               *bufio.ReadWriter
	InBytes              : i32,
	OutBytes             : i32,
	TransType            : TransType,
	StartAt              : time::Duration,
	//Sdp                  : &sdp.Session,
	AControl             : String,
	VControl             : String,
	ACodec               : String,
	VCodec               : String,
	OptionIntervalMillis : i64,
	SDPRaw               : String,

	debugLogEnable :bool,
	lastRtpSN      :u16,

	Agent    : String,
	authLine : String,

	//tcp channels
	aRTPChannel        : i32,
	aRTPControlChannel : i32,
	vRTPChannel        : i32,
	vRTPControlChannel : i32,

	UDPServer   : UDPServer,
	RTPHandles  : Vec<fn (&RTPPack)-> bool>,
	StopHandles : Vec<fn ()>,
}