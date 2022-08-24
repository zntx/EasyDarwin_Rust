

use super::pack::*;
use super::player::Player;
use super::rtsp_client::RTSPClient;
use super::udp_server::UDPServer;
pub struct Pusher  {
	//Session		      : &Session,
	RTSPClient        : RTSPClient,
	players           :Vec::<(String, Player)>, //SessionID <-> Player
	//playersLock       sync.RWMutex
	gopCacheEnable    : bool,
	gopCache          : Vec::<RTPPack>,
	//gopCacheLock      sync.RWMutex
	UDPServer         : UDPServer,
	spsppsInSTAPaPack : bool,
	//cond              : sync.Cond,
	queue             : Vec::<RTPPack>,
}