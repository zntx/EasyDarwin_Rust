


use super::pack::*;
pub struct Player  {
	//*Session
	//Pusher *Pusher
	//cond   *sync.Cond
	queue  : Vec<RTPPack>,
	queueLimit : i32,
	dropPacketWhenPaused :bool,
	paused : bool,
}