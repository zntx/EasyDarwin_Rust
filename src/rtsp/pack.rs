



pub enum RTPType{
	RTP_TYPE_AUDIO ,
	RTP_TYPE_VIDEO ,
	RTP_TYPE_AUDIOCONTROL ,
	RTP_TYPE_VIDEOCONTROL ,
    UNKOWN,
}
impl RTPType {
    fn String(&self) -> String {
        match self {
            RTP_TYPE_AUDIO   => String::from("audio"),
            RTP_TYPE_VIDEO => String::from("video"),
            RTP_TYPE_AUDIOCONTROL => String::from("audio control"),
            RTP_TYPE_VIDEOCONTROL => String::from("video control"),
            UNKOWN => String::from("UNKOWN"),
        }
    }
}

pub enum TransType{
	TRANS_TYPE_TCP,
	TRANS_TYPE_UDP,
    UNKOWN,
}
impl TransType {
    fn String(&self) -> String{
        match self {
            TRANS_TYPE_TCP  => String::from("TCP"),
            TRANS_TYPE_UDP => String::from("UDP"),
            UNKOWN => String::from("unknow"),
        }
    }
}

const UDP_BUF_SIZE: u32 = 1048576;

pub struct RTPPack {
	pub Type   :RTPType,
	pub Buffer : Vec<u8>,//*bytes.Buffer
}