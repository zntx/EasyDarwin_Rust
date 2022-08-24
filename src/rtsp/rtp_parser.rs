


pub struct RTPInfo  {
	Version        : i32,
	Padding        : bool,
	Extension      : bool,
	CSRCCnt        : i32,
	Marker         : bool,
	PayloadType    : i32,
	SequenceNumber : i32,
	Timestamp      : i32,
	SSRC           : i32,
	Payload        : Vec<u8>,
	PayloadOffset  :i32,
}