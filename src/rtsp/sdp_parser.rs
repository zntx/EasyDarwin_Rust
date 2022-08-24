


pub struct SDPInfo  {
	AVType             :String,
	Codec              :String,
	TimeScale          :i32,
	Control            :String,
	Rtpmap             :i32,
	Config             : Vec::<u8>,
	SpropParameterSets :Vec::<Vec::<u8>>,
	PayloadType        :i32,
	SizeLength         :i32,
	IndexLength        :i32,
}