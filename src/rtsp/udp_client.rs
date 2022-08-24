

pub struct UDPClient  {
	//Session  : Session,

	APort        :i32,
	//AConn        *net.UDPConn
	AControlPort :i32,
	//AControlConn *net.UDPConn
	VPort        :i32,
	//VConn        *net.UDPConn
	VControlPort :i32,
	//VControlConn *net.UDPConn

	Stoped        :bool,
}