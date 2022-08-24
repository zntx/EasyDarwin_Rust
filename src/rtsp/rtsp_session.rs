use std::time;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use std::net::TcpStream ;
use std::io::Read;

use super::pack::*;
use super::session_logger::SessionLogger;
use super::sdp_parser::SDPInfo;
use super::pusher::Pusher;
use super::player::Player;
use super::udp_client::UDPClient;
use super::rtsp_server::Server;
use super::rtsp_requset::Request;
use super::rtsp_response::Response;
pub enum SessionType{
	SESSION_TYPE_PUSHER,
	SESSEION_TYPE_PLAYER,
    UNKOWN,
}

impl SessionType {
    fn String(&self ) -> String {
        match self {
            SESSION_TYPE_PUSHER  => String::from("pusher"),
            SESSEION_TYPE_PLAYER => String::from("player"),
            UNKOWN => String::from("unknow"),
        } 
    }
}


pub struct Session {
    //sessionLogger : SessionLogger, 
    ID        : String,
    //Server    *Server
    //Conn      *RichConn
    connRW    :TcpStream,//*bufio.ReadWriter
    //connWLock sync.RWMutex
    Type      :SessionType,
    TransType :TransType,
    Path      : String,
    URL       : String,
    SDPRaw    : String,
    SDPMap    : Vec<(String, SDPInfo)>,

    authorizationEnable : bool,
    nonce               : String,
    closeOld            : bool,
    debugLogEnable      : bool,

    AControl : String,
    VControl : String,
    ACodec   : String,
    VCodec   : String,

    // stats info
    InBytes  :usize,
    OutBytes :i32,
    StartAt  :Instant,
    Timeout  :i32,

    Stoped : bool,

    //tcp channels
    aRTPChannel        :i32,
    aRTPControlChannel :i32,
    vRTPChannel        :i32,
    vRTPControlChannel :i32,

	Pusher      : Option<Pusher>,
	Player      : Option<Player>,
	UDPClient   : Option<UDPClient>,
	RTPHandles  : Vec<fn(&RTPPack) -> bool>,
	StopHandles : Vec<fn() -> bool>,
}

// ReadLine is a low-level line-reading primitive. Most callers should use
// ReadBytes('\n') or ReadString('\n') instead or use a Scanner.
//
// ReadLine tries to return a single line, not including the end-of-line bytes.
// If the line was too long for the buffer then isPrefix is set and the
// beginning of the line is returned. The rest of the line will be returned
// from future calls. isPrefix will be false when returning the last fragment
// of the line. The returned buffer is only valid until the next call to
// ReadLine. ReadLine either returns a non-nil line or it returns an error,
// never both.
//
// The text returned from ReadLine does not include the line end ("\r\n" or "\n").
// No indication or error is given if the input ends without a final line end.
// Calling UnreadByte after ReadLine will always unread the last byte read
// (possibly a character belonging to the line end) even if that byte is not
// part of the line returned by ReadLine.
fn ReadLine(stream: &mut TcpStream) -> (Vec<u8>, bool, String)
{
    let mut buf:Vec<u8> = Vec::new();
    let mut isPrefix = false;
    let mut errInfo  = String::new();    
    loop {
        for byte in stream.bytes() {
            match byte {
            Ok(ch) => {
                if ch == '\n' as u8 {
                    isPrefix = true;
                    break;
                }
                else if ch == '\r' as u8 {
                    continue;
                }
                buf.push(ch)
            },
            Err(err) => {
                println!("error {}", err);
                errInfo  = format!("{}", err);    
                break;
            }
        }
        }
    }
    (buf, isPrefix, errInfo)
}

impl Session {
    //pub fn String(&self) ->String {
    //    String::From("session{}{}{}{}{}", self.Type, self.TransType, self.Path, self.ID, self.Conn.RemoteAddr().String())
    //}


    pub fn NewSession(server :&Server, conn :TcpStream) ->Session {
        let networkBuffer = 204800;//:= utils.Conf().Section("rtsp").Key("network_buffer").MustInt(204800)
        let timeoutMillis = 0;//:= utils.Conf().Section("rtsp").Key("timeout").MustInt(0)
        //let timeoutTCPConn := &RichConn{conn, time.Duration(timeoutMillis) * time.Millisecond}
        let authorizationEnable = false;//:= utils.Conf().Section("rtsp").Key("authorization_enable").MustInt(0)
        let close_old = 0;//:= utils.Conf().Section("rtsp").Key("close_old").MustInt(0)
        let debugLogEnable = 0;//:= utils.Conf().Section("rtsp").Key("debug_log_enable").MustInt(0)

        let time_now = SystemTime::now();
        let session = Session {
            //sessionLogger : SessionLogger, 
            ID        : "0".to_string(),
            //Server    *Server
            //Conn      *RichConn
            connRW    : conn,//*bufio.ReadWriter
            //connWLock sync.RWMutex
            Type      : SessionType::UNKOWN,
            TransType : TransType::UNKOWN,
            Path      : String::new(),
            URL       : String::new(),
            SDPRaw    : String::new(),
            SDPMap    : Vec::new(),

            authorizationEnable : false,
            nonce               : String::new(),
            closeOld            : false,
            debugLogEnable      : false,

            AControl : String::new(),
            VControl : String::new(),
            ACodec   : String::new(),
            VCodec   : String::new(),

            // stats info
            InBytes  : 0,
            OutBytes : 0,
            StartAt  : Instant::now(),
            Timeout  : 30,

            Stoped : false,

            //tcp channels
            aRTPChannel        : -1,
            aRTPControlChannel : -1,
            vRTPChannel        : -1,
            vRTPControlChannel : -1,

            Pusher      : None,
            Player      : None,
            UDPClient   : None,
            RTPHandles  : Vec::new(),
            StopHandles : Vec::new(),
        };



        //session.logger = log.New(os.Stdout, fmt.Sprintf("[%s]", session.ID), log.LstdFlags|log.Lshortfile)
        //if !utils.Debug {
        //    session.logger.SetOutput(utils.GetLogWriter())
        //}
        return session
    }

    pub fn Stop(&mut self) {
        if self.Stoped {
            return;
        }
        self.Stoped = true;
        for h in  self.StopHandles {
            h();
        }
        /* 
        if self.Conn != nil {
            self.connRW.Flush();
            self.Conn.Close();
            self.Conn = nil;
        }
        if self.UDPClient != nil {
            self.UDPClient.Stop();
            self.UDPClient = nil;
        } */
    }

    pub fn Start(&mut self) {
        //defer session.Stop()
        let mut buf1 = [0u8; 4];//= make([]byte, 1)
        //buf2 := make([]byte, 2)
        //logger := session.logger
        let mut timer = Instant::now();//:= time.Unix(0, 0)
        loop {
            if self.Stoped == true {
                println!("session stop");
                break;
            }

            let len = self.connRW.read(&mut buf1).unwrap();
            println!("Request: len {}", len);

            /*if _, err := io.ReadFull(session.connRW, buf1); err != nil {
                logger.Println(session, err)
                return
            }*/
            if buf1[0] == 0x24 { //rtp data
                /*if _, err := io.ReadFull(session.connRW, buf1); err != nil {
                    logger.Println(err)
                    return
                }
                if _, err := io.ReadFull(session.connRW, buf2); err != nil {
                    logger.Println(err)
                    return
                }*/
                let channel = buf1[1] as i32;//int(buf1[1]);
                let rtpLen  = buf1[2] as usize;//int(binary.BigEndian.Uint16(buf1[2]));
                let mut rtpBytes = Vec::<u8>::with_capacity(rtpLen);//make([]byte, rtpLen)
                let len = self.connRW.read(&mut rtpBytes).unwrap();

                println!("Request: len {}", len);
    
                //rtpBuf := bytes.NewBuffer(rtpBytes)
                let mut pack = RTPPack{
                    Type   : RTPType::UNKOWN,
                    Buffer : rtpBytes,//*bytes.Buffer
                };

                if channel == self.aRTPChannel {
                    
                    pack.Type = RTPType::RTP_TYPE_AUDIO;
                    
                    let elapsed  = &timer.elapsed();
                    if elapsed.as_secs()   >= 30 {
                        println!("Recv an audio RTP package");
                        timer = Instant::now();
                    }
                }
                else if channel == self.aRTPControlChannel {
                    pack.Type = RTPType::RTP_TYPE_AUDIOCONTROL;
                }
                else if channel == self.vRTPChannel {
                    pack.Type = RTPType::RTP_TYPE_VIDEO;
                    let elapsed  = &timer.elapsed();let elapsed_time = &timer.elapsed();
                    if elapsed.as_secs() >= 30 {
                        println!("Recv an video RTP package");
                        timer = Instant::now();
                    }
                }
                else if channel == self.vRTPControlChannel {
                    pack.Type = RTPType::RTP_TYPE_VIDEOCONTROL;
                }
                else {
                    println!("unknow rtp pack type, {}", channel);
                    continue
                }
                self.InBytes += rtpLen + 4;
                for h in self.RTPHandles {
                    h(&pack);
                }
            } else { // rtsp cmd
                let reqBuf = Vec::<u8>::new();//= bytes.NewBuffer(nil)
                //reqBuf.Write(buf1)
                loop {
                    if self.Stoped == false {
                        println!("session stop ");
                        break;
                    }
                    ;
                    let (line, isPrefix, err) = ReadLine(&mut self.connRW); 
                    if err.len() == 0 {
                        println!("{}",err);
                        return
                    } 
                    else {
                        
                        for ch in &line { reqBuf.push( *ch );}
                        if !isPrefix {
                            for ch in b"\r\n" { reqBuf.push( *ch );}
                        }
                        if line.len() == 0 {//空行
                            let requests = String::from_utf8_lossy(&reqBuf);
                            println!("Request: [{}]", requests);
                             
                            let mut req = Request::NewRequest(requests.to_string());
                            if let req = None {
                                break
                            }
                            let req = req.unwrap();

                            self.InBytes += reqBuf.len();
                            let contentLen : usize = req.GetContentLength() as usize;
                            self.InBytes += contentLen ;
                            if contentLen > 0 {
                                let mut bodyBuf = Vec::with_capacity(contentLen) ;//make([]byte, contentLen)
                                let len  = 0;
                                match self.connRW.read(&mut bodyBuf) {
                                    Ok(_len) => { len =_len;},
                                    Err(err) => { println!(" error {} ", err); },
                                }
                                if len != contentLen {
                                    println!("read rtsp request body failed, expect size{}, got size{}", contentLen, len);
                                    return ;
                                }
                                req.Body = String::from_utf8_lossy(&reqBuf).to_string();
                            }
                            self.handleRequest(req);
                            break;
                        }
                    }
                }
            }
        }
    }
/* 
    fn CheckAuth(authLine :String, method :String, sessionNonce :String) -> String {
        realmRex := regexp.MustCompile(`realm="(.*?)"`)
        nonceRex := regexp.MustCompile(`nonce="(.*?)"`)
        usernameRex := regexp.MustCompile(`username="(.*?)"`)
        responseRex := regexp.MustCompile(`response="(.*?)"`)
        uriRex := regexp.MustCompile(`uri="(.*?)"`)

        realm := ""
        nonce := ""
        username := ""
        response := ""
        uri := ""
        result1 := realmRex.FindStringSubmatch(authLine)
        if len(result1) == 2 {
            realm = result1[1]
        } else {
            return fmt.Errorf("CheckAuth error : no realm found")
        }
        result1 = nonceRex.FindStringSubmatch(authLine)
        if len(result1) == 2 {
            nonce = result1[1]
        } else {
            return fmt.Errorf("CheckAuth error : no nonce found")
        }
        if sessionNonce != nonce {
            return fmt.Errorf("CheckAuth error : sessionNonce not same as nonce")
        }

        result1 = usernameRex.FindStringSubmatch(authLine)
        if len(result1) == 2 {
            username = result1[1]
        } else {
            return fmt.Errorf("CheckAuth error : username not found")
        }

        result1 = responseRex.FindStringSubmatch(authLine)
        if len(result1) == 2 {
            response = result1[1]
        } else {
            return fmt.Errorf("CheckAuth error : response not found")
        }

        result1 = uriRex.FindStringSubmatch(authLine)
        if len(result1) == 2 {
            uri = result1[1]
        } else {
            return fmt.Errorf("CheckAuth error : uri not found")
        }
        var user models.User
        err := db.SQLite.Where("Username = ?", username).First(&user).Error
        if err != nil {
            return fmt.Errorf("CheckAuth error : user not exists")
        }
        md5UserRealmPwd := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", username, realm, user.Password))))
        md5MethodURL := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s", method, uri))))
        myResponse := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", md5UserRealmPwd, nonce, md5MethodURL))))
        if myResponse != response {
            return fmt.Errorf("CheckAuth error : response not equal")
        }
        return nil
    }
*/
    pub fn handleRequest(&mut self, req : Request) {
        //if session.Timeout > 0 {
        //	session.Conn.SetDeadline(time.Now().Add(time.Duration(session.Timeout) * time.Second))
        //}
        //logger := session.logger
        println!("<<<\n{:?}", req);
        
        let res = Response::NewResponse(200, "OK".to_string(), req.Header["CSeq"], self.ID.clone(), "".to_string());
        /*defer fn() {
            if p := recover(); p != nil {
                logger.Printf("handleRequest err ocurs:%v", p)
                res.StatusCode = 500
                res.Status = fmt.Sprintf("Inner Server Error, %v", p)
            }
            logger.Printf(">>>\n%s", res)
            outBytes := []byte(res.String())
            session.connWLock.Lock()
            session.connRW.Write(outBytes)
            session.connRW.Flush()
            session.connWLock.Unlock()
            session.OutBytes += len(outBytes)
            switch req.Method {
            case "PLAY", "RECORD":
                switch session.Type {
                case SESSEION_TYPE_PLAYER:
                    if session.Pusher.HasPlayer(session.Player) {
                        session.Player.Pause(false)
                    } else {
                        session.Pusher.AddPlayer(session.Player)
                    }
                    // case SESSION_TYPE_PUSHER:
                    // 	session.Server.AddPusher(session.Pusher)
                }
            case "TEARDOWN":
                {
                    session.Stop()
                    return
                }
            }
            if res.StatusCode != 200 && res.StatusCode != 401 {
                logger.Printf("Response request error[%d]. stop session.", res.StatusCode)
                session.Stop()
            }
        }()*/
        if req.Method != "OPTIONS".to_string() {
            if self.authorizationEnable {
                let authLine = &req.Header.get("Authorization").unwrap();
                let mut authFailed = true;
                if (*authLine).len() != 0  {
                    let err = CheckAuth(authLine, req.Method, self.nonce);
                    if err == String::new() {
                        authFailed = false;
                    } else {
                       println!("{}", err);
                    }
                }
                if authFailed {
                    res.StatusCode = 401;
                    res.Status = "Unauthorized".to_string();
                    let nonce  = format!("{}", md5.Sum([]byte(shortid.MustGenerate())));
                    self.nonce = nonce;
                    res.Header.insert("WWW-Authenticate".to_string(), format!("Digest realm=\"EasyDarwin\", nonce=\"{}\", algorithm=\"MD5\"", nonce));
                    return
                }
            }
        }
        //switch req.Method {
        if req.Method  == "OPTIONS" {
            res.Header.insert("Public".to_string(),  "DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, OPTIONS, ANNOUNCE, RECORD".to_string());
        }
        else if req.Method  == "ANNOUNCE" {
            self.Type = SessionType::SESSION_TYPE_PUSHER;
            self.URL = req.URL.clone();

            url, err := url.Parse(req.URL);
            if err != nil {
                res.StatusCode = 500;
                res.Status = "Invalid URL".to_string();
                return
            }
            self.Path = url.Path;

            self.SDPRaw = req.Body;
            self.SDPMap = ParseSDP(req.Body);
            sdp, ok := session.SDPMap["audio"]
            if ok {
                session.AControl = sdp.Control
                session.ACodec = sdp.Codec
                logger.Printf("audio codec[%s]\n", session.ACodec)
            }
            sdp, ok = session.SDPMap["video"]
            if ok {
                session.VControl = sdp.Control
                session.VCodec = sdp.Codec
                logger.Printf("video codec[%s]\n", session.VCodec)
            }
            addPusher := false
            if session.closeOld {
                r, _ := session.Server.TryAttachToPusher(session)
                if r < -1 {
                    logger.Printf("reject pusher.")
                    res.StatusCode = 406
                    res.Status = "Not Acceptable"
                } else if r == 0 {
                    addPusher = true
                } else {
                    logger.Printf("Attached to old pusher")
                    // 尝试发给客户端ANNOUCE
                    // players := pusher.GetPlayers()
                    // for _, v := range players {
                    // 	sess := v.Session

                    // 	hearers := make(map[string]string)
                    // 	hearers["Content-Type"] = "application/sdp"
                    // 	hearers["Session"] = sess.ID
                    // 	hearers["Content-Length"] = strconv.Itoa(len(v.SDPRaw))
                    // 	var req = Request{Method: ANNOUNCE, URL: v.URL, Version: "1.0", Header: hearers, Body: pusher.SDPRaw()}
                    // 	sess.connWLock.Lock()
                    // 	logger.Println(req.String())
                    // 	outBytes := []byte(req.String())
                    // 	sess.connRW.Write(outBytes)
                    // 	sess.connRW.Flush()
                    // 	sess.connWLock.Unlock()
                    // }
                }
            } else {
                addPusher = true
            }
            if addPusher {
                session.Pusher = NewPusher(session)
                addedToServer := session.Server.AddPusher(session.Pusher)
                if !addedToServer {
                    logger.Printf("reject pusher.")
                    res.StatusCode = 406
                    res.Status = "Not Acceptable"
                }
            }
        }
        else if req.Method  == "DESCRIBE" {
            session.Type = SESSEION_TYPE_PLAYER
            session.URL = req.URL

            url, err := url.Parse(req.URL)
            if err != nil {
                res.StatusCode = 500
                res.Status = "Invalid URL"
                return
            }
            session.Path = url.Path
            pusher := session.Server.GetPusher(session.Path)
            if pusher == nil {
                res.StatusCode = 404
                res.Status = "NOT FOUND"
                return
            }
            session.Player = NewPlayer(session, pusher)
            session.Pusher = pusher
            session.AControl = pusher.AControl()
            session.VControl = pusher.VControl()
            session.ACodec = pusher.ACodec()
            session.VCodec = pusher.VCodec()
            session.Conn.timeout = 0
            res.SetBody(session.Pusher.SDPRaw())
        }
        else if req.Method  == "SETUP" {
            ts := req.Header["Transport"]
            // control字段可能是`stream=1`字样，也可能是rtsp://...字样。即control可能是url的path，也可能是整个url
            // 例1：
            // a=control:streamid=1
            // 例2：
            // a=control:rtsp://192.168.1.64/trackID=1
            // 例3：
            // a=control:?ctype=video
            setupUrl, err := url.Parse(req.URL)
            if err != nil {
                res.StatusCode = 500
                res.Status = "Invalid URL"
                return
            }
            if setupUrl.Port() == "" {
                setupUrl.Host = fmt.Sprintf("%s:554", setupUrl.Host)
            }
            setupPath := setupUrl.String()

            // error status. SETUP without ANNOUNCE or DESCRIBE.
            if session.Pusher == nil {
                res.StatusCode = 500
                res.Status = "Error Status"
                return
            }
            //setupPath = setupPath[strings.LastIndex(setupPath, "/")+1:]
            vPath := ""
            if strings.Index(strings.ToLower(session.VControl), "rtsp://") == 0 {
                vControlUrl, err := url.Parse(session.VControl)
                if err != nil {
                    res.StatusCode = 500
                    res.Status = "Invalid VControl"
                    return
                }
                if vControlUrl.Port() == "" {
                    vControlUrl.Host = fmt.Sprintf("%s:554", vControlUrl.Host)
                }
                vPath = vControlUrl.String()
            } else {
                vPath = session.VControl
            }

            aPath := ""
            if strings.Index(strings.ToLower(session.AControl), "rtsp://") == 0 {
                aControlUrl, err := url.Parse(session.AControl)
                if err != nil {
                    res.StatusCode = 500
                    res.Status = "Invalid AControl"
                    return
                }
                if aControlUrl.Port() == "" {
                    aControlUrl.Host = fmt.Sprintf("%s:554", aControlUrl.Host)
                }
                aPath = aControlUrl.String()
            } else {
                aPath = session.AControl
            }

            mtcp := regexp.MustCompile("interleaved=(\\d+)(-(\\d+))?")
            mudp := regexp.MustCompile("client_port=(\\d+)(-(\\d+))?")

            if tcpMatchs := mtcp.FindStringSubmatch(ts); tcpMatchs != nil {
                session.TransType = TRANS_TYPE_TCP
                if setupPath == aPath || aPath != "" && strings.LastIndex(setupPath, aPath) == len(setupPath)-len(aPath) {
                    session.aRTPChannel, _ = strconv.Atoi(tcpMatchs[1])
                    session.aRTPControlChannel, _ = strconv.Atoi(tcpMatchs[3])
                } else if setupPath == vPath || vPath != "" && strings.LastIndex(setupPath, vPath) == len(setupPath)-len(vPath) {
                    session.vRTPChannel, _ = strconv.Atoi(tcpMatchs[1])
                    session.vRTPControlChannel, _ = strconv.Atoi(tcpMatchs[3])
                } else {
                    res.StatusCode = 500
                    res.Status = fmt.Sprintf("SETUP [TCP] got UnKown control:%s", setupPath)
                    logger.Printf("SETUP [TCP] got UnKown control:%s", setupPath)
                }
                logger.Printf("Parse SETUP req.TRANSPORT:TCP.Session.Type:%d,control:%s, AControl:%s,VControl:%s", session.Type, setupPath, aPath, vPath)
            } else if udpMatchs := mudp.FindStringSubmatch(ts); udpMatchs != nil {
                session.TransType = TRANS_TYPE_UDP
                // no need for tcp timeout.
                session.Conn.timeout = 0
                if session.Type == SESSEION_TYPE_PLAYER && session.UDPClient == nil {
                    session.UDPClient = &UDPClient{
                        Session: session,
                    }
                }
                if session.Type == SESSION_TYPE_PUSHER && session.Pusher.UDPServer == nil {
                    session.Pusher.UDPServer = &UDPServer{
                        Session: session,
                    }
                }
                logger.Printf("Parse SETUP req.TRANSPORT:UDP.Session.Type:%d,control:%s, AControl:%s,VControl:%s", session.Type, setupPath, aPath, vPath)
                if setupPath == aPath || aPath != "" && strings.LastIndex(setupPath, aPath) == len(setupPath)-len(aPath) {
                    if session.Type == SESSEION_TYPE_PLAYER {
                        session.UDPClient.APort, _ = strconv.Atoi(udpMatchs[1])
                        session.UDPClient.AControlPort, _ = strconv.Atoi(udpMatchs[3])
                        if err := session.UDPClient.SetupAudio(); err != nil {
                            res.StatusCode = 500
                            res.Status = fmt.Sprintf("udp client setup audio error, %v", err)
                            return
                        }
                    }
                    if session.Type == SESSION_TYPE_PUSHER {
                        if err := session.Pusher.UDPServer.SetupAudio(); err != nil {
                            res.StatusCode = 500
                            res.Status = fmt.Sprintf("udp server setup audio error, %v", err)
                            return
                        }
                        tss := strings.Split(ts, ";")
                        idx := -1
                        for i, val := range tss {
                            if val == udpMatchs[0] {
                                idx = i
                            }
                        }
                        tail := append([]string{}, tss[idx+1:]...)
                        tss = append(tss[:idx+1], fmt.Sprintf("server_port=%d-%d", session.Pusher.UDPServer.APort, session.Pusher.UDPServer.AControlPort))
                        tss = append(tss, tail...)
                        ts = strings.Join(tss, ";")
                    }
                } else if setupPath == vPath || vPath != "" && strings.LastIndex(setupPath, vPath) == len(setupPath)-len(vPath) {
                    if session.Type == SESSEION_TYPE_PLAYER {
                        session.UDPClient.VPort, _ = strconv.Atoi(udpMatchs[1])
                        session.UDPClient.VControlPort, _ = strconv.Atoi(udpMatchs[3])
                        if err := session.UDPClient.SetupVideo(); err != nil {
                            res.StatusCode = 500
                            res.Status = fmt.Sprintf("udp client setup video error, %v", err)
                            return
                        }
                    }

                    if session.Type == SESSION_TYPE_PUSHER {
                        if err := session.Pusher.UDPServer.SetupVideo(); err != nil {
                            res.StatusCode = 500
                            res.Status = fmt.Sprintf("udp server setup video error, %v", err)
                            return
                        }
                        tss := strings.Split(ts, ";")
                        idx := -1
                        for i, val := range tss {
                            if val == udpMatchs[0] {
                                idx = i
                            }
                        }
                        tail := append([]string{}, tss[idx+1:]...)
                        tss = append(tss[:idx+1], fmt.Sprintf("server_port=%d-%d", session.Pusher.UDPServer.VPort, session.Pusher.UDPServer.VControlPort))
                        tss = append(tss, tail...)
                        ts = strings.Join(tss, ";")
                    }
                } else {
                    logger.Printf("SETUP [UDP] got UnKown control:%s", setupPath)
                }
            }
            res.Header["Transport"] = ts
        }
        else if req.Method  == "PLAY" {
            // error status. PLAY without ANNOUNCE or DESCRIBE.
            if session.Pusher == nil {
                res.StatusCode = 500
                res.Status = "Error Status"
                return
            }
            res.Header["Range"] = req.Header["Range"]
        }
        else if req.Method  == "RECORD" {
            // error status. RECORD without ANNOUNCE or DESCRIBE.
            if session.Pusher == nil {
                res.StatusCode = 500
                res.Status = "Error Status"
                return
            }
        }
        else if req.Method  == "PAUSE" {
            if session.Player == nil {
                res.StatusCode = 500
                res.Status = "Error Status"
                return
            }
            session.Player.Pause(true)
        }
    }

    fn SendRTP(&mut self,pack *RTPPack) ->(err error) {
        if pack == nil {
            err = fmt.Errorf("player send rtp got nil pack")
            return
        }
        if session.TransType == TRANS_TYPE_UDP {
            if session.UDPClient == nil {
                err = fmt.Errorf("player use udp transport but udp client not found")
                return
            }
            err = session.UDPClient.SendRTP(pack)
            return
        }
        switch pack.Type {
        case RTP_TYPE_AUDIO:
            bufChannel := make([]byte, 2)
            bufChannel[0] = 0x24
            bufChannel[1] = byte(session.aRTPChannel)
            session.connWLock.Lock()
            session.connRW.Write(bufChannel)
            bufLen := make([]byte, 2)
            binary.BigEndian.PutUint16(bufLen, uint16(pack.Buffer.Len()))
            session.connRW.Write(bufLen)
            session.connRW.Write(pack.Buffer.Bytes())
            session.connRW.Flush()
            session.connWLock.Unlock()
            session.OutBytes += pack.Buffer.Len() + 4
        case RTP_TYPE_AUDIOCONTROL:
            bufChannel := make([]byte, 2)
            bufChannel[0] = 0x24
            bufChannel[1] = byte(session.aRTPControlChannel)
            session.connWLock.Lock()
            session.connRW.Write(bufChannel)
            bufLen := make([]byte, 2)
            binary.BigEndian.PutUint16(bufLen, uint16(pack.Buffer.Len()))
            session.connRW.Write(bufLen)
            session.connRW.Write(pack.Buffer.Bytes())
            session.connRW.Flush()
            session.connWLock.Unlock()
            session.OutBytes += pack.Buffer.Len() + 4
        case RTP_TYPE_VIDEO:
            bufChannel := make([]byte, 2)
            bufChannel[0] = 0x24
            bufChannel[1] = byte(session.vRTPChannel)
            session.connWLock.Lock()
            session.connRW.Write(bufChannel)
            bufLen := make([]byte, 2)
            binary.BigEndian.PutUint16(bufLen, uint16(pack.Buffer.Len()))
            session.connRW.Write(bufLen)
            session.connRW.Write(pack.Buffer.Bytes())
            session.connRW.Flush()
            session.connWLock.Unlock()
            session.OutBytes += pack.Buffer.Len() + 4
        case RTP_TYPE_VIDEOCONTROL:
            bufChannel := make([]byte, 2)
            bufChannel[0] = 0x24
            bufChannel[1] = byte(session.vRTPControlChannel)
            session.connWLock.Lock()
            session.connRW.Write(bufChannel)
            bufLen := make([]byte, 2)
            binary.BigEndian.PutUint16(bufLen, uint16(pack.Buffer.Len()))
            session.connRW.Write(bufLen)
            session.connRW.Write(pack.Buffer.Bytes())
            session.connRW.Flush()
            session.connWLock.Unlock()
            session.OutBytes += pack.Buffer.Len() + 4
        default:
            err = fmt.Errorf("session tcp send rtp got unkown pack type[%v]", pack.Type)
        }
        return
    }
}
