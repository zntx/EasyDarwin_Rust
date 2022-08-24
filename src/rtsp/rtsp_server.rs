use std::cell::RefCell;
use std::net::UdpSocket;

use std::net::{TcpListener, TcpStream, SocketAddr}; 
use std::ops::DerefMut;
use std::thread;
use std::io::Read;
use std::io::prelude::*;

use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::sync::Mutex;



use super::session_logger::SessionLogger;
use super::pusher::Pusher;
use super::rtsp_session::Session;
pub struct Server {
    sessionLogger : SessionLogger,
    TCPListener    : TcpListener,			//tcp 链接会话句柄
	TCPPort        : i32,
	Stoped         : bool,
	pushers        : Vec< (String,  Pusher)>,// map[string]*Pusher, // Path <-> Pusher 推流客户端
	//pushersLock    : sync.RWMutex,
	addPusherCh    : (mpsc::Sender<Pusher>, Receiver<Pusher>), // 添加本地存储的 的通道
	removePusherCh : (mpsc::Sender<Pusher>, Receiver<Pusher>), // 移除本地存储的 的通道

	//session: Vec<Arc<RefCell<Session>>>,
}



impl Server {
	pub fn GetServer() -> Server {
		Server{
			sessionLogger:  SessionLogger::new(),
			TCPListener: 	TcpListener::bind("0.0.0.0:7878").unwrap(),
			Stoped:         true,
			TCPPort:        554,//utils.Conf().Section("rtsp").Key("port").MustInt(554),
			pushers:        Vec::with_capacity(5),//make(map[string]*Pusher),
			addPusherCh:    mpsc::channel(),//make(chan *Pusher),
			removePusherCh: mpsc::channel(),//make(chan *Pusher),
		}
	}

	pub fn Start(&mut self)  {
		/*var (
			//logger   = server.logger
			addr     *net.TCPAddr
			listener *net.TCPListener
		)
		if addr, err = net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", server.TCPPort)); err != nil {
			return
		}
		if listener, err = net.ListenTCP("tcp", addr); err != nil {
			return
		}*/

		let localRecord = false;//:= utils.Conf().Section("rtsp").Key("save_stream_to_local").MustInt(0)
		let ffmpeg = "";//:= utils.Conf().Section("rtsp").Key("ffmpeg_path").MustString("")
		let m3u8_dir_path = "";//:= utils.Conf().Section("rtsp").Key("m3u8_dir_path").MustString("")
		let ts_duration_second = 6;//:= utils.Conf().Section("rtsp").Key("ts_duration_second").MustInt(6)
		//let mut SaveStreamToLocal = false;
		/*if (len(ffmpeg) > 0) && localRecord > 0 && len(m3u8_dir_path) > 0 {
			err = utils.EnsureDir(m3u8_dir_path)
			if err != nil {
				logger.Printf("Create m3u8_dir_path[%s] err:%v.", m3u8_dir_path, err)
			} else {
				SaveStreamToLocal = true
			}
		}*/
		/* 
		go fn() { // save to local.
			pusher2ffmpegMap := make(map[*Pusher]*exec.Cmd)
			if SaveStreamToLocal {
				logger.Printf("Prepare to save stream to local....")
				defer logger.Printf("End save stream to local....")
			}
			var pusher *Pusher
			addChnOk := true
			removeChnOk := true
			for addChnOk || removeChnOk {
				select {
				case pusher, addChnOk = <-server.addPusherCh:
					if SaveStreamToLocal {
						if addChnOk {
							dir := path.Join(m3u8_dir_path, pusher.Path(), time.Now().Format("20060102"))
							err := utils.EnsureDir(dir)
							if err != nil {
								logger.Printf("EnsureDir:[%s] err:%v.", dir, err)
								continue
							}
							m3u8path := path.Join(dir, fmt.Sprintf("out.m3u8"))
							port := pusher.Server().TCPPort
							rtsp := fmt.Sprintf("rtsp://localhost:%d%s", port, pusher.Path())
							paramStr := utils.Conf().Section("rtsp").Key(pusher.Path()).MustString("-c:v copy -c:a aac")
							params := []string{"-fflags", "genpts", "-rtsp_transport", "tcp", "-i", rtsp, "-hls_time", strconv.Itoa(ts_duration_second), "-hls_list_size", "0", m3u8path}
							if paramStr != "default" {
								paramsOfThisPath := strings.Split(paramStr, " ")
								params = append(params[:6], append(paramsOfThisPath, params[6:]...)...)
							}
							// ffmpeg -i ~/Downloads/720p.mp4 -s 640x360 -g 15 -c:a aac -hls_time 5 -hls_list_size 0 record.m3u8
							cmd := exec.Command(ffmpeg, params...)
							f, err := os.OpenFile(path.Join(dir, fmt.Sprintf("log.txt")), os.O_RDWR|os.O_CREATE, 0755)
							if err == nil {
								cmd.Stdout = f
								cmd.Stderr = f
							}
							err = cmd.Start()
							if err != nil {
								logger.Printf("Start ffmpeg err:%v", err)
							}
							pusher2ffmpegMap[pusher] = cmd
							logger.Printf("add ffmpeg [%v] to pull stream from pusher[%v]", cmd, pusher)
						} else {
							logger.Printf("addPusherChan closed")
						}
					}
				case pusher, removeChnOk = <-server.removePusherCh:
					if SaveStreamToLocal {
						if removeChnOk {
							cmd := pusher2ffmpegMap[pusher]
							proc := cmd.Process
							if proc != nil {
								logger.Printf("prepare to SIGTERM to process:%v", proc)
								proc.Signal(syscall.SIGTERM)
								proc.Wait()
								// proc.Kill()
								// no need to close attached log file.
								// see "Wait releases any resources associated with the Cmd."
								// if closer, ok := cmd.Stdout.(io.Closer); ok {
								// 	closer.Close()
								// 	logger.Printf("process:%v Stdout closed.", proc)
								// }
								logger.Printf("process:%v terminate.", proc)
							}
							delete(pusher2ffmpegMap, pusher)
							logger.Printf("delete ffmpeg from pull stream from pusher[%v]", pusher)
						} else {
							for _, cmd := range pusher2ffmpegMap {
								proc := cmd.Process
								if proc != nil {
									logger.Printf("prepare to SIGTERM to process:%v", proc)
									proc.Signal(syscall.SIGTERM)
								}
							}
							pusher2ffmpegMap = make(map[*Pusher]*exec.Cmd)
							logger.Printf("removePusherChan closed")
						}
					}
				}
			}
		}()*/

		self.Stoped = false;
		//server.TCPListener = listener
		println!("rtsp server start on{}", self.TCPPort);
		//networkBuffer := utils.Conf().Section("rtsp").Key("network_buffer").MustInt(1048576)
		loop  {
			if self.Stoped == false {
				println!("server stop. exit");
				break;
			}
			match self.TCPListener.accept() {  // 有请求到来
				Ok((mut scoket, addr)) => {
					println!("new clinet : {addr:?}");
					//id = id + 1;
					
					let session = Session::NewSession(self, scoket);
					//let session = Arc::new(RefCell::new(session));

					//self.session.push(session);

					

					let thread_session = thread::spawn( move || { // 没个新的请求创建线程去处理
						session.Start(  );
					});
					
				},
				Err(e) =>println!("couldnot get client:{e:?}"),
			}
		}
		return
	}

	pub fn Stop(& mut self ) {
		//logger := server.logger
		//logger.Println("rtsp server stop on", server.TCPPort)
		self.Stoped = true;
		//if self.TCPListener != nil {
		//	self.TCPListener.Close();
		//	//server.TCPListener = nil
		//}
		//server.pushersLock.Lock()
		//server.pushers = make(map[string]*Pusher)
		//server.pushersLock.Unlock()

		//close(server.addPusherCh)
		//close(server.removePusherCh)
	}
	/*
	fn AddPusher(&mut self , pusher : &Pusher) ->bool {
		//logger := server.logger
		let added = false;
		//server.pushersLock.Lock()
		_, ok := server.pushers[pusher.Path()]
		if !ok {
			server.pushers[pusher.Path()] = pusher
			logger.Printf("%v start, now pusher size[%d]", pusher, len(server.pushers))
			added = true
		} else {
			added = false
		}
		server.pushersLock.Unlock()
		if added {
			go pusher.Start()
			server.addPusherCh <- pusher
		}
		return added
	}

	fn TryAttachToPusher(&self, session : &Session) ->(int, &Pusher) {
		server.pushersLock.Lock()
		attached := 0
		var pusher *Pusher = nil
		if _pusher, ok := server.pushers[session.Path]; ok {
			if _pusher.RebindSession(session) {
				session.logger.Printf("Attached to a pusher")
				attached = 1
				pusher = _pusher
			} else {
				attached = -1
			}
		}
		server.pushersLock.Unlock()
		return attached, pusher
	}

	fn RemovePusher(&self, pusher : &Pusher) {
		logger := server.logger
		removed := false
		server.pushersLock.Lock()
		if _pusher, ok := server.pushers[pusher.Path()]; ok && pusher.ID() == _pusher.ID() {
			delete(server.pushers, pusher.Path())
			logger.Printf("%v end, now pusher size[%d]\n", pusher, len(server.pushers))
			removed = true
		}
		server.pushersLock.Unlock()
		if removed {
			server.removePusherCh <- pusher
		}
	}

	fn GetPusher(&self, path string) (pusher *Pusher) {
		server.pushersLock.RLock()
		pusher = server.pushers[path]
		server.pushersLock.RUnlock()
		return
	}

	fn GetPushers(&self ) (pushers map[string]*Pusher) {
		pushers = make(map[string]*Pusher)
		server.pushersLock.RLock()
		for k, v := range server.pushers {
			pushers[k] = v
		}
		server.pushersLock.RUnlock()
		return
	}*/

	fn  GetPusherSize(&self) -> usize {
		//server.pushersLock.RLock()
		let size = self.pushers.len();
		//server.pushersLock.RUnlock()
		return size;
	}
}
