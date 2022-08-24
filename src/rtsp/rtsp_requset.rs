
use std::collections::HashMap;

pub const RTSP_VERSION: &str = "RTSP/1.0";

// Client to server for presentation and stream objects; recommended
pub const DESCRIBE: &str = "DESCRIBE";
// Bidirectional for client and stream objects; optional
pub const ANNOUNCE: &str = "ANNOUNCE";
// Bidirectional for client and stream objects; optional
pub const GET_PARAMETER: &str = "GET_PARAMETER";
// Bidirectional for client and stream objects; required for Client to server, optional for server to client
pub const OPTIONS: &str = "OPTIONS";
// Client to server for presentation and stream objects; recommended
pub const PAUSE: &str = "PAUSE";
// Client to server for presentation and stream objects; required
pub const PLAY: &str = "PLAY";
// Client to server for presentation and stream objects; optional
pub const RECORD: &str = "RECORD";
// Server to client for presentation and stream objects; optional
pub const REDIRECT: &str = "REDIRECT";
// Client to server for stream objects; required
pub const SETUP: &str = "SETUP";
// Bidirectional for presentation and stream objects; optional
pub const SET_PARAMETER: &str = "SET_PARAMETER";
// Client to server for presentation and stream objects; required
pub const TEARDOWN: &str = "TEARDOWN";
pub const DATA: &str = "DATA";

#[derive(Debug)]
pub struct Request {
    pub Method: String,
    pub URL: String,
    pub Version: String,
    pub Header: HashMap<String, String>, //map[string]string
    pub Content: String,
    pub Body: String,
}

impl Request {
    pub fn NewRequest(content: String) -> Option<Request> {
        //lines := strings.Split(strings.TrimSpace(content), "\r\n")
        let lines: Vec<&str> = content.split("\r\n").collect();
        if lines.len() == 0 {
            return None;
        }

        /*let items = regexp.MustCompile("\\s+").Split(strings.TrimSpace(lines[0]), -1);
        if items.len() < 3 {
            return nil
        }
        if !strings.HasPrefix(items[2], "RTSP") {
            log.Printf("invalid rtsp request, line[0] %s", lines[0])
            return nil
        }*/

        let mut method = String::new();
        let mut url = String::new();
        let mut version = String::new();
        let mut header = HashMap::new(); //(map[string]string)
        for i in 0..lines.len() {
            let line = lines.get(i).unwrap();
            let line = line.trim();

            if i == 0 {
                if line.contains("RTSP") == false {
                    return None;
                }
            }

            //let headerItems = regexp.MustCompile(":\\s+").Split(line, 2);
            let headerItems: Vec<&str> = line.split(" ").collect();
            if headerItems.len() < 2 {
                continue;
            }
            if i == 0 {
                if headerItems.len() < 3 {
                    continue;
                }
                let mut method = String::from(*headerItems.get(0).unwrap());
                let mut url = String::from(*headerItems.get(1).unwrap());
                let mut version = String::from(*headerItems.get(2).unwrap());
            } else {
                //header[headerItems[0]] = headerItems[1]
                let key = String::from(*headerItems.get(0).unwrap());
                let value = String::from(*headerItems.get(1).unwrap());
                header.insert(key, value);
            }
        }
        return Some(Request {
            Method: method,
            URL: url,
            Version: version,
            Header: header,
            Content: content,
            Body: String::from(""),
        });
    }

    pub fn String(&self) -> String {
        let mut str = format!("{} {} {}\r\n", self.Method, self.URL, self.Version);
        for (key, value) in &self.Header {
            //str += format!("{}: {}\r\n", &key, &value);
            str = format!("{}{}: {}\r\n", str, key, value);
        }
        str += "\r\n";
        str += &self.Body[..];
        return str;
    }

    pub fn GetContentLength(&self) -> u32 {
        for (key, value) in &self.Header {
            if key == "Content-Length" {
                return String::from(value).parse::<u32>().unwrap();
            }
        }

        if let  Some(value) = &self.Header.get("Content-Length") {
            return String::from(*value).parse::<u32>().unwrap(); 
        }
        return 0;
    }
}

#[derive(Debug)]
pub struct User {
    pub Username : String,
    pub Password : String,
}

impl  User {
    fn Parse (path : String) -> User {
        match path.find(':') {
            Some(pos) => {
                User {
                    Username : String::from(&path[..pos]),
                    Password : String::from(&path[pos+1..]),
                }
            },
            None => {
                User {
                    Username : path,
                    Password : String::new(),
                }
            },    
        }
    }
}

#[derive(Debug)]
pub struct Url {
    scheme : String, //
    user : User,               //User 包含了所有的认证信息，这里调用 Username和 Password 来获取独立值。
    Host: String,//Host 同时包括主机名和端口信息，如过端口存在的话，使用 strings.Split() 从 Host 中手动提取端口。
    Path : String,//这里我们提出路径和查询片段信息。

    Fragment : String,
    RawQuery : String,//要得到字符串中的 k=v 这种格式的查询参数，可以使用 RawQuery 函数。你也可以将查询参数解析为一个map。已解析的查询参数 map 以查询字符串为键，对应值字符串切片为值，所以如何只想得到一个键对应的第一个值，将索引位置设置为 [0] 就行了。
}

impl Url {
    pub fn parse(url: &str) -> Option<Url>{
        // "postgres://user:pass@host.com:5432/path?k=v#f"

        let mut pos = match  url.find('?'){
            Some(pos) => pos,
            None => 0,
        };

        //参数
        let parameter = if pos > 0 {
            String::from(&url[pos+1..])
        } else {
            String::new()
        };

        let (rawQuery,fragment ) = if parameter.len() > 0 {
            match parameter.find('#') {
                Some(pos) => {
                    (String::from(&parameter[..pos]), String::from(&parameter[pos+1..]) )
                },
                None => {
                    (String::new(), String::new() )
                }
            } 
        }else {
            (String::new(), String::new() )
        };

        // 路径
        let path = if pos > 0 {
            &url[..pos]
        } else {
            &url[..]
        };

        pos = match path.find("://") {
            Some(pos) => { pos},
            None => {0},
        };
        if pos == 0 {
            return None;
        }

        let scheme = path[..pos].to_string();
        let path = &path[pos+3..];

        let pos = match path.find('@') {
            Some(pos) => { pos},
            None => {0},
        };

        // 用户名 密码
        let usr = if pos > 0 {
            path[..pos].to_string()
        }
        else {
            String::new()
        };

        let path = if pos > 0 {
            &path[pos+1..]
        }
        else {
            &path[..]
        };

        let pos = match path.find('/') {
            Some(pos) => { pos},
            None => {0},
        };

        let host = if  pos > 0{
            &path[..pos]
        } else {
            &path[..]
        };

        let path = if  pos > 0{
            &path[pos+1..]
        } else {
            &path[..]
        };


        let usr = if usr.len() > 0 {
            User::Parse(usr)
        } else {
            User {
                Username : String::new(),
                Password : String::new(),
            }
        } ;
        Some(    Url {
                scheme : scheme, //
                user : usr,    //User 包含了所有的认证信息，这里调用 Username和 Password 来获取独立值。
                Host: String::from(host),//Host 同时包括主机名和端口信息，如过端口存在的话，使用 strings.Split() 从 Host 中手动提取端口。
                Path : String::from(path),//这里我们提出路径和查询片段信息。

                Fragment : fragment,
                RawQuery : rawQuery,//要得到字符串中的 k=v 这种格式的查询参数，可以使用 RawQuery 函数。你也可以将查询参数解析为一个map。已解析的查询参数 map 以查询字符串为键，对应值字符串切片为值，所以如何只想得到一个键对应的第一个值，将索引位置设置为 [0] 就行了。
            }
        )
    }

    pub fn hostname(&self) -> String {
        match self.Host.find(':') {
            Some(pos) => { String::from(&self.Host[..pos])},
            None => String::new()
        }

    }
    pub fn port(&self) -> u32 {
        match self.Host.find(':') {
            Some(pos) => { match String::from(&self.Host[pos+1..]).parse::<u32>() {
                Ok(port) => port,
                Err(_) => 0,
            }},
            None => 0
        }

    }
}
