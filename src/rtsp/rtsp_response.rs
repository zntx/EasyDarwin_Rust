use std::fmt;
use std::collections::HashMap;

use super::rtsp_requset::RTSP_VERSION;

pub struct Response  {
	pub Version    :String,
	pub StatusCode :i32,
	pub Status     :String,
	pub Header     : HashMap<String, String>,//map[string]interface{}
	pub Body       :String,
}

impl Response {
	pub fn  NewResponse(statusCode :i32, status:String, cSeq:String, sid:String, body : String) ->Response {

		let mut book_reviews = HashMap::new();

		// Review some books.
		book_reviews.insert(
			"Adventures of Huckleberry Finn".to_string(),
			"My favorite book.".to_string(),
		);
		let mut res = Response{
			Version:    RTSP_VERSION.to_string(),
			StatusCode: statusCode,
			Status:     status,
			Header:     HashMap::new(),//map[string]interface{}{"CSeq": cSeq, "Session": sid},
			Body:       body,
		};
		res.Header.insert("CSeq".to_string(),  cSeq);
		res.Header.insert("Session".to_string(), sid);
		let len = body.len();
		if len > 0 {
			res.Header.insert("Content-Length".to_string(), format!("{}", len));
		}
		return res
	}

	pub fn SetBody(&mut self , body :String) {
		let len = body.len();
		self.Body = body;
		if len > 0 {
			self.Header.insert("Content-Length".to_string(), format!("{}", len));
			//r.Header["Content-Length"] = strconv.Itoa(len)
		}
	}
}
/* *
impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}\r\n", self.Version, self.StatusCode, self.Status);
		for (key, value) in &self.Header {
			let key = String::from(key);
			let keyvalue = String::from(value);
			write!("{}{}", key, value);
		}
		write!(f, "\r\n")
    }
}*/