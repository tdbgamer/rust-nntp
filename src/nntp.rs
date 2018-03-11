#![crate_name = "nntp"]
#![crate_type = "lib"]
#[macro_use]
extern crate failure;
extern crate openssl;

//#![feature(collections)]

use std::string::String;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::net::{ToSocketAddrs, SocketAddr};
use std::vec::Vec;
use std::collections::HashMap;
use std::str::FromStr;
use std::ops::Deref;

use failure::Error;
use openssl::ssl::{SslMethod, SslConnector, SslStream};

pub type NNTPResult<T> = Result<T, Error>;

struct AllowedCodes(Vec<isize>);

impl Deref for AllowedCodes {
    type Target = Vec<isize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<isize> for AllowedCodes {
    fn from(num: isize) -> Self {
        AllowedCodes(vec![num])
    }
}

impl From<Vec<isize>> for AllowedCodes {
    fn from(nums: Vec<isize>) -> Self {
        AllowedCodes(nums)
    }
}

enum InternalStream {
    Normal(TcpStream),
    Ssl(SslStream<TcpStream>),
}

impl InternalStream {
    pub fn connect(host: &str, addr: &SocketAddr, timeout: u64) -> NNTPResult<Self> {
        use std::time::Duration;
        let connector = SslConnector::builder(SslMethod::tls())?.build();
        let tcp_stream = TcpStream::connect_timeout(&addr, Duration::from_secs(timeout))?;
        match connector.connect(&host, tcp_stream) {
            Ok(stream) => Ok(InternalStream::Ssl(stream)),
            Err(_) => Ok(InternalStream::Normal(TcpStream::connect_timeout(&addr, Duration::from_secs(timeout))?))
        }
    }
}

impl Read for InternalStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            InternalStream::Normal(ref mut s) => s.read(buf),
            InternalStream::Ssl(ref mut s) => s.read(buf)
        }
    }
}

impl Write for InternalStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            InternalStream::Normal(ref mut s) => s.write(buf),
            InternalStream::Ssl(ref mut s) => s.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            InternalStream::Normal(ref mut s) => s.flush(),
            InternalStream::Ssl(ref mut s) => s.flush()
        }
    }
}

/// Stream to be used for interfacing with a NNTP server.
pub struct NNTPStream {
    stream: InternalStream,
}

pub struct Article {
    pub headers: HashMap<String, String>,
    pub body: Vec<String>,
}

impl Article {
    pub fn new_article(lines: Vec<String>) -> Article {
        let mut headers = HashMap::new();
        let mut body = Vec::new();
        let mut parsing_headers = true;

        for i in lines.iter() {
            if i == &format!("\r\n") {
                parsing_headers = false;
                continue;
            }
            if parsing_headers {
                let mut header = i.splitn(2, ':');
                let chars_to_trim: &[char] = &['\r', '\n'];
                let key = format!("{}", header.nth(0).unwrap().trim_matches(chars_to_trim));
                let value = format!("{}", header.nth(0).unwrap().trim_matches(chars_to_trim));
                headers.insert(key, value);
            } else {
                body.push(i.clone());
            }
        }
        Article { headers: headers, body: body }
    }
}

pub struct NewsGroup {
    pub name: String,
    pub high: isize,
    pub low: isize,
    pub status: String,
}

impl NewsGroup {
    pub fn new_news_group(group: &str) -> NewsGroup {
        let chars_to_trim: &[char] = &['\r', '\n', ' '];
        let trimmed_group = group.trim_matches(chars_to_trim);
        let split_group: Vec<&str> = trimmed_group.split(' ').collect();
        NewsGroup { name: format!("{}", split_group[0]), high: FromStr::from_str(split_group[1]).unwrap(), low: FromStr::from_str(split_group[2]).unwrap(), status: format!("{}", split_group[3]) }
    }
}

fn open_socket(addr: (&str, u16)) -> NNTPResult<InternalStream> {
    let mut last_error = format_err!("Every socket failed to connect");
    for socket_addr in addr.to_socket_addrs()? {
        match InternalStream::connect(&addr.0, &socket_addr, 10) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_error = e;
            }
        };
    }
    Err(last_error)
}

impl NNTPStream {
    /// Creates an NNTP Stream.
    pub fn connect(addr: (&str, u16)) -> NNTPResult<NNTPStream> {
        let mut socket = NNTPStream {
            stream: open_socket(addr)?
        };
        socket.read_response(200)?;
        Ok(socket)
    }

    pub fn login<T>(&mut self, username: T, password: T) -> NNTPResult<()>
        where T: Into<String> {
        self.stream.write_fmt(format_args!("AUTHINFO USER {}\r\n", username.into()))?;
        self.read_response(381)?;
        self.stream.write_fmt(format_args!("AUTHINFO PASS {}\r\n", password.into()))?;
        self.read_response(vec![250, 281])?;
        Ok(())
    }

    /// The article indicated by the current article number in the currently selected newsgroup is selected.
    pub fn article(&mut self) -> NNTPResult<Article> {
        self.retrieve_article(&format!("ARTICLE\r\n"))
    }

    /// The article indicated by the article id is selected.
    pub fn article_by_id(&mut self, article_id: &str) -> NNTPResult<Article> {
        self.retrieve_article(&format!("ARTICLE {}\r\n", article_id))
    }

    /// The article indicated by the article number in the currently selected newsgroup is selected.
    pub fn article_by_number(&mut self, article_number: isize) -> NNTPResult<Article> {
        self.retrieve_article(&format!("ARTICLE {}\r\n", article_number))
    }

    fn retrieve_article(&mut self, article_command: &str) -> NNTPResult<Article> {
        self.stream.write_fmt(format_args!("{}", article_command))?;
        self.read_response(220)?;
        let lines = self.read_multiline_response()?;
        Ok(Article::new_article(lines))
    }

    /// Retrieves the body of the current article number in the currently selected newsgroup.
    pub fn body(&mut self) -> NNTPResult<Vec<String>> {
        self.retrieve_body(&format!("BODY\r\n"))
    }

    /// Retrieves the body of the article id as bytes.
    pub fn body_by_id_bytes(&mut self, article_id: &str) {
        self.retrieve_body_bytes(&format!("BODY {}\r\n", article_id))
    }

    /// Retrieves the body of the article id.
    pub fn body_by_id(&mut self, article_id: &str) -> NNTPResult<Vec<String>> {
        self.retrieve_body(&format!("BODY {}\r\n", article_id))
    }

    /// Retrieves the body of the article number in the currently selected newsgroup.
    pub fn body_by_number(&mut self, article_number: isize) -> NNTPResult<Vec<String>> {
        self.retrieve_body(&format!("BODY {}\r\n", article_number))
    }

    fn retrieve_body_bytes(&mut self, body_command: &str) -> NNTPResult<Vec<String>> {
        self.stream.write_fmt(format_args!("{}", body_command))?;
        self.read_response(222)?;
        self.read_bytes()
    }

    fn retrieve_body(&mut self, body_command: &str) -> NNTPResult<Vec<String>> {
        self.stream.write_fmt(format_args!("{}", body_command))?;
        self.read_response(222)?;
        self.read_multiline_response()
    }

    /// Gives the list of capabilities that the server has.
    pub fn capabilities(&mut self) -> NNTPResult<Vec<String>> {
        let capabilities_command = format!("CAPABILITIES\r\n");
        self.stream.write_fmt(format_args!("{}", capabilities_command))?;
        self.read_response(101)?;
        self.read_multiline_response()
    }

    /// Retrieves the date as the server sees the date.
    pub fn date(&mut self) -> NNTPResult<String> {
        let date_command = format!("DATE\r\n");
        self.stream.write_fmt(format_args!("{}", date_command))?;
        let (_, message) = self.read_response(111)?;
        Ok(message)
    }

    /// Retrieves the headers of the current article number in the currently selected newsgroup.
    pub fn head(&mut self) -> NNTPResult<Vec<String>> {
        self.retrieve_head(&format!("HEAD\r\n"))
    }

    /// Retrieves the headers of the article id.
    pub fn head_by_id(&mut self, article_id: &str) -> NNTPResult<Vec<String>> {
        self.retrieve_head(&format!("HEAD {}\r\n", article_id))
    }

    /// Retrieves the headers of the article number in the currently selected newsgroup.
    pub fn head_by_number(&mut self, article_number: isize) -> NNTPResult<Vec<String>> {
        self.retrieve_head(&format!("HEAD {}\r\n", article_number))
    }

    fn retrieve_head(&mut self, head_command: &str) -> NNTPResult<Vec<String>> {
        self.stream.write_fmt(format_args!("{}", head_command))?;
        self.read_response(221)?;
        self.read_multiline_response()
    }

    /// Moves the currently selected article number back one
    pub fn last(&mut self) -> NNTPResult<String> {
        let last_command = format!("LAST\r\n");
        self.stream.write_fmt(format_args!("{}", last_command))?;
        let (_, message) = self.read_response(223)?;
        Ok(message)
    }

    /// Lists all of the newgroups on the server.
    pub fn list(&mut self) -> NNTPResult<Vec<NewsGroup>> {
        let list_command = format!("LIST\r\n");

        self.stream.write_fmt(format_args!("{}", list_command))?;
        self.read_response(215)?;

        let lines = self.read_multiline_response()?;
        let lines: Vec<NewsGroup> = lines.iter().map(|ref mut x| NewsGroup::new_news_group((*x))).collect();
        Ok(lines)
    }

    /// Selects a newsgroup
    pub fn group(&mut self, group: &str) -> NNTPResult<()> {
        let group_command = format!("GROUP {}\r\n", group);
        self.stream.write_fmt(format_args!("{}", group_command))?;
        self.read_response(211)?;
        Ok(())
    }

    /// Show the help command given on the server.
    pub fn help(&mut self) -> NNTPResult<Vec<String>> {
        let help_command = format!("HELP\r\n");
        self.stream.write_fmt(format_args!("{}", help_command))?;
        self.read_response(100)?;
        self.read_multiline_response()
    }

    /// Quits the current session.
    pub fn quit(&mut self) -> NNTPResult<()> {
        let quit_command = format!("QUIT\r\n");
        self.stream.write_fmt(format_args!("{}", quit_command))?;
        self.read_response(205)?;
        Ok(())
    }

    /// Retrieves a list of newsgroups since the date and time given.
    pub fn newgroups(&mut self, date: &str, time: &str, use_gmt: bool) -> NNTPResult<Vec<String>> {
        let newgroups_command = match use_gmt {
            true => format!("NEWSGROUP {} {} GMT\r\n", date, time),
            false => format!("NEWSGROUP {} {}\r\n", date, time)
        };
        self.stream.write_fmt(format_args!("{}", newgroups_command))?;
        self.read_response(231)?;
        self.read_multiline_response()
    }

    /// Retrieves a list of new news since the date and time given.
    pub fn newnews(&mut self, wildmat: &str, date: &str, time: &str, use_gmt: bool) -> NNTPResult<Vec<String>> {
        let newnews_command = match use_gmt {
            true => format!("NEWNEWS {} {} {} GMT\r\n", wildmat, date, time),
            false => format!("NEWNEWS {} {} {}\r\n", wildmat, date, time)
        };
        self.stream.write_fmt(format_args!("{}", newnews_command))?;
        self.read_response(230)?;
        self.read_multiline_response()
    }

    /// Moves the currently selected article number forward one
    pub fn next(&mut self) -> NNTPResult<String> {
        let next_command = format!("NEXT\r\n");
        self.stream.write_fmt(format_args!("{}", next_command))?;
        let (_, message) = self.read_response(223)?;
        Ok(message)
    }

    /// Posts a message to the NNTP server.
    pub fn post(&mut self, message: &str) -> NNTPResult<()> {
        if !self.is_valid_message(message) {
            bail!("Invalid message format. Message must end with \"\r\n.\r\n\"");
        }
        let post_command = format!("POST\r\n");
        self.stream.write_fmt(format_args!("{}", post_command))?;
        let (_, message) = self.read_response(340)?;
        self.stream.write_fmt(format_args!("{}", message))?;
        self.read_response(240)?;
        Ok(())
    }

    /// Gets information about the current article.
    pub fn stat(&mut self) -> NNTPResult<String> {
        self.retrieve_stat(&format!("STAT\r\n"))
    }

    /// Gets the information about the article id.
    pub fn stat_by_id(&mut self, article_id: &str) -> NNTPResult<String> {
        self.retrieve_stat(&format!("STAT {}\r\n", article_id))
    }

    /// Gets the information about the article number.
    pub fn stat_by_number(&mut self, article_number: isize) -> NNTPResult<String> {
        self.retrieve_stat(&format!("STAT {}\r\n", article_number))
    }

    fn retrieve_stat(&mut self, stat_command: &str) -> NNTPResult<String> {
        self.stream.write_fmt(format_args!("{}", stat_command))?;
        let (_, message) = self.read_response(223)?;
        Ok(message)
    }

    fn is_valid_message(&self, message: &str) -> bool {
        //Carriage return
        let cr = 0x0d;
        //Line Feed
        let lf = 0x0a;
        //Dot
        let dot = 0x2e;
        let message_string = message.to_string();
        let message_bytes = message_string.as_bytes();
        let length = message_string.len();

        return length >= 5 && (message_bytes[length - 1] == lf && message_bytes[length - 2] == cr &&
            message_bytes[length - 3] == dot && message_bytes[length - 4] == lf && message_bytes[length - 5] == cr);
    }

    //Retrieve single line response
    fn read_response<T>(&mut self, expected_code: T) -> NNTPResult<(isize, String)>
        where T: Into<AllowedCodes> {
        let cr = b'\r';
        let lf = b'\n';
        let mut line_buffer: Vec<u8> = Vec::new();

        while line_buffer.len() < 2 || (line_buffer[line_buffer.len() - 1] != lf && line_buffer[line_buffer.len() - 2] != cr) {
            let byte_buffer: &mut [u8] = &mut [0];
            self.stream.read(byte_buffer)?;
            line_buffer.push(byte_buffer[0]);
        }

        let response = String::from_utf8(line_buffer).unwrap();
        let chars_to_trim: &[char] = &['\r', '\n'];
        let trimmed_response = response.trim_matches(chars_to_trim);
        let trimmed_response_vec: Vec<char> = trimmed_response.chars().collect();
        if trimmed_response_vec.len() < 5 || trimmed_response_vec[3] != ' ' {
            bail!("Invalid response");
        }

        let v: Vec<&str> = trimmed_response.splitn(2, ' ').collect();
        let code: isize = FromStr::from_str(v[0]).unwrap();
        let message = v[1];
        if !expected_code.into().contains(&code) {
            bail!("Invalid response code: {}", code);
        }
        Ok((code, message.to_string()))
    }

    fn read_bytes(&mut self) -> NNTPResult<Vec<u8>> {
        let mut buffer = [0u8; 2048];
        let mut bytes = Vec::new();
        let mut bytes_read = self.stream.read(&mut buffer)?;
        while bytes_read == buffer.len() {
            bytes.append(&mut buffer[..].to_owned());
            bytes_read = self.stream.read(&mut buffer)?;
        }
        bytes.append(&mut buffer[..bytes_read].to_owned());
        if bytes[bytes.len() - 1] == b'.' {
            bytes.pop().unwrap();
        }
        Ok(bytes)
    }

    fn read_multiline_response(&mut self) -> NNTPResult<Vec<String>> {
        let mut response: Vec<String> = Vec::new();
        let cr = b'\r';
        let lf = b'\n';
        let mut line_buffer: Vec<u8> = Vec::new();
        let mut complete = false;

        while !complete {
            while line_buffer.len() < 2 || (line_buffer[line_buffer.len() - 1] != lf && line_buffer[line_buffer.len() - 2] != cr) {
                let byte_buffer: &mut [u8] = &mut [0];
                match self.stream.read(byte_buffer) {
                    Ok(_) => {}
                    Err(_) => println!("Error Reading!"),
                }
                line_buffer.push(byte_buffer[0]);
            }

            match String::from_utf8(line_buffer.clone()) {
                Ok(res) => {
                    if res == format!(".\r\n") {
                        complete = true;
                    } else {
                        response.push(res.clone());
                        line_buffer = Vec::new();
                    }
                }
                Err(_) => bail!("Error Reading")
            }
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect() {
        let nntp_stream = NNTPStream::connect(("nntp.aioe.org", 119));
        assert!(nntp_stream.is_ok());
        let mut nntp_stream = nntp_stream.unwrap();

        let capabilities = nntp_stream.capabilities();
        assert!(capabilities.is_ok());
    }
}