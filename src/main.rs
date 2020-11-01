use hmac::{Hmac, Mac, NewMac};
use pyo3::prelude::*;
use pyo3::types::IntoPyDict;
use serde_json::{Map, Value};
use sha2::Sha256;
use std::io::{self, Write};
use std::str;
use zmq;

type HmacSha256 = Hmac<Sha256>;

fn make_channel(context: &zmq::Context, ports: &Value, channel_type: &str) -> zmq::Socket {
    let url = format!("tcp://127.0.0.1:{}", ports[channel_type]);
    let mut channel: zmq::Socket;

    match channel_type {
        "shell" => {
            channel = context.socket(zmq::DEALER).unwrap();
            channel.set_linger(1000).unwrap();
            channel.connect(&url).unwrap();
        }
        "iopub" => {
            channel = context.socket(zmq::SUB).unwrap();
            channel.set_linger(1000).unwrap();
            channel.connect(&url).unwrap();
            channel.set_subscribe(b"").unwrap();
        }
        _ => {
            panic!("Unknown channel type!");
        }
    };
    channel
}

fn start_kernel(py: Python) -> Value {
    let locals = [("jupyterm", py.import("jupyterm").unwrap())].into_py_dict(py);
    let code = "jupyterm.start_kernel()";
    let kernel_info_str: &str = py
        .eval(code, None, Some(&locals))
        .unwrap()
        .extract()
        .unwrap();
    let kernel_info: Value = serde_json::from_str(kernel_info_str).unwrap();
    kernel_info
}

// useful for debugging!
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

struct Session {
    key: Value,
    session_id: String,
}

struct Cutypr {
    context: zmq::Context,
    session: Session,
    ports: Value,
    message_count: i32,
    shell_channel: Option<zmq::Socket>,
    iopub_channel: Option<zmq::Socket>,
}

impl Cutypr {
    fn new(session: Session, ports: Value) -> Cutypr {
        Cutypr {
            context: zmq::Context::new(),
            session: session,
            ports: ports,
            message_count: 1,
            shell_channel: None,
            iopub_channel: None,
        }
    }

    fn initialize_channels(&mut self) {
        self.shell_channel = Some(make_channel(&self.context, &self.ports, "shell"));
        self.iopub_channel = Some(make_channel(&self.context, &self.ports, "iopub"));
    }

    fn make_message(&self, message_type: &str, content: Map<String, Value>) -> Map<String, Value> {
        let mut msg = Map::new();

        let msg_id = format!("{}_{}", self.session.session_id, self.message_count);
        // self.message_count += 1;

        let mut header = Map::new();
        header.insert("msg_id".to_string(), Value::String(msg_id.clone()));
        header.insert(
            "msg_type".to_string(),
            Value::String(message_type.to_string()),
        );
        header.insert("username".to_string(), Value::String("vinayak".to_string()));
        header.insert(
            "session".to_string(),
            Value::String(self.session.session_id.to_string()),
        );

        msg.insert("header".to_string(), Value::Object(header));
        msg.insert("msg_id".to_string(), Value::String(msg_id.clone()));
        msg.insert(
            "msg_type".to_string(),
            Value::String(message_type.to_string()),
        );
        msg.insert("content".to_string(), Value::Object(content));
        msg.insert("metadata".to_string(), Value::Object(Map::new()));
        msg.insert("parent_header".to_string(), Value::Object(Map::new()));

        msg
    }

    fn sign(&self, msg_list: &Vec<String>) -> String {
        let mut signature = HmacSha256::new_varkey(self.session.session_id.as_bytes()).unwrap();
        for message in msg_list {
            signature.update(message.as_bytes());
        }

        let result = signature.finalize().into_bytes();
        hex::encode(result)
    }

    fn serialize(&self, msg: Map<String, Value>) -> Vec<String> {
        let mut msg_list: Vec<String> = Vec::new();
        msg_list.push(msg["header"].to_string());
        msg_list.push(msg["parent_header"].to_string());
        msg_list.push(msg["metadata"].to_string());
        msg_list.push(msg["content"].to_string());

        // sign
        let signature = self.sign(&msg_list);

        msg_list.insert(0, String::from(signature));
        msg_list.insert(0, String::from("<IDS|MSG>"));
        msg_list
    }

    fn execute(&self, code: &String) {
        // make content
        let mut content = Map::new();
        content.insert("code".to_string(), Value::String(code.clone()));
        content.insert("silent".to_string(), Value::Bool(false));
        content.insert("store_history".to_string(), Value::Bool(true));
        content.insert("user_expressions".to_string(), Value::Null);
        content.insert("allow_stdin".to_string(), Value::Bool(true));
        content.insert("stop_on_error".to_string(), Value::Bool(true));

        // make_message(execute_request, content)
        let msg = self.make_message("execute_request", content);

        // serialize
        let msg_list = self.serialize(msg);

        // send_multipart
        self.shell_channel
            .as_ref()
            .unwrap()
            .send_multipart(&msg_list, 0)
            .unwrap();
    }

    // fn deserialize(&self, msg_frames) {}

    fn msg_ready(&self) -> bool {
        self.iopub_channel
            .as_ref()
            .unwrap()
            .poll(zmq::POLLIN, 10)
            .expect("client failed polling")
            > 0
    }

    fn get_msg(&self) -> Map<String, Value> {
        let msg_list = self
            .iopub_channel
            .as_ref()
            .unwrap()
            .recv_multipart(0)
            .unwrap();

        // https://gitlab.com/srwalker101/rust-jupyter-client/-/blob/dev/src/wire.rs#L28
        let delim_idx = msg_list
            .iter()
            .position(|r| String::from_utf8(r.to_vec()).unwrap() == "<IDS|MSG>")
            .unwrap();

        // couldn't move msg_frames into deserialize
        let msg_frames = &msg_list[delim_idx + 2..];
        let header = serde_json::from_str(str::from_utf8(&msg_frames[0]).unwrap()).unwrap();
        let parent_header = serde_json::from_str(str::from_utf8(&msg_frames[1]).unwrap()).unwrap();
        let metadata = serde_json::from_str(str::from_utf8(&msg_frames[2]).unwrap()).unwrap();
        let content = serde_json::from_str(str::from_utf8(&msg_frames[3]).unwrap()).unwrap();

        let mut msg = Map::new();
        msg.insert("header".to_string(), Value::Object(header));
        msg.insert("parent_header".to_string(), Value::Object(parent_header));
        msg.insert("metadata".to_string(), Value::Object(metadata));
        msg.insert("content".to_string(), Value::Object(content));

        msg
    }
}

fn main() {
    let mut kernel_info: Value = serde_json::from_str("{}").unwrap();

    // start the Python kernel
    // TODO: also shut it down
    Python::with_gil(|py| {
        kernel_info = start_kernel(py);
    });

    let session = Session {
        key: kernel_info["key"].clone(),
        session_id: String::from("rust"),
    };

    let mut client = Cutypr::new(session, kernel_info["ports"].clone());
    client.initialize_channels();

    let mut execution_state = "idle";
    let mut execution_count: i32 = 1;
    let mut code = String::new();

    loop {
        code.clear();

        print!("In [{}]: ", execution_count);
        io::stdout().flush().unwrap();

        io::stdin().read_line(&mut code).unwrap();

        if code.trim().is_empty() {
            continue;
        };

        client.execute(&code);
        execution_state = "busy";

        while execution_state != "idle" {
            while client.msg_ready() {
                let msg = client.get_msg();
                let msg_type = msg["header"]["msg_type"].as_str().unwrap();

                match msg_type {
                    "status" => {
                        // couldn't save contents of msg["content"]["execution_state"]
                        // directly into execution_state
                        let _execution_state = msg["content"]["execution_state"].as_str().unwrap();
                        match _execution_state {
                            "starting" => execution_state = "starting",
                            "idle" => execution_state = "idle",
                            "busy" => execution_state = "busy",
                            _ => {
                                panic!("Unknown execution state");
                            }
                        };
                    }
                    "stream" => {
                        let stream_name = msg["content"]["name"].as_str().unwrap();

                        match stream_name {
                            "stdout" => {
                                println!("{}", msg["content"]["text"].to_string());
                            }
                            "stderr" => {
                                eprintln!("{}", msg["content"]["text"].to_string());
                            }
                            _ => println!("Unknown stream name"),
                        };
                    }
                    "execute_input" => {
                        execution_count += 1;
                    }
                    "error" => {
                        println!("error!");
                    }
                    _ => {
                        println!("Unknown message type");
                    }
                };
            }
        }
    }
}
