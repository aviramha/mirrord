use std::{collections::HashMap, process::Stdio, time::Duration};

use futures::{stream::StreamExt, SinkExt};
use mirrord_protocol::{ClientMessage, DaemonCodec, GetEnvVarsRequest, DaemonMessage, RemoteResult, tcp::LayerTcp};
use rstest::rstest;
use tokio::{net::TcpListener, process::Command, time::timeout};

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn happy_flow() {
    let mut env = HashMap::new();
    env.insert("RUST_LOG", "warn,mirrord=debug");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    env.insert("MIRRORD_CONNECT_TCP", &addr);
    let dylib_path = test_cdylib::build_current_project();
    env.insert("DYLD_INSERT_LIBRARIES", dylib_path.to_str().unwrap());
    env.insert("LD_PRELOAD", dylib_path.to_str().unwrap());
    let mut server = Command::new("/Library/Frameworks/Python.framework/Versions/3.9/bin/python3")
        .args(vec!["-u", "tests/apps/app_flask.py"])
        .envs(env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    timeout(Duration::from_secs(5), async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut codec = actix_codec::Framed::new(stream, DaemonCodec::new());
        let msg = codec.next().await.unwrap().unwrap();
        if let ClientMessage::GetEnvVarsRequest(request) = msg {
            assert!(request.env_vars_filter.is_empty());
            assert!(request.env_vars_select.len() == 1);
            assert!(request.env_vars_select.contains("*"));
        } else {
            panic!("unexpected request {:?}", msg)
        }
        codec
            .send(DaemonMessage::GetEnvVarsResponse( Ok(HashMap::new())))
            .await
            .unwrap();
        let msg = codec.next().await.unwrap().unwrap();
        if let ClientMessage::Tcp(LayerTcp::PortSubscribe(port)) = msg {
            assert_eq!(port, 80);
        } else {
            panic!("unexpected request {:?}", msg)
        }
    })
    .await
    .unwrap();

    server.kill().await.unwrap();
    let output = server.wait_with_output().await.unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .to_lowercase()
        .contains("error"));
}
