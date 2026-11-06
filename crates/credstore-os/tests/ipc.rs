use credstore_os::{
    EndpointAccess, EndpointKind, Ipc, IpcListener, IpcStream, Paths, Platform, PlatformPaths,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn platform(tag: &str) -> Platform {
    let home = std::env::temp_dir().join(format!(
        "credstore-ipc-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    Platform::with_paths(PlatformPaths::dev_with_home(home))
}

#[tokio::test(flavor = "multi_thread")]
async fn same_user_round_trip_and_identity() {
    let p = platform("rt");
    let ep = p.endpoint(EndpointKind::Agent);
    let mut listener = p.bind(&ep, &EndpointAccess::SameUser).await.unwrap();

    let server = tokio::spawn(async move {
        let mut s = listener.accept().await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        // Identity is checked after the first read (required on Windows).
        let peer = s.authorize().unwrap();
        s.write_all(b"world").await.unwrap();
        (buf, peer)
    });

    let mut c = p.connect(&ep).await.unwrap();
    c.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"world");

    let (got, peer) = server.await.unwrap();
    assert_eq!(&got, b"hello");
    assert_eq!(
        peer.pid,
        Some(std::process::id()),
        "peer pid is this process"
    );
    assert!(peer.uid.is_some() || peer.sid.is_some(), "{peer:?}");
    #[cfg(windows)]
    assert!(peer.sid.as_deref().unwrap().starts_with("S-1-"));
}

#[tokio::test(flavor = "multi_thread")]
async fn second_daemon_on_same_endpoint_is_refused() {
    let p = platform("dup");
    let ep = p.endpoint(EndpointKind::Approver);
    let _first = p.bind(&ep, &EndpointAccess::SameUser).await.unwrap();
    let err = p
        .bind(&ep, &EndpointAccess::SameUser)
        .await
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("already"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_without_daemon_says_not_running() {
    let p = platform("none");
    let err = p
        .connect(&p.endpoint(EndpointKind::Agent))
        .await
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("not running"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn many_sequential_clients() {
    let p = platform("many");
    let ep = p.endpoint(EndpointKind::Agent);
    let mut listener = p.bind(&ep, &EndpointAccess::SameUser).await.unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..5 {
            let mut s = listener.accept().await.unwrap();
            let mut b = [0u8; 1];
            s.read_exact(&mut b).await.unwrap();
            s.authorize().unwrap();
            s.write_all(&b).await.unwrap();
        }
    });
    for i in 0..5u8 {
        let mut c = p.connect(&ep).await.unwrap();
        c.write_all(&[i]).await.unwrap();
        let mut b = [0u8; 1];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(b[0], i);
    }
    server.await.unwrap();
}
