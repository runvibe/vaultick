use std::io::Cursor;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::HeaderValue;
use axum::routing::get;
use futures_util::StreamExt;
use vaultick_request::{
    RequestSpec, ResolvedRequest, execute_async, execute_blocking, stream_redacted_output,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_execution_and_redaction_work_for_streaming_bodies() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/events",
                get(|| async move {
                    let stream = async_stream::stream! {
                        yield Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"data: super-"));
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        yield Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"secret-token\n\n"));
                    };

                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            HeaderValue::from_static("text/event-stream"),
                        )],
                        Body::from_stream(stream),
                    )
                }),
            ),
        )
        .await
        .unwrap();
    });

    let request = ResolvedRequest::from_spec(
        &RequestSpec {
            url: format!("http://{addr}/events"),
            method: Some("GET".to_string()),
            headers: Vec::new(),
            body: None,
            timeout: None,
        },
        |_| unreachable!(),
    )
    .unwrap();

    let async_response = execute_async(&request).await.unwrap();
    let mut chunks = Vec::new();
    let mut stream = async_response.into_redacted_stream(&["super-secret-token".to_string()]);
    while let Some(chunk) = stream.next().await {
        chunks.extend(chunk.unwrap());
    }
    assert_eq!(String::from_utf8(chunks).unwrap(), "data: [REDACTED]\n\n");

    let request_for_blocking = request.clone();
    let output = tokio::task::spawn_blocking(move || {
        let blocking_response = execute_blocking(&request_for_blocking).unwrap();
        let mut output = Vec::new();
        blocking_response
            .copy_redacted_to_writer(&mut output, &["super-secret-token".to_string()])
            .unwrap();
        output
    })
    .await
    .unwrap();
    assert_eq!(String::from_utf8(output).unwrap(), "data: [REDACTED]\n\n");

    let mut reader_output = Vec::new();
    stream_redacted_output(
        Cursor::new(b"hello super-secret-token world".to_vec()),
        &mut reader_output,
        &["super-secret-token".to_string()],
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(reader_output).unwrap(),
        "hello [REDACTED] world"
    );
}
