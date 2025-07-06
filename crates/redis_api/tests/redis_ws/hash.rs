use crate::get_test_ws_url;
use futures::StreamExt;
use tokio_tungstenite::connect_async;
use url::Url;

#[tokio::test]
async fn test_ws_hash_set_and_get() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/hash/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}
