use crate::get_test_ws_url;
use futures::StreamExt;
use tokio_tungstenite::connect_async;
use url::Url;

#[tokio::test]
async fn test_admin_ws_ping() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/admin/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read ping message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        if msg.is_text() {
            let text = msg.to_text()?;
            assert!(text.contains("ping"));
        }
    }

    Ok(())
}
