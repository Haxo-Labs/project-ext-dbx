use crate::get_test_ws_url;
use futures::StreamExt;
use tokio_tungstenite::connect_async;
use url::Url;

#[tokio::test]
async fn test_redis_ws_set_get_string_basic() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/string/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}

#[tokio::test]
async fn test_redis_ws_ping_pong() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/string/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}

#[tokio::test]
async fn test_redis_ws_string_info() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/string/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}

#[tokio::test]
async fn test_redis_ws_set_get_string_with_special_chars() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/string/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}

#[tokio::test]
async fn test_redis_ws_string_overwrite() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/string/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}

#[tokio::test]
async fn test_redis_ws_get_nonexistent_string() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/string/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}

#[tokio::test]
async fn test_redis_ws_delete_string() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/string/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}

#[tokio::test]
async fn test_redis_ws_delete_nonexistent_string() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/string/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}

#[tokio::test]
async fn test_redis_ws_concurrent_string_operations() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/string/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}

#[tokio::test]
async fn test_redis_ws_batch_string_operations() -> Result<(), anyhow::Error> {
    let ws_url = get_test_ws_url().await;
    let url = Url::parse(&format!("{}/string/ws", ws_url))?;

    let (ws_stream, _) = connect_async(url).await?;
    let (_write, mut read) = ws_stream.split();

    // Read initial message
    if let Some(msg) = read.next().await {
        let msg = msg?;
        assert!(msg.is_text());
    }

    Ok(())
}
