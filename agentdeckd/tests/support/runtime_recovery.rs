//! Integration-test-only aggregate helper.
//!
//! Production RuntimeCore must consume each `RecoveryPage` immediately and must never collect the
//! whole database. Existing P3.2 assertions use this helper only to keep their focused fixtures
//! compact while the production API remains strictly paged.

use agentdeckd::runtime::store::{RecoveryState, RuntimeStoreError, RuntimeStoreHandle};

pub async fn load_recovery_state(
    store: &RuntimeStoreHandle,
) -> Result<RecoveryState, RuntimeStoreError> {
    let mut cursor = store.begin_recovery_scan().await?;
    let mut conversations = Vec::new();
    let mut accepted = Vec::new();
    let mut started = Vec::new();
    let completion = loop {
        let page = store.load_recovery_page(cursor).await?;
        if let Some(record) = page.conversation {
            conversations.push(record.conversation);
            accepted.extend(record.accepted);
            if let Some(record) = record.started {
                started.push(record);
            }
        }
        match (page.next_cursor, page.completion) {
            (Some(next), None) => cursor = next,
            (None, Some(completion)) => break completion,
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    };
    store.finish_recovery_scan(completion).await?;
    Ok(RecoveryState {
        conversations,
        accepted,
        started,
    })
}
