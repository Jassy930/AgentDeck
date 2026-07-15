use super::*;

impl RuntimeStoreHandle {
    pub async fn mark_started_with_event(
        &self,
        input: StartCommand,
    ) -> Result<StartOutcome, RuntimeStoreError> {
        self.mark_started_with_source(input, StartEventSource::Canonical)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn mark_started_with_legacy_v1_fixture_for_test(
        &self,
        input: StartCommand,
        intent: Vec<u8>,
        event: Vec<u8>,
    ) -> Result<StartOutcome, RuntimeStoreError> {
        validate_maximum(
            intent.len(),
            crate::runtime::model::MAX_EXECUTION_INTENT_BYTES,
        )?;
        validate_maximum(event.len(), crate::runtime::model::MAX_RUNTIME_EVENT_BYTES)?;
        self.mark_started_with_source(input, StartEventSource::LegacyV1Fixture { intent, event })
            .await
    }

    async fn mark_started_with_source(
        &self,
        input: StartCommand,
        event_source: StartEventSource,
    ) -> Result<StartOutcome, RuntimeStoreError> {
        validate_nonempty_maximum(&input.execution_nonce, MAX_EXECUTION_NONCE_BYTES)?;
        let charge = memory_charge(
            size_of::<NormalCommand>(),
            &[
                input.execution_nonce.capacity(),
                MAX_CRITICAL_COMMAND_RECORD_BYTES,
                event_source.retained_capacity(),
            ],
        )?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::StartCommand {
                input,
                event_source,
                reply,
            },
        )
        .await?
    }
}
