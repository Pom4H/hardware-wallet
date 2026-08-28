use super::*;

#[test]
fn create_requires_backup_verification_before_pin() {
    let setup = SetupId(10);
    let state = State::default();

    let transition = update(
        state,
        Event::StartCreate {
            id: setup,
            passphrase: PassphraseMode::Disabled,
        },
    );
    assert_eq!(transition.effect, Effect::GenerateKeyMaterial(setup));

    let transition = update(transition.state, Event::KeyMaterialReady(setup));
    assert_eq!(transition.effect, Effect::ShowBackup(setup));

    let transition = update(transition.state, Event::BackupShown(setup));
    assert_eq!(transition.effect, Effect::ChallengeBackup(setup));

    let transition = update(transition.state, Event::BackupVerified(setup));
    assert_eq!(transition.effect, Effect::ConfigurePin(setup));
}

#[test]
fn recovery_skips_new_backup_and_configures_pin() {
    let setup = SetupId(11);
    let state = State::default();

    let transition = update(
        state,
        Event::StartRecovery {
            id: setup,
            format: RecoveryFormat::Mnemonic,
            passphrase: PassphraseMode::Optional,
        },
    );
    assert_eq!(
        transition.effect,
        Effect::CaptureRecoveryMaterial {
            id: setup,
            format: RecoveryFormat::Mnemonic,
        }
    );

    let transition = update(transition.state, Event::RecoveryMaterialCaptured(setup));
    assert_eq!(transition.effect, Effect::DeriveRecoveredKeyMaterial(setup));

    let transition = update(transition.state, Event::KeyMaterialReady(setup));
    assert_eq!(transition.effect, Effect::ConfigurePin(setup));
}
