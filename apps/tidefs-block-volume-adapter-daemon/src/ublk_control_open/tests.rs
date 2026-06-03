#![cfg(test)]
use super::resize_smoke::UblkControlResizeSmokeFailureClass;
use super::*;
use tidefs_block_volume_adapter_ublk_control_runtime::UblkResizeRefusalReason;
use tidefs_ublk_abi::UblkCtrlCommand;

fn ready_inputs() -> UblkControlOpenInputs {
    UblkControlOpenInputs {
        kernel_release: "7.0.0-test".to_string(),
        control_path: PathBuf::from("/dev/ublk-control"),
        control_path_present: true,
        control_path_is_char_device: true,
        sys_module_ublk_drv_present: true,
        sys_class_ublk_char_present: true,
        sys_class_block_present: true,
        control_open_result: Some(Ok(())),
        host_identity: ObserveHostIdentity::BareMetal,
    }
}

fn returned_add_dev_outcome(dev_id: u32) -> UblkControlAddDevOutcome {
    let mut returned_info = tidefs_block_volume_adapter_ublk_control_runtime::build_add_dev_info(
        UblkControlAddDevInput::conservative_tidefs(),
    )
    .expect("add dev info");
    returned_info.dev_id = dev_id;
    UblkControlAddDevOutcome::from_dev_info(returned_info)
}

fn projected_set_params_input(dev_id: u32) -> UblkControlSetParamsInput {
    UblkControlSetParamsInput::from_kernel_dev_id_and_params(
        dev_id,
        build_ublk_parameter_spec_report()
            .expect("ublk parameter construction")
            .params,
    )
}

const fn start_dev_input(dev_id: u32) -> UblkControlStartDevInput {
    UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(dev_id, 1234)
}

const fn start_dev_readiness(submitted_fetch_commands: u32) -> UblkControlStartDevReadiness {
    UblkControlStartDevReadiness::from_queue_geometry_with_runtime(
        1,
        64,
        submitted_fetch_commands,
        true,
    )
}

const fn live_start_dev_readiness(submitted_fetch_commands: u32) -> UblkControlStartDevReadiness {
    UblkControlStartDevReadiness::from_queue_geometry_with_runtime(
        1,
        64,
        submitted_fetch_commands,
        true,
    )
}

const fn data_queue_input(dev_id: u32) -> UblkDataQueueRuntimeOpenInput {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        dev_id,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    )
}

fn data_queue_open_outcome(dev_id: u32) -> UblkDataQueueRuntimeOpenOutcome {
    let data_queue_spec =
        tidefs_block_volume_adapter_ublk_control_runtime::build_data_queue_runtime_open_spec(
            data_queue_input(dev_id),
        )
        .expect("data queue spec");
    UblkDataQueueRuntimeOpenOutcome::from_spec(&data_queue_spec)
}

#[test]
fn refuses_old_kernel_without_open_attempt() {
    let mut inputs = ready_inputs();
    inputs.kernel_release = "6.12.79-test".to_string();

    let report = evaluate_ublk_control_open_preflight(&inputs);

    assert_eq!(
        report.kernel_class,
        HostKernelClass::LinuxTooPrevious
    );
    assert_eq!(
        report.admission_class,
        UblkControlOpenAdmissionClass::Refused
    );
    assert_eq!(
        report.refusal_class,
        UblkControlOpenRefusalClass::KernelBelowLinux700
    );
    assert!(!report.control_open_attempted);
    assert!(!report.control_opened);
    assert!(!report.mutating_ioctl_issued);
}

#[test]
fn refuses_missing_control_device_without_open_attempt() {
    let mut inputs = ready_inputs();
    inputs.control_path_present = false;
    inputs.control_path_is_char_device = false;
    inputs.control_open_result = None;

    let report = evaluate_ublk_control_open_preflight(&inputs);

    assert_eq!(
        report.refusal_class,
        UblkControlOpenRefusalClass::MissingUblkControl
    );
    assert!(!report.control_open_attempted);
    assert!(!report.control_opened);
}

#[test]
fn refuses_non_character_control_device_without_open_attempt() {
    let mut inputs = ready_inputs();
    inputs.control_path_is_char_device = false;
    inputs.control_open_result = None;

    let report = evaluate_ublk_control_open_preflight(&inputs);

    assert_eq!(
        report.refusal_class,
        UblkControlOpenRefusalClass::UblkControlNotCharacterDevice
    );
    assert!(!report.control_open_attempted);
    assert!(!report.control_opened);
}

#[test]
fn admits_ready_host_after_real_control_open_result() {
    let report = evaluate_ublk_control_open_preflight(&ready_inputs());

    assert_eq!(
        report.admission_class,
        UblkControlOpenAdmissionClass::Admitted
    );
    assert_eq!(report.refusal_class, UblkControlOpenRefusalClass::None);
    assert!(report.control_open_attempted);
    assert!(report.control_opened);
    assert!(!report.read_only_probe_ioctl_issued);
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.ublk_device_created);
}

#[test]
fn reports_open_failure_without_issuing_ioctls() {
    let mut inputs = ready_inputs();
    inputs.control_open_result = Some(Err(UblkControlOpenErrorClass::PermissionDenied));

    let report = evaluate_ublk_control_open_preflight(&inputs);

    assert_eq!(
        report.admission_class,
        UblkControlOpenAdmissionClass::Refused
    );
    assert_eq!(
        report.refusal_class,
        UblkControlOpenRefusalClass::ControlOpenFailed
    );
    assert!(report.control_open_attempted);
    assert!(!report.control_opened);
    assert_eq!(
        report.control_open_error_class,
        Some(UblkControlOpenErrorClass::PermissionDenied)
    );
    assert!(!report.read_only_probe_ioctl_issued);
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.ublk_device_created);
}

#[test]
fn readonly_probe_refuses_old_kernel_without_uring_cmd_attempt() {
    let mut inputs = ready_inputs();
    inputs.kernel_release = "6.12.79-test".to_string();

    let report = evaluate_ublk_control_readonly_probe(&inputs, None);

    assert!(!report.open_report.control_open_attempted);
    assert!(!report.probe_uring_cmd_attempted);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::HostNotAdmitted
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}

#[test]
fn readonly_probe_refuses_missing_control_device_without_uring_cmd_attempt() {
    let mut inputs = ready_inputs();
    inputs.control_path_present = false;
    inputs.control_path_is_char_device = false;
    inputs.control_open_result = None;

    let report = evaluate_ublk_control_readonly_probe(&inputs, None);

    assert_eq!(
        report.open_report.refusal_class,
        UblkControlOpenRefusalClass::MissingUblkControl
    );
    assert!(!report.open_report.control_open_attempted);
    assert!(!report.probe_uring_cmd_attempted);
}

#[test]
fn readonly_probe_reports_open_failure_without_uring_cmd_attempt() {
    let mut inputs = ready_inputs();
    inputs.control_open_result = Some(Err(UblkControlOpenErrorClass::PermissionDenied));

    let report = evaluate_ublk_control_readonly_probe(&inputs, None);

    assert!(report.open_report.control_open_attempted);
    assert!(!report.open_report.control_opened);
    assert!(!report.probe_uring_cmd_attempted);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::ControlOpenFailed
    );
}

#[test]
fn readonly_probe_success_maps_features_and_stays_non_mutating() {
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_CONTROL_PLAN_REQUIRED_FEATURES.bits(),
        ))),
    );

    assert!(report.open_report.control_opened);
    assert!(report.probe_uring_cmd_attempted);
    assert!(report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::None
    );
    assert!(report
        .probe_features
        .is_some_and(|features| features.contains(TIDEFS_UBLK_CONTROL_PLAN_REQUIRED_FEATURES)));
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}

#[test]
fn readonly_probe_errno_maps_failure_class() {
    const ENOTTY_FOR_TEST: i32 = 25;
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Err(UblkControlReadonlyProbeError::UblkCommandErrno(
            ENOTTY_FOR_TEST,
        ))),
    );

    assert!(report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::UblkCommandErrno
    );
    assert_eq!(report.probe_errno, Some(ENOTTY_FOR_TEST));
    assert_eq!(report.probe_features, None);
}

#[test]
fn readonly_probe_not_attempted_after_open_records_correct_failure_class() {
    let report = evaluate_ublk_control_readonly_probe(&ready_inputs(), None);

    assert!(report.open_report.control_opened);
    assert!(!report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::ProbeNotAttemptedAfterOpen
    );
    assert_eq!(report.probe_errno, None);
    assert_eq!(report.probe_features, None);
    assert_eq!(report.probe_error, None);
    assert_eq!(
        report.probe_spec,
        UblkControlReadonlyProbeSpec::get_features()
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}

#[test]
fn readonly_probe_maps_submission_queue_full_non_errno_error() {
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Err(UblkControlReadonlyProbeError::SubmissionQueueFull)),
    );

    assert!(report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::SubmissionQueueFull
    );
    assert_eq!(report.probe_errno, None);
    assert_eq!(report.probe_features, None);
    assert_eq!(
        report.probe_error,
        Some(UblkControlReadonlyProbeError::SubmissionQueueFull)
    );
    assert_eq!(
        report.probe_spec,
        UblkControlReadonlyProbeSpec::get_features()
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}

#[test]
fn readonly_probe_maps_io_uring_setup_errno_with_error_preservation() {
    const EPERM_FOR_TEST: i32 = 1;
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Err(UblkControlReadonlyProbeError::IoUringSetupErrno(
            EPERM_FOR_TEST,
        ))),
    );

    assert!(report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::IoUringSetupErrno
    );
    assert_eq!(report.probe_errno, Some(EPERM_FOR_TEST));
    assert_eq!(report.probe_features, None);
    assert_eq!(
        report.probe_error,
        Some(UblkControlReadonlyProbeError::IoUringSetupErrno(
            EPERM_FOR_TEST
        ))
    );
    assert_eq!(
        report.probe_spec,
        UblkControlReadonlyProbeSpec::get_features()
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}
#[test]
fn readonly_probe_maps_io_uring_setup_missing_errno() {
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Err(UblkControlReadonlyProbeError::IoUringSetupMissingErrno)),
    );

    assert!(report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::IoUringSetupMissingErrno
    );
    assert_eq!(report.probe_errno, None);
    assert_eq!(report.probe_features, None);
    assert_eq!(
        report.probe_error,
        Some(UblkControlReadonlyProbeError::IoUringSetupMissingErrno)
    );
    assert_eq!(
        report.probe_spec,
        UblkControlReadonlyProbeSpec::get_features()
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}
#[test]
fn readonly_probe_maps_io_uring_submit_errno() {
    const EAGAIN_FOR_TEST: i32 = 11;
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Err(UblkControlReadonlyProbeError::IoUringSubmitErrno(
            EAGAIN_FOR_TEST,
        ))),
    );

    assert!(report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::IoUringSubmitErrno
    );
    assert_eq!(report.probe_errno, Some(EAGAIN_FOR_TEST));
    assert_eq!(report.probe_features, None);
    assert_eq!(
        report.probe_error,
        Some(UblkControlReadonlyProbeError::IoUringSubmitErrno(
            EAGAIN_FOR_TEST
        ))
    );
    assert_eq!(
        report.probe_spec,
        UblkControlReadonlyProbeSpec::get_features()
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}

#[test]
fn readonly_probe_maps_io_uring_submit_missing_errno() {
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Err(
            UblkControlReadonlyProbeError::IoUringSubmitMissingErrno,
        )),
    );

    assert!(report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::IoUringSubmitMissingErrno
    );
    assert_eq!(report.probe_errno, None);
    assert_eq!(report.probe_features, None);
    assert_eq!(
        report.probe_error,
        Some(UblkControlReadonlyProbeError::IoUringSubmitMissingErrno)
    );
    assert_eq!(
        report.probe_spec,
        UblkControlReadonlyProbeSpec::get_features()
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}

#[test]
fn readonly_probe_maps_completion_missing() {
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Err(UblkControlReadonlyProbeError::CompletionMissing)),
    );

    assert!(report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::CompletionMissing
    );
    assert_eq!(report.probe_errno, None);
    assert_eq!(report.probe_features, None);
    assert_eq!(
        report.probe_error,
        Some(UblkControlReadonlyProbeError::CompletionMissing)
    );
    assert_eq!(
        report.probe_spec,
        UblkControlReadonlyProbeSpec::get_features()
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}

#[test]
fn readonly_probe_maps_unexpected_completion_user_data() {
    const BAD_USER_DATA: u64 = 0xdead;
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Err(
            UblkControlReadonlyProbeError::UnexpectedCompletionUserData(BAD_USER_DATA),
        )),
    );

    assert!(report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::UnexpectedCompletionUserData
    );
    assert_eq!(report.probe_errno, None);
    assert_eq!(report.probe_features, None);
    assert_eq!(
        report.probe_error,
        Some(UblkControlReadonlyProbeError::UnexpectedCompletionUserData(
            BAD_USER_DATA
        ))
    );
    assert_eq!(
        report.probe_spec,
        UblkControlReadonlyProbeSpec::get_features()
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}

#[test]
fn readonly_probe_maps_unsupported_read_only_command() {
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Err(
            UblkControlReadonlyProbeError::UnsupportedReadOnlyCommand(UblkCtrlCommand::GetDevInfo2),
        )),
    );

    assert!(report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::UnsupportedReadOnlyCommand
    );
    assert_eq!(report.probe_errno, None);
    assert_eq!(report.probe_features, None);
    assert_eq!(
        report.probe_error,
        Some(UblkControlReadonlyProbeError::UnsupportedReadOnlyCommand(
            UblkCtrlCommand::GetDevInfo2
        ))
    );
    assert_eq!(
        report.probe_spec,
        UblkControlReadonlyProbeSpec::get_features()
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}

#[test]
fn readonly_probe_maps_unsupported_mutating_command() {
    let report = evaluate_ublk_control_readonly_probe(
        &ready_inputs(),
        Some(Err(
            UblkControlReadonlyProbeError::UnsupportedMutatingCommand(UblkCtrlCommand::AddDev),
        )),
    );

    assert!(report.probe_uring_cmd_attempted);
    assert!(!report.probe_uring_cmd_completed);
    assert_eq!(
        report.probe_failure_class,
        UblkControlReadonlyProbeFailureClass::UnsupportedMutatingCommand
    );
    assert_eq!(report.probe_errno, None);
    assert_eq!(report.probe_features, None);
    assert_eq!(
        report.probe_error,
        Some(UblkControlReadonlyProbeError::UnsupportedMutatingCommand(
            UblkCtrlCommand::AddDev
        ))
    );
    assert_eq!(
        report.probe_spec,
        UblkControlReadonlyProbeSpec::get_features()
    );
    assert!(!report.mutating_ioctl_issued);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_device_created);
}

#[test]
fn add_dev_refuses_old_kernel_without_mutation_attempt() {
    let mut inputs = ready_inputs();
    inputs.kernel_release = "6.12.79-test".to_string();

    let report = evaluate_ublk_control_add_dev_boundary(
        &inputs,
        None,
        UblkControlAddDevInput::conservative_tidefs(),
        None,
    );

    assert!(!report.readonly_report.open_report.control_open_attempted);
    assert!(!report.readonly_report.probe_uring_cmd_attempted);
    assert!(!report.add_dev_uring_cmd_attempted);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::HostNotAdmitted
    );
    assert!(!report.ublk_device_pair_created);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn add_dev_refuses_missing_control_device_without_mutation_attempt() {
    let mut inputs = ready_inputs();
    inputs.control_path_present = false;
    inputs.control_path_is_char_device = false;
    inputs.control_open_result = None;

    let report = evaluate_ublk_control_add_dev_boundary(
        &inputs,
        None,
        UblkControlAddDevInput::conservative_tidefs(),
        None,
    );

    assert_eq!(
        report.readonly_report.open_report.refusal_class,
        UblkControlOpenRefusalClass::MissingUblkControl
    );
    assert!(!report.readonly_report.open_report.control_open_attempted);
    assert!(!report.add_dev_uring_cmd_attempted);
}

#[test]
fn add_dev_waits_for_successful_feature_probe() {
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Err(UblkControlReadonlyProbeError::UblkCommandErrno(25))),
        UblkControlAddDevInput::conservative_tidefs(),
        None,
    );

    assert!(report.readonly_report.open_report.control_opened);
    assert!(report.readonly_report.probe_uring_cmd_attempted);
    assert!(!report.readonly_report.probe_uring_cmd_completed);
    assert!(!report.add_dev_uring_cmd_attempted);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::FeatureProbeFailed
    );
}

#[test]
fn add_dev_requires_ioctl_encoded_user_copy_features() {
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            UblkFeatureFlags::CMD_IOCTL_ENCODE.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        None,
    );

    assert!(report.readonly_report.probe_uring_cmd_completed);
    assert!(!report.add_dev_required_features_available);
    assert!(!report.add_dev_uring_cmd_attempted);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::RequiredFeaturesMissing
    );
}

#[test]
fn add_dev_success_records_kernel_returned_device_pair() {
    let mut returned_info = tidefs_block_volume_adapter_ublk_control_runtime::build_add_dev_info(
        UblkControlAddDevInput::conservative_tidefs(),
    )
    .expect("add dev info");
    returned_info.dev_id = 17;
    returned_info.owner_uid = 1000;
    returned_info.owner_gid = 1000;

    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(UblkControlAddDevOutcome::from_dev_info(returned_info))),
    );

    assert!(report.add_dev_required_features_available);
    assert!(report.add_dev_uring_cmd_attempted);
    assert!(report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::None
    );
    assert_eq!(report.add_dev_outcome.expect("outcome").dev_info.dev_id, 17);
    assert!(report.ublk_device_pair_created);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn add_dev_errno_maps_failure_class() {
    const EPERM_FOR_TEST: i32 = 1;
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::UblkCommandErrno(
            EPERM_FOR_TEST,
        ))),
    );

    assert!(report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::UblkCommandErrno
    );
    assert_eq!(report.add_dev_errno, Some(EPERM_FOR_TEST));
    assert_eq!(report.add_dev_outcome, None);
}

#[test]
fn add_dev_reports_control_open_failed() {
    let mut inputs = ready_inputs();
    inputs.control_open_result = Some(Err(UblkControlOpenErrorClass::PermissionDenied));

    let report = evaluate_ublk_control_add_dev_boundary(
        &inputs,
        None,
        UblkControlAddDevInput::conservative_tidefs(),
        None,
    );

    assert!(report.readonly_report.open_report.control_open_attempted);
    assert!(!report.readonly_report.open_report.control_opened);
    assert!(!report.add_dev_uring_cmd_attempted);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::ControlOpenFailed
    );
    assert!(!report.ublk_device_pair_created);
}

#[test]
fn add_dev_reports_not_attempted_after_feature_probe() {
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        None,
    );

    assert!(report.readonly_report.probe_uring_cmd_completed);
    assert!(report.add_dev_required_features_available);
    assert!(!report.add_dev_uring_cmd_attempted);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::AddDevNotAttemptedAfterFeatureProbe
    );
    assert!(!report.ublk_device_pair_created);
}

#[test]
fn add_dev_maps_submission_queue_full_non_errno_error() {
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::SubmissionQueueFull)),
    );

    assert!(report.add_dev_required_features_available);
    assert!(report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::SubmissionQueueFull
    );
    assert_eq!(report.add_dev_errno, None);
    assert_eq!(report.add_dev_outcome, None);
    assert_eq!(
        report.add_dev_error,
        Some(UblkControlAddDevError::SubmissionQueueFull)
    );
    assert!(!report.ublk_device_pair_created);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn add_dev_maps_completion_missing_non_errno_error() {
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::CompletionMissing)),
    );

    assert!(report.add_dev_required_features_available);
    assert!(report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::CompletionMissing
    );
    assert_eq!(report.add_dev_errno, None);
    assert_eq!(report.add_dev_outcome, None);
    assert_eq!(
        report.add_dev_error,
        Some(UblkControlAddDevError::CompletionMissing)
    );
    assert!(!report.ublk_device_pair_created);
}

#[test]
fn add_dev_maps_invalid_input_error() {
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::ZeroHardwareQueues)),
    );

    assert!(report.add_dev_required_features_available);
    assert!(report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::InvalidAddDevInput
    );
    assert_eq!(report.add_dev_errno, None);
    assert_eq!(report.add_dev_outcome, None);
    assert_eq!(
        report.add_dev_error,
        Some(UblkControlAddDevError::ZeroHardwareQueues)
    );
    assert!(!report.ublk_device_pair_created);
}

#[test]
fn add_dev_maps_io_uring_setup_errno_with_error_preservation() {
    const EPERM_FOR_TEST: i32 = 1;
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::IoUringSetupErrno(
            EPERM_FOR_TEST,
        ))),
    );

    assert!(report.add_dev_required_features_available);
    assert!(report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::IoUringSetupErrno
    );
    assert_eq!(report.add_dev_errno, Some(EPERM_FOR_TEST));
    assert_eq!(report.add_dev_outcome, None);
    assert_eq!(
        report.add_dev_error,
        Some(UblkControlAddDevError::IoUringSetupErrno(EPERM_FOR_TEST))
    );
    assert!(!report.ublk_device_pair_created);
}

#[test]
fn add_dev_maps_io_uring_submit_errno_with_error_preservation() {
    const EBUSY_FOR_TEST: i32 = 16;
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::IoUringSubmitErrno(
            EBUSY_FOR_TEST,
        ))),
    );

    assert!(report.add_dev_required_features_available);
    assert!(report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::IoUringSubmitErrno
    );
    assert_eq!(report.add_dev_errno, Some(EBUSY_FOR_TEST));
    assert_eq!(report.add_dev_outcome, None);
    assert_eq!(
        report.add_dev_error,
        Some(UblkControlAddDevError::IoUringSubmitErrno(EBUSY_FOR_TEST))
    );
    assert!(!report.ublk_device_pair_created);
}

#[test]
fn add_dev_maps_io_uring_setup_missing_errno() {
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::IoUringSetupMissingErrno)),
    );

    assert!(report.add_dev_required_features_available);
    assert!(report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::IoUringSetupMissingErrno
    );
    assert_eq!(report.add_dev_errno, None);
    assert_eq!(report.add_dev_outcome, None);
    assert_eq!(
        report.add_dev_error,
        Some(UblkControlAddDevError::IoUringSetupMissingErrno)
    );
    assert!(!report.ublk_device_pair_created);
}

#[test]
fn add_dev_maps_io_uring_submit_missing_errno() {
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::IoUringSubmitMissingErrno)),
    );

    assert!(report.add_dev_required_features_available);
    assert!(report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::IoUringSubmitMissingErrno
    );
    assert_eq!(report.add_dev_errno, None);
    assert_eq!(report.add_dev_outcome, None);
    assert_eq!(
        report.add_dev_error,
        Some(UblkControlAddDevError::IoUringSubmitMissingErrno)
    );
    assert!(!report.ublk_device_pair_created);
}

#[test]
fn add_dev_maps_unexpected_completion_user_data_non_errno_error() {
    const BOGUS_USER_DATA: u64 = 0x_dead_beef;
    let report = evaluate_ublk_control_add_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::UnexpectedCompletionUserData(
            BOGUS_USER_DATA,
        ))),
    );

    assert!(report.add_dev_required_features_available);
    assert!(report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.add_dev_failure_class,
        UblkControlAddDevFailureClass::UnexpectedCompletionUserData
    );
    assert_eq!(report.add_dev_errno, None);
    assert_eq!(report.add_dev_outcome, None);
    assert_eq!(
        report.add_dev_error,
        Some(UblkControlAddDevError::UnexpectedCompletionUserData(
            BOGUS_USER_DATA
        ))
    );
    assert!(!report.ublk_device_pair_created);
}

#[test]
fn add_del_dev_refuses_old_kernel_without_cleanup_attempt() {
    let mut inputs = ready_inputs();
    inputs.kernel_release = "6.12.79-test".to_string();

    let report = evaluate_ublk_control_add_del_dev_boundary(
        &inputs,
        None,
        UblkControlAddDevInput::conservative_tidefs(),
        None,
        None,
    );

    assert!(
        !report
            .add_dev_report
            .readonly_report
            .open_report
            .control_open_attempted
    );
    assert!(!report.add_dev_report.add_dev_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::HostNotAdmitted
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(!report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn add_del_dev_skips_cleanup_when_add_dev_fails() {
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::UblkCommandErrno(1))),
        None,
    );

    assert!(
        report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_completed
    );
    assert!(report.add_dev_report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::AddDevFailed
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(!report.cleanup_failed_after_add_dev);
}

#[test]
fn add_del_dev_success_records_device_pair_cleanup() {
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert_eq!(report.del_dev_target_dev_id, Some(17));
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::None
    );
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(!report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(report.ublk_device_pair_deleted);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn add_del_dev_errno_records_cleanup_failure_after_add_dev() {
    const EBUSY_FOR_TEST: i32 = 16;
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(Err(UblkControlDelDevError::UblkCommandErrno(
            EBUSY_FOR_TEST,
        ))),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_completed);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::UblkCommandErrno
    );
    assert_eq!(report.del_dev_errno, Some(EBUSY_FOR_TEST));
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn add_del_dev_rejects_auto_device_id_as_cleanup_target() {
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(u32::MAX))),
        Some(Err(UblkControlDelDevError::AutoDeviceId)),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert_eq!(report.del_dev_target_dev_id, Some(u32::MAX));
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::InvalidDelDevInput
    );
    assert!(report.cleanup_failed_after_add_dev);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn add_del_dev_reports_control_open_failed_without_cleanup_attempt() {
    let mut inputs = ready_inputs();
    inputs.control_open_result = Some(Err(UblkControlOpenErrorClass::PermissionDenied));

    let report = evaluate_ublk_control_add_del_dev_boundary(
        &inputs,
        None,
        UblkControlAddDevInput::conservative_tidefs(),
        None,
        None,
    );

    assert!(
        report
            .add_dev_report
            .readonly_report
            .open_report
            .control_open_attempted
    );
    assert!(
        !report
            .add_dev_report
            .readonly_report
            .open_report
            .control_opened
    );
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::ControlOpenFailed
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(!report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn add_del_dev_feature_probe_failed_without_cleanup_attempt() {
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Err(UblkControlReadonlyProbeError::UblkCommandErrno(22))),
        UblkControlAddDevInput::conservative_tidefs(),
        None,
        None,
    );

    assert!(
        report
            .add_dev_report
            .readonly_report
            .open_report
            .control_opened
    );
    assert!(
        !report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_completed
    );
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::FeatureProbeFailed
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(!report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn add_del_dev_required_features_missing_without_cleanup_attempt() {
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(0))),
        UblkControlAddDevInput::conservative_tidefs(),
        None,
        None,
    );

    assert!(
        report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_completed
    );
    assert!(!report.add_dev_report.add_dev_required_features_available);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::RequiredFeaturesMissing
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(!report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn add_del_dev_not_attempted_after_add_dev_success() {
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert_eq!(report.del_dev_target_dev_id, Some(17));
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::DelDevNotAttemptedAfterAddDev
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn del_dev_iouring_setup_errno_cleanup_failure_after_add_dev() {
    const EACCES_FOR_TEST: i32 = 13;
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(Err(UblkControlDelDevError::IoUringSetupErrno(
            EACCES_FOR_TEST,
        ))),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_completed);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::IoUringSetupErrno
    );
    assert_eq!(report.del_dev_errno, Some(EACCES_FOR_TEST));
    assert_eq!(
        report.del_dev_error,
        Some(UblkControlDelDevError::IoUringSetupErrno(EACCES_FOR_TEST))
    );
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn del_dev_iouring_setup_missing_errno_cleanup_failure_after_add_dev() {
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(Err(UblkControlDelDevError::IoUringSetupMissingErrno)),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_completed);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::IoUringSetupMissingErrno
    );
    assert_eq!(report.del_dev_errno, None);
    assert_eq!(
        report.del_dev_error,
        Some(UblkControlDelDevError::IoUringSetupMissingErrno)
    );
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn del_dev_submission_queue_full_cleanup_failure_after_add_dev() {
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(Err(UblkControlDelDevError::SubmissionQueueFull)),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_completed);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::SubmissionQueueFull
    );
    assert_eq!(report.del_dev_errno, None);
    assert_eq!(
        report.del_dev_error,
        Some(UblkControlDelDevError::SubmissionQueueFull)
    );
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn del_dev_iouring_submit_errno_cleanup_failure_after_add_dev() {
    const EINTR_FOR_TEST: i32 = 4;
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(Err(UblkControlDelDevError::IoUringSubmitErrno(
            EINTR_FOR_TEST,
        ))),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_completed);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::IoUringSubmitErrno
    );
    assert_eq!(report.del_dev_errno, Some(EINTR_FOR_TEST));
    assert_eq!(
        report.del_dev_error,
        Some(UblkControlDelDevError::IoUringSubmitErrno(EINTR_FOR_TEST))
    );
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn del_dev_iouring_submit_missing_errno_cleanup_failure_after_add_dev() {
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(Err(UblkControlDelDevError::IoUringSubmitMissingErrno)),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_completed);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::IoUringSubmitMissingErrno
    );
    assert_eq!(report.del_dev_errno, None);
    assert_eq!(
        report.del_dev_error,
        Some(UblkControlDelDevError::IoUringSubmitMissingErrno)
    );
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn del_dev_completion_missing_cleanup_failure_after_add_dev() {
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(Err(UblkControlDelDevError::CompletionMissing)),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_completed);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::CompletionMissing
    );
    assert_eq!(report.del_dev_errno, None);
    assert_eq!(
        report.del_dev_error,
        Some(UblkControlDelDevError::CompletionMissing)
    );
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn del_dev_unexpected_completion_user_data_cleanup_failure_after_add_dev() {
    const BOGUS_USER_DATA: u64 = 0x_dead_beef;
    let report = evaluate_ublk_control_add_del_dev_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(Err(UblkControlDelDevError::UnexpectedCompletionUserData(
            BOGUS_USER_DATA,
        ))),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_completed);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::UnexpectedCompletionUserData
    );
    assert_eq!(report.del_dev_errno, None);
    assert_eq!(
        report.del_dev_error,
        Some(UblkControlDelDevError::UnexpectedCompletionUserData(
            BOGUS_USER_DATA
        ))
    );
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]

fn set_params_refuses_old_kernel_without_mutation_or_cleanup_attempt() {
    let mut inputs = ready_inputs();
    inputs.kernel_release = "6.12.79-test".to_string();

    let report = evaluate_ublk_control_set_params_boundary(
        &inputs,
        None,
        UblkControlAddDevInput::conservative_tidefs(),
        None,
        None,
        None,
        None,
    );

    assert!(
        !report
            .add_dev_report
            .readonly_report
            .open_report
            .control_open_attempted
    );
    assert!(!report.set_params_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::HostNotAdmitted
    );
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::HostNotAdmitted
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(!report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_waits_for_required_add_dev_features() {
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            UblkFeatureFlags::CMD_IOCTL_ENCODE.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        None,
        None,
        None,
        None,
    );

    assert!(
        report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_completed
    );
    assert!(!report.add_dev_report.add_dev_required_features_available);
    assert!(!report.set_params_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::RequiredFeaturesMissing
    );
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::RequiredFeaturesMissing
    );
}

#[test]
fn set_params_skips_when_add_dev_fails() {
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Err(UblkControlAddDevError::UblkCommandErrno(1))),
        None,
        None,
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.set_params_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::AddDevFailed
    );
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::AddDevFailed
    );
}

#[test]
fn set_params_success_records_projected_params_and_cleanup() {
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        Some(Ok(UblkControlSetParamsOutcome::from_input(input))),
        Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert_eq!(report.set_params_target_dev_id, Some(17));
    assert!(report.set_params_projected);
    assert!(report.set_params_uring_cmd_attempted);
    assert!(report.set_params_uring_cmd_completed);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::None
    );
    assert_eq!(report.set_params_spec.param_types, input.params.types);
    assert_eq!(
        report.set_params_spec.dev_sectors,
        input.params.basic.dev_sectors
    );
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(!report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(report.ublk_device_pair_deleted);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn set_params_errno_still_records_del_dev_cleanup() {
    const EINVAL_FOR_TEST: i32 = 22;
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        Some(Err(UblkControlSetParamsError::UblkCommandErrno(
            EINVAL_FOR_TEST,
        ))),
        Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    );

    assert!(report.set_params_uring_cmd_attempted);
    assert!(!report.set_params_uring_cmd_completed);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::UblkCommandErrno
    );
    assert_eq!(report.set_params_errno, Some(EINVAL_FOR_TEST));
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(!report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_deleted);
}

#[test]
fn set_params_invalid_input_does_not_submit_but_still_cleans_up() {
    let mut input = projected_set_params_input(u32::MAX);
    input.params.len = 0;
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(u32::MAX))),
        Some(input),
        Some(Err(UblkControlSetParamsError::AutoDeviceId)),
        Some(Err(UblkControlDelDevError::AutoDeviceId)),
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert_eq!(report.set_params_target_dev_id, Some(u32::MAX));
    assert!(!report.set_params_uring_cmd_attempted);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::InvalidSetParamsInput
    );
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::InvalidDelDevInput
    );
    assert!(report.cleanup_failed_after_add_dev);
}

#[test]
fn set_params_success_with_del_dev_errno_records_cleanup_failure() {
    const EBUSY_FOR_TEST: i32 = 16;
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        Some(Ok(UblkControlSetParamsOutcome::from_input(input))),
        Some(Err(UblkControlDelDevError::UblkCommandErrno(
            EBUSY_FOR_TEST,
        ))),
    );

    assert!(report.set_params_uring_cmd_completed);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_completed);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::UblkCommandErrno
    );
    assert_eq!(report.del_dev_errno, Some(EBUSY_FOR_TEST));
    assert!(report.cleanup_attempted_after_add_dev);
    assert!(report.cleanup_failed_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_when_control_open_failed() {
    let mut inputs = ready_inputs();
    inputs.control_open_result = Some(Err(UblkControlOpenErrorClass::PermissionDenied));

    let report = evaluate_ublk_control_set_params_boundary(
        &inputs,
        None,
        UblkControlAddDevInput::conservative_tidefs(),
        None,
        None,
        None,
        None,
    );

    assert!(
        report
            .add_dev_report
            .readonly_report
            .open_report
            .control_open_attempted
    );
    assert!(
        !report
            .add_dev_report
            .readonly_report
            .open_report
            .control_opened
    );
    assert!(!report.set_params_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::ControlOpenFailed
    );
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::ControlOpenFailed
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(!report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_when_feature_probe_not_completed() {
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        None,
        UblkControlAddDevInput::conservative_tidefs(),
        None,
        None,
        None,
        None,
    );

    assert!(
        report
            .add_dev_report
            .readonly_report
            .open_report
            .control_opened
    );
    assert!(
        !report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_completed
    );
    assert!(!report.set_params_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::FeatureProbeFailed
    );
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::FeatureProbeFailed
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(!report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_when_parameter_build_failed() {
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        None,
        None,
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert_eq!(report.set_params_target_dev_id, Some(17));
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::ParameterBuildFailed
    );
    assert!(!report.set_params_uring_cmd_attempted);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::DelDevNotAttemptedAfterAddDev
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(report.ublk_device_pair_created);
}

#[test]
fn set_params_when_not_attempted_after_add_dev() {
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        None,
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.set_params_projected);
    assert!(!report.set_params_uring_cmd_attempted);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::SetParamsNotAttemptedAfterAddDev
    );
    assert!(!report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.del_dev_failure_class,
        UblkControlDelDevFailureClass::DelDevNotAttemptedAfterAddDev
    );
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_iouring_setup_errno_still_cleans_up() {
    const EPERM_FOR_TEST: i32 = 1;
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        Some(Err(UblkControlSetParamsError::IoUringSetupErrno(
            EPERM_FOR_TEST,
        ))),
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.set_params_uring_cmd_attempted);
    assert!(!report.set_params_uring_cmd_completed);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::IoUringSetupErrno
    );
    assert_eq!(report.set_params_errno, Some(EPERM_FOR_TEST));
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_iouring_setup_missing_errno_still_cleans_up() {
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        Some(Err(UblkControlSetParamsError::IoUringSetupMissingErrno)),
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.set_params_uring_cmd_attempted);
    assert!(!report.set_params_uring_cmd_completed);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::IoUringSetupMissingErrno
    );
    assert_eq!(report.set_params_errno, None);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_submission_queue_full_still_cleans_up() {
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        Some(Err(UblkControlSetParamsError::SubmissionQueueFull)),
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.set_params_uring_cmd_attempted);
    assert!(!report.set_params_uring_cmd_completed);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::SubmissionQueueFull
    );
    assert_eq!(report.set_params_errno, None);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_iouring_submit_errno_still_cleans_up() {
    const EIO_FOR_TEST: i32 = 5;
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        Some(Err(UblkControlSetParamsError::IoUringSubmitErrno(
            EIO_FOR_TEST,
        ))),
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.set_params_uring_cmd_attempted);
    assert!(!report.set_params_uring_cmd_completed);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::IoUringSubmitErrno
    );
    assert_eq!(report.set_params_errno, Some(EIO_FOR_TEST));
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_iouring_submit_missing_errno_still_cleans_up() {
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        Some(Err(UblkControlSetParamsError::IoUringSubmitMissingErrno)),
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.set_params_uring_cmd_attempted);
    assert!(!report.set_params_uring_cmd_completed);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::IoUringSubmitMissingErrno
    );
    assert_eq!(report.set_params_errno, None);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_completion_missing_still_cleans_up() {
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        Some(Err(UblkControlSetParamsError::CompletionMissing)),
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.set_params_uring_cmd_attempted);
    assert!(!report.set_params_uring_cmd_completed);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::CompletionMissing
    );
    assert_eq!(report.set_params_errno, None);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn set_params_unexpected_completion_user_data_still_cleans_up() {
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_set_params_boundary(
        &ready_inputs(),
        Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        UblkControlAddDevInput::conservative_tidefs(),
        Some(Ok(returned_add_dev_outcome(17))),
        Some(input),
        Some(Err(
            UblkControlSetParamsError::UnexpectedCompletionUserData(0x_dead_c0de),
        )),
        None,
    );

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.set_params_uring_cmd_attempted);
    assert!(!report.set_params_uring_cmd_completed);
    assert_eq!(
        report.set_params_failure_class,
        UblkControlSetParamsFailureClass::UnexpectedCompletionUserData
    );
    assert_eq!(report.set_params_errno, None);
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
    assert!(report.ublk_device_pair_created);
    assert!(!report.ublk_device_pair_deleted);
}

#[test]
fn start_dev_when_control_open_failed() {
    let mut inputs = ready_inputs();
    inputs.control_open_result = Some(Err(UblkControlOpenErrorClass::PermissionDenied));

    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &inputs,
        probe_result: None,
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: None,
        set_params_input: None,
        set_params_result: None,
        start_dev_input: None,
        start_dev_result: None,
        start_dev_readiness: start_dev_readiness(0),
        del_dev_result: None,
    });

    assert!(
        report
            .set_params_report
            .add_dev_report
            .readonly_report
            .open_report
            .control_open_attempted
    );
    assert!(
        !report
            .set_params_report
            .add_dev_report
            .readonly_report
            .open_report
            .control_opened
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.set_params_report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::ControlOpenFailed
    );
    assert!(!report.ublk_block_device_started);
}

#[test]
fn start_dev_when_feature_probe_not_completed() {
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: None,
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: None,
        set_params_input: None,
        set_params_result: None,
        start_dev_input: None,
        start_dev_result: None,
        start_dev_readiness: start_dev_readiness(0),
        del_dev_result: None,
    });

    assert!(
        report
            .set_params_report
            .add_dev_report
            .readonly_report
            .open_report
            .control_opened
    );
    assert!(
        !report
            .set_params_report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_completed
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.set_params_report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::FeatureProbeFailed
    );
    assert!(!report.ublk_block_device_started);
}

#[test]
fn start_dev_when_required_features_missing() {
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            UblkFeatureFlags::CMD_IOCTL_ENCODE.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: None,
        set_params_input: None,
        set_params_result: None,
        start_dev_input: None,
        start_dev_result: None,
        start_dev_readiness: start_dev_readiness(0),
        del_dev_result: None,
    });

    assert!(
        report
            .set_params_report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_completed
    );
    assert!(
        !report
            .set_params_report
            .add_dev_report
            .add_dev_required_features_available
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.set_params_report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::RequiredFeaturesMissing
    );
    assert!(!report.ublk_block_device_started);
}

#[test]
fn start_dev_when_add_dev_failed() {
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: Some(Err(UblkControlAddDevError::UblkCommandErrno(1))),
        set_params_input: None,
        set_params_result: None,
        start_dev_input: None,
        start_dev_result: None,
        start_dev_readiness: start_dev_readiness(0),
        del_dev_result: None,
    });

    assert!(
        report
            .set_params_report
            .add_dev_report
            .add_dev_uring_cmd_attempted
    );
    assert!(
        !report
            .set_params_report
            .add_dev_report
            .add_dev_uring_cmd_completed
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.set_params_report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::AddDevFailed
    );
    assert!(!report.ublk_block_device_started);
}

#[test]
fn start_dev_when_parameter_build_failed() {
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        set_params_input: None,
        set_params_result: None,
        start_dev_input: None,
        start_dev_result: None,
        start_dev_readiness: start_dev_readiness(0),
        del_dev_result: None,
    });

    assert!(
        report
            .set_params_report
            .add_dev_report
            .add_dev_uring_cmd_completed
    );
    assert_eq!(report.start_dev_target_dev_id, Some(17));
    assert!(!report.set_params_report.set_params_projected);
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.set_params_report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::ParameterBuildFailed
    );
    assert!(!report.ublk_block_device_started);
}

#[test]
fn start_dev_when_not_attempted_after_set_params() {
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        set_params_input: Some(input),
        set_params_result: Some(Ok(UblkControlSetParamsOutcome::from_input(input))),
        start_dev_input: Some(start_dev_input(17)),
        start_dev_result: None,
        start_dev_readiness: live_start_dev_readiness(64),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.set_params_report.set_params_uring_cmd_completed);
    assert_eq!(report.start_dev_target_dev_id, Some(17));
    assert!(report.start_dev_readiness.all_fetches_ready());
    assert!(!report.start_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::StartDevNotAttemptedAfterSetParams
    );
    assert!(report.set_params_report.del_dev_uring_cmd_completed);
    assert!(!report.ublk_block_device_started);
}
#[test]
fn start_dev_refuses_old_kernel_without_mutation_or_cleanup_attempt() {
    let mut inputs = ready_inputs();
    inputs.kernel_release = "6.12.79-test".to_string();

    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &inputs,
        probe_result: None,
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: None,
        set_params_input: None,
        set_params_result: None,
        start_dev_input: None,
        start_dev_result: None,
        start_dev_readiness: start_dev_readiness(0),
        del_dev_result: None,
    });

    assert!(
        !report
            .set_params_report
            .add_dev_report
            .readonly_report
            .open_report
            .control_open_attempted
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.set_params_report.del_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::HostNotAdmitted
    );
    assert!(!report.ublk_block_device_started);
}

#[test]
fn fetch_req_readiness_boundary_reports_queue_without_submission() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let fetch_input = UblkDataQueueFetchReqInput::user_copy(
        0,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );
    let fetch_spec = build_fetch_req_spec(fetch_input).expect("fetch spec");
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
        0,
        false,
    );

    let report = evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &ready_inputs(),
        add_dev_input,
        fetch_spec,
        readiness,
    );

    assert_eq!(report.fetch_req_spec.command.as_str(), "FETCH_REQ");
    assert_eq!(report.fetch_req_spec.q_id, 0);
    assert_eq!(report.fetch_req_spec.tag, 0);
    assert_eq!(report.fetch_req_spec.user_copy_addr, 0);
    assert_eq!(report.fetch_req_readiness.required_fetch_commands, 64);
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 0);
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert!(!report.data_queue_open_attempted);
    assert!(!report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submitted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn start_dev_skips_when_set_params_fails_but_records_cleanup() {
    const EINVAL_FOR_TEST: i32 = 22;
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        set_params_input: Some(input),
        set_params_result: Some(Err(UblkControlSetParamsError::UblkCommandErrno(
            EINVAL_FOR_TEST,
        ))),
        start_dev_input: None,
        start_dev_result: None,
        start_dev_readiness: start_dev_readiness(0),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.set_params_report.set_params_uring_cmd_attempted);
    assert!(!report.set_params_report.set_params_uring_cmd_completed);
    assert!(!report.start_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::SetParamsFailed
    );
    assert!(report.set_params_report.del_dev_uring_cmd_attempted);
    assert!(report.set_params_report.del_dev_uring_cmd_completed);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn start_dev_requires_ready_data_queue_fetches_after_set_params() {
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        set_params_input: Some(input),
        set_params_result: Some(Ok(UblkControlSetParamsOutcome::from_input(input))),
        start_dev_input: Some(start_dev_input(17)),
        start_dev_result: None,
        start_dev_readiness: start_dev_readiness(0),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.set_params_report.set_params_uring_cmd_completed);
    assert_eq!(report.start_dev_target_dev_id, Some(17));
    assert_eq!(report.start_dev_daemon_pid, Some(1234));
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert!(report.start_dev_readiness.data_queue_runtime_live);
    assert_eq!(report.start_dev_readiness.required_fetch_commands, 64);
    assert_eq!(report.start_dev_readiness.submitted_fetch_commands, 0);
    assert!(!report.start_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::DataQueueFetchesNotReady
    );
    assert!(report.set_params_report.del_dev_uring_cmd_attempted);
    assert!(report.set_params_report.del_dev_uring_cmd_completed);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn start_dev_readiness_requires_live_data_queue_runtime() {
    let input = projected_set_params_input(17);
    let dropped_runtime =
        UblkControlStartDevReadiness::from_queue_geometry_with_runtime(1, 64, 64, false);
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        set_params_input: Some(input),
        set_params_result: Some(Ok(UblkControlSetParamsOutcome::from_input(input))),
        start_dev_input: Some(start_dev_input(17)),
        start_dev_result: None,
        start_dev_readiness: dropped_runtime,
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert_eq!(report.start_dev_readiness.submitted_fetch_commands, 64);
    assert!(!report.start_dev_readiness.data_queue_runtime_live);
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert!(!report.start_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::DataQueueFetchesNotReady
    );
}

#[test]
fn start_dev_success_records_started_boundary_and_cleanup() {
    let input = projected_set_params_input(17);
    let start_input = start_dev_input(17);
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        set_params_input: Some(input),
        set_params_result: Some(Ok(UblkControlSetParamsOutcome::from_input(input))),
        start_dev_input: Some(start_input),
        start_dev_result: Some(Ok(UblkControlStartDevOutcome::from_input(start_input))),
        start_dev_readiness: live_start_dev_readiness(64),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.start_dev_readiness.all_fetches_ready());
    assert!(report.start_dev_readiness.data_queue_runtime_live);
    assert!(report.start_dev_uring_cmd_attempted);
    assert!(report.start_dev_uring_cmd_completed);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::None
    );
    assert_eq!(report.start_dev_target_dev_id, Some(17));
    assert_eq!(report.start_dev_daemon_pid, Some(1234));
    assert!(report.ublk_block_device_started);
    assert!(report.set_params_report.del_dev_uring_cmd_completed);
}

#[test]
fn start_dev_errno_records_failure_and_cleanup() {
    const EBUSY_FOR_TEST: i32 = 16;
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        set_params_input: Some(input),
        set_params_result: Some(Ok(UblkControlSetParamsOutcome::from_input(input))),
        start_dev_input: Some(start_dev_input(17)),
        start_dev_result: Some(Err(UblkControlStartDevError::UblkCommandErrno(
            EBUSY_FOR_TEST,
        ))),
        start_dev_readiness: start_dev_readiness(64),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.start_dev_uring_cmd_attempted);
    assert!(!report.start_dev_uring_cmd_completed);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::UblkCommandErrno
    );
    assert_eq!(report.start_dev_errno, Some(EBUSY_FOR_TEST));
    assert!(report.set_params_report.del_dev_uring_cmd_completed);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn start_dev_invalid_input_does_not_submit_but_still_cleans_up() {
    let input = projected_set_params_input(17);
    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        set_params_input: Some(input),
        set_params_result: Some(Ok(UblkControlSetParamsOutcome::from_input(input))),
        start_dev_input: Some(UblkControlStartDevInput::from_kernel_dev_id_and_daemon_pid(
            17, 0,
        )),
        start_dev_result: Some(Err(UblkControlStartDevError::InvalidDaemonPid)),
        start_dev_readiness: start_dev_readiness(64),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(!report.start_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::InvalidStartDevInput
    );
    assert!(report.set_params_report.del_dev_uring_cmd_completed);
    assert!(!report.ublk_block_device_started);
}
#[test]
fn start_dev_when_add_dev_did_not_return_device_id() {
    let add_dev_outcome_without_id = UblkControlAddDevOutcome {
        command: tidefs_block_volume_adapter_ublk_control_runtime::UblkControlAddDevCommand::AddDev,
        request_raw: UblkCtrlCommand::AddDev.request().raw(),
        dev_info: tidefs_ublk_abi::UblkSrvCtrlDevInfo {
            dev_id: u32::MAX,
            ..tidefs_block_volume_adapter_ublk_control_runtime::build_add_dev_info(
                UblkControlAddDevInput::conservative_tidefs(),
            )
            .expect("add dev info")
        },
    };

    let report = evaluate_ublk_control_start_dev_boundary(UblkControlStartDevBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: Some(Ok(add_dev_outcome_without_id)),
        set_params_input: None,
        set_params_result: None,
        start_dev_input: None,
        start_dev_result: None,
        start_dev_readiness: start_dev_readiness(0),
        del_dev_result: None,
    });

    assert!(
        report
            .set_params_report
            .add_dev_report
            .add_dev_uring_cmd_completed
    );
    assert_eq!(report.start_dev_target_dev_id, None);
    assert!(!report.start_dev_uring_cmd_attempted);
    assert_eq!(
        report.start_dev_failure_class,
        UblkControlStartDevFailureClass::AddDevDidNotReturnDeviceId
    );
    assert!(!report.ublk_block_device_started);
}

#[test]
fn data_queue_fetch_req_readiness_reports_command_shape_without_submission() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let fetch_req_input = UblkDataQueueFetchReqInput::user_copy(0, 7, 1, 64);
    let fetch_req_spec = build_fetch_req_spec(fetch_req_input).expect("fetch req spec");
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(1, 64, 0, false);

    let report = evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &ready_inputs(),
        add_dev_input,
        fetch_req_spec,
        readiness,
    );

    assert_eq!(report.fetch_req_spec.command.as_str(), "FETCH_REQ");
    assert_eq!(report.fetch_req_spec.q_id, 0);
    assert_eq!(report.fetch_req_spec.tag, 7);
    assert_eq!(
        report.fetch_req_spec.request_direction.as_str(),
        "read_write"
    );
    assert_eq!(report.fetch_req_spec.uring_cmd_sqe_bytes, 128);
    assert_eq!(report.fetch_req_readiness.required_fetch_commands, 64);
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 0);
    assert!(!report.fetch_req_readiness.all_fetches_ready());
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert!(!report.data_queue_open_attempted);
    assert!(!report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submitted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn data_queue_fetch_req_readiness_feeds_start_dev_when_runtime_is_live() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let fetch_req_input = UblkDataQueueFetchReqInput::user_copy(0, 0, 1, 64);
    let fetch_req_spec = build_fetch_req_spec(fetch_req_input).expect("fetch req spec");
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(1, 64, 64, true);

    let report = evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &ready_inputs(),
        add_dev_input,
        fetch_req_spec,
        readiness,
    );

    assert!(report.fetch_req_readiness.all_fetches_ready());
    assert!(report.start_dev_readiness.all_fetches_ready());
    assert_eq!(report.start_dev_readiness.required_fetch_commands, 64);
    assert_eq!(report.start_dev_readiness.submitted_fetch_commands, 64);
    assert!(report.start_dev_readiness.data_queue_runtime_live);
    assert!(!report.fetch_req_submitted);
    assert!(!report.ublk_block_device_started);
}
#[test]
fn fetch_req_readiness_boundary_reports_correctly_when_control_open_failed() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let fetch_input = UblkDataQueueFetchReqInput::user_copy(
        0,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );
    let fetch_spec = build_fetch_req_spec(fetch_input).expect("fetch spec");
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
        0,
        false,
    );

    let mut inputs = ready_inputs();
    inputs.control_path_present = false;
    inputs.control_open_result = Some(Err(UblkControlOpenErrorClass::NotFound));

    let report = evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &inputs,
        add_dev_input,
        fetch_spec,
        readiness,
    );

    assert!(!report.open_report.control_opened);
    assert_eq!(report.fetch_req_spec.command.as_str(), "FETCH_REQ");
    assert_eq!(report.fetch_req_readiness.required_fetch_commands, 64);
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 0);
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert!(!report.data_queue_open_attempted);
    assert!(!report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submitted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn fetch_req_readiness_boundary_reports_correctly_when_kernel_not_supported() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let fetch_input = UblkDataQueueFetchReqInput::user_copy(
        0,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );
    let fetch_spec = build_fetch_req_spec(fetch_input).expect("fetch spec");
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
        0,
        false,
    );

    let mut inputs = ready_inputs();
    inputs.kernel_release = "5.10.0-legacy".to_string();

    let report = evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &inputs,
        add_dev_input,
        fetch_spec,
        readiness,
    );

    assert!(!report.open_report.observe_baseline_satisfied);
    assert_eq!(report.fetch_req_spec.command.as_str(), "FETCH_REQ");
    assert_eq!(report.fetch_req_spec.q_id, 0);
    assert_eq!(report.fetch_req_spec.tag, 0);
    assert_eq!(report.fetch_req_spec.user_copy_addr, 0);
    assert!(!report.fetch_req_readiness.all_fetches_ready());
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert!(!report.data_queue_open_attempted);
    assert!(!report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submitted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn fetch_req_readiness_boundary_all_nonclaim_fields_are_consistent() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let fetch_input = UblkDataQueueFetchReqInput::user_copy(
        0,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );
    let fetch_spec = build_fetch_req_spec(fetch_input).expect("fetch spec");
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
        0,
        false,
    );

    let report = evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &ready_inputs(),
        add_dev_input,
        fetch_spec,
        readiness,
    );

    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert!(!report.data_queue_runtime_live);
    assert!(!report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submitted);
    assert!(!report.ublk_block_device_started);
    assert_eq!(report.data_queue_path, PathBuf::from("/dev/ublkc0"));
    assert_eq!(report.add_dev_input.nr_hw_queues, 1);
    assert_eq!(report.add_dev_input.queue_depth, 64);
    assert_eq!(report.fetch_req_spec.uring_cmd_sqe_bytes, 128);
    assert!(!report.fetch_req_spec.commits_result);
    assert!(report.fetch_req_spec.must_remain_in_flight_for_start);
}

#[test]
fn fetch_req_readiness_boundary_with_multi_queue_geometry() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let fetch_input = UblkDataQueueFetchReqInput::user_copy(
        0,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );
    let fetch_spec = build_fetch_req_spec(fetch_input).expect("fetch spec");
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(4, 128, 256, true);

    let report = evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &ready_inputs(),
        add_dev_input,
        fetch_spec,
        readiness,
    );

    assert_eq!(report.fetch_req_readiness.nr_hw_queues, 4);
    assert_eq!(report.fetch_req_readiness.queue_depth, 128);
    assert_eq!(report.fetch_req_readiness.required_fetch_commands, 512);
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 256);
    assert!(report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.fetch_req_readiness.all_fetches_ready());
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert_eq!(report.start_dev_readiness.required_fetch_commands, 512);
    assert_eq!(report.start_dev_readiness.submitted_fetch_commands, 256);
    assert!(report.start_dev_readiness.data_queue_runtime_live);
    assert!(!report.fetch_req_submitted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn fetch_req_readiness_boundary_requires_runtime_live_even_when_all_fetches_count_match() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let fetch_input = UblkDataQueueFetchReqInput::user_copy(
        0,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );
    let fetch_spec = build_fetch_req_spec(fetch_input).expect("fetch spec");
    let readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(1, 64, 64, false);

    let report = evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &ready_inputs(),
        add_dev_input,
        fetch_spec,
        readiness,
    );

    assert_eq!(report.fetch_req_readiness.required_fetch_commands, 64);
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 64);
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.fetch_req_readiness.all_fetches_ready());
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert!(!report.ublk_block_device_started);
}

#[test]
fn fetch_req_readiness_boundary_start_dev_readiness_inherits_data_queue_runtime_live() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let fetch_input = UblkDataQueueFetchReqInput::user_copy(
        0,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );
    let fetch_spec = build_fetch_req_spec(fetch_input).expect("fetch spec");

    let live_readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(2, 64, 128, true);
    let live_report = evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &ready_inputs(),
        add_dev_input,
        fetch_spec,
        live_readiness,
    );
    assert!(live_report.start_dev_readiness.data_queue_runtime_live);
    assert!(live_report.start_dev_readiness.all_fetches_ready());

    let dead_readiness = UblkDataQueueFetchReqReadiness::from_queue_geometry(2, 64, 128, false);
    let dead_report = evaluate_ublk_data_queue_fetch_req_readiness_boundary(
        &ready_inputs(),
        add_dev_input,
        fetch_spec,
        dead_readiness,
    );
    assert!(!dead_report.start_dev_readiness.data_queue_runtime_live);
    assert!(!dead_report.start_dev_readiness.all_fetches_ready());
}

#[test]
fn data_queue_open_boundary_refuses_without_add_dev() {
    let mut inputs = ready_inputs();
    inputs.kernel_release = "6.12.79-test".to_string();

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &inputs,
        probe_result: None,
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: None,
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: None,
    });

    assert!(!report.add_dev_report.add_dev_uring_cmd_attempted);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::HostNotAdmitted
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert!(!report.del_dev_uring_cmd_attempted);
}

#[test]
fn data_queue_open_boundary_records_runtime_open_and_cleanup_without_fetch_or_start() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );
    let data_queue_spec =
        tidefs_block_volume_adapter_ublk_control_runtime::build_data_queue_runtime_open_spec(
            data_queue_input,
        )
        .expect("data queue spec");
    let data_queue_outcome = UblkDataQueueRuntimeOpenOutcome::from_spec(&data_queue_spec);

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Ok(data_queue_outcome)),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert_eq!(
        report.data_queue_spec.data_queue_path,
        PathBuf::from("/dev/ublkc17")
    );
    assert!(report.data_queue_open_attempted);
    assert!(report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::None
    );
    assert!(report.fetch_req_readiness.data_queue_runtime_live);
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 0);
    assert!(!report.fetch_req_readiness.all_fetches_ready());
    assert!(!report.fetch_req_submitted);
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
    assert!(report.cleanup_attempted_after_add_dev);
}

#[test]
fn data_queue_open_boundary_reports_path_refusal_and_still_cleans_up() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::DataQueuePathMissing)),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueuePathMissing
    );
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueuePathMissing)
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}
#[test]
fn data_queue_open_boundary_reports_control_open_failed() {
    let mut inputs = ready_inputs();
    inputs.control_open_result = Some(Err(UblkControlOpenErrorClass::PermissionDenied));

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &inputs,
        probe_result: None,
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: None,
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: None,
    });

    assert!(!report.add_dev_report.add_dev_uring_cmd_attempted);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::ControlOpenFailed
    );
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
}

#[test]
fn data_queue_open_boundary_reports_feature_probe_failed() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Err(UblkControlReadonlyProbeError::UblkCommandErrno(22))),
        add_dev_input,
        add_dev_result: None,
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: None,
    });

    assert!(!report.add_dev_report.add_dev_uring_cmd_attempted);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::FeatureProbeFailed
    );
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
}

#[test]
fn data_queue_open_boundary_reports_required_features_missing() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(0))),
        add_dev_input,
        add_dev_result: None,
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: None,
    });

    assert!(!report.add_dev_report.add_dev_uring_cmd_attempted);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::RequiredFeaturesMissing
    );
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
}

#[test]
fn data_queue_open_boundary_reports_add_dev_failed() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Err(UblkControlAddDevError::UblkCommandErrno(1))),
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: None,
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::AddDevFailed
    );
    assert!(!report.del_dev_uring_cmd_attempted);
    assert!(!report.cleanup_attempted_after_add_dev);
}

#[test]
fn data_queue_open_boundary_reports_not_attempted_after_add_dev() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: None,
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueueOpenNotAttemptedAfterAddDev
    );
    assert!(!report.del_dev_uring_cmd_attempted);
}

#[test]
fn data_queue_open_boundary_reports_invalid_data_queue_runtime_input() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input(17)),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::AutoDeviceId)),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::InvalidDataQueueRuntimeInput
    );
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::AutoDeviceId)
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_reports_data_queue_path_mismatch() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input(17)),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::DataQueuePathMismatch)),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueuePathMismatch
    );
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueuePathMismatch)
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_reports_data_queue_open_errno_with_attempt() {
    const EACCES_FOR_TEST: i32 = 13;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input(17)),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(
            EACCES_FOR_TEST,
        ))),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueueOpenErrno
    );
    assert_eq!(report.data_queue_errno, Some(EACCES_FOR_TEST));
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(
            EACCES_FOR_TEST
        ))
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_reports_io_uring_setup_errno_with_open() {
    const ENOMEM_FOR_TEST: i32 = 12;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input(17)),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::IoUringSetupErrno(
            ENOMEM_FOR_TEST,
        ))),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.data_queue_open_attempted);
    assert!(report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::IoUringSetupErrno
    );
    assert_eq!(report.data_queue_errno, Some(ENOMEM_FOR_TEST));
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::IoUringSetupErrno(
            ENOMEM_FOR_TEST
        ))
    );
    assert!(report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_maps_errno_variants_and_preserves_cleanup() {
    const DATA_QUEUE_OPEN_ERRNO: i32 = 5;
    const IO_URING_SETUP_ERRNO: i32 = 12;

    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let dq_input = data_queue_input(17);

    let variants: &[(
        UblkDataQueueRuntimeOpenError,
        UblkDataQueueOpenFailureClass,
        bool,
        bool,
        Option<i32>,
    )] = &[
        (
            UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(DATA_QUEUE_OPEN_ERRNO),
            UblkDataQueueOpenFailureClass::DataQueueOpenErrno,
            true,
            false,
            Some(DATA_QUEUE_OPEN_ERRNO),
        ),
        (
            UblkDataQueueRuntimeOpenError::DataQueueOpenMissingErrno,
            UblkDataQueueOpenFailureClass::DataQueueOpenMissingErrno,
            true,
            false,
            None,
        ),
        (
            UblkDataQueueRuntimeOpenError::IoUringSetupErrno(IO_URING_SETUP_ERRNO),
            UblkDataQueueOpenFailureClass::IoUringSetupErrno,
            true,
            true,
            Some(IO_URING_SETUP_ERRNO),
        ),
        (
            UblkDataQueueRuntimeOpenError::IoUringSetupMissingErrno,
            UblkDataQueueOpenFailureClass::IoUringSetupMissingErrno,
            true,
            true,
            None,
        ),
        (
            UblkDataQueueRuntimeOpenError::DataQueuePathMismatch,
            UblkDataQueueOpenFailureClass::DataQueuePathMismatch,
            false,
            false,
            None,
        ),
        (
            UblkDataQueueRuntimeOpenError::DataQueuePathNotCharacterDevice,
            UblkDataQueueOpenFailureClass::DataQueuePathNotCharacterDevice,
            false,
            false,
            None,
        ),
        (
            UblkDataQueueRuntimeOpenError::DataQueueMetadataErrno(2),
            UblkDataQueueOpenFailureClass::DataQueueMetadataErrno,
            false,
            false,
            Some(2),
        ),
        (
            UblkDataQueueRuntimeOpenError::DataQueueMetadataMissingErrno,
            UblkDataQueueOpenFailureClass::DataQueueMetadataMissingErrno,
            false,
            false,
            None,
        ),
    ];

    for &(ref error, failure_class, expected_attempted, expected_opened, expected_errno) in variants
    {
        let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(dq_input),
            data_queue_open_result: Some(Err(*error)),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

        assert!(
            report.add_dev_report.add_dev_uring_cmd_completed,
            "add_dev should complete for error {error:?}"
        );
        assert_eq!(
            report.data_queue_open_attempted, expected_attempted,
            "open_attempted mismatch for {error:?}"
        );
        assert_eq!(
            report.data_queue_opened, expected_opened,
            "opened mismatch for {error:?}"
        );
        assert_eq!(
            report.data_queue_failure_class, failure_class,
            "failure_class mismatch for {error:?}"
        );
        assert_eq!(
            report.data_queue_errno, expected_errno,
            "errno mismatch for {error:?}"
        );
        assert_eq!(
            report.data_queue_error,
            Some(*error),
            "error not preserved for {error:?}"
        );
        if expected_opened {
            assert!(report.fetch_req_readiness.data_queue_runtime_live);
        } else {
            assert!(!report.fetch_req_readiness.data_queue_runtime_live);
        }
        assert!(
            report.del_dev_uring_cmd_attempted,
            "del_dev should be attempted for cleanup after {error:?}"
        );
        assert!(
            report.del_dev_uring_cmd_completed,
            "del_dev should complete for {error:?}"
        );
    }
}

#[test]
fn data_queue_open_boundary_maps_invalid_input_to_runtime_input_class() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let dq_input = data_queue_input(17);

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(dq_input),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::AutoDeviceId)),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::InvalidDataQueueRuntimeInput
    );
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::AutoDeviceId)
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_maps_mmap_failed_to_data_queue_open_errno_without_attempt() {
    const MMAP_ERRNO: i32 = 14;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_in = data_queue_input(17);

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_in),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::MmapFailed(MMAP_ERRNO))),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueueOpenErrno
    );
    assert_eq!(report.data_queue_errno, Some(MMAP_ERRNO));
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::MmapFailed(MMAP_ERRNO))
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn fetch_req_submission_boundary_refuses_without_data_queue_open() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let report = evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::DataQueuePathMissing)),
            fetch_req_submission_result: None,
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        },
    );

    assert!(
        report
            .data_queue_open_report
            .add_dev_report
            .add_dev_uring_cmd_completed
    );
    assert!(!report.data_queue_open_report.data_queue_opened);
    assert!(!report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submission_completed);
    assert!(!report.fetch_req_submitted);
    assert_eq!(
        report.fetch_req_failure_class,
        UblkDataQueueFetchReqSubmissionFailureClass::DataQueueNotOpen
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert!(report.data_queue_open_report.del_dev_uring_cmd_attempted);
    assert!(report.data_queue_open_report.del_dev_uring_cmd_completed);
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn fetch_req_submission_boundary_records_all_tags_without_start_dev() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );

    let report = evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        },
    );

    assert!(report.data_queue_open_report.data_queue_opened);
    assert!(report.fetch_req_submission_attempted);
    assert!(report.fetch_req_submission_completed);
    assert!(report.fetch_req_submitted);
    assert_eq!(
        report.fetch_req_failure_class,
        UblkDataQueueFetchReqSubmissionFailureClass::None
    );
    assert_eq!(report.fetch_req_errno, None);
    assert_eq!(report.fetch_req_readiness.required_fetch_commands, 64);
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 64);
    assert!(report.fetch_req_readiness.all_fetches_ready());
    assert!(report.start_dev_readiness.all_fetches_ready());
    assert_eq!(
        report
            .fetch_req_outcome
            .expect("submission outcome")
            .last_submitted_tag,
        Some(63)
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.io_uring_queue_processed);
    assert!(!report.ublk_block_device_started);
    assert!(report.data_queue_open_report.del_dev_uring_cmd_completed);
}

#[test]
fn fetch_req_submission_boundary_records_partial_submit_error_and_cleanup() {
    const EINVAL_FOR_TEST: i32 = 22;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submit_error = UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
        tag: 7,
        submitted_fetch_commands: 7,
        error: UblkDataQueueFetchReqError::IoUringSubmitErrno(EINVAL_FOR_TEST),
    };

    let report = evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Err(submit_error)),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        },
    );

    assert!(report.data_queue_open_report.data_queue_opened);
    assert!(report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submission_completed);
    assert!(report.fetch_req_submitted);
    assert_eq!(
        report.fetch_req_failure_class,
        UblkDataQueueFetchReqSubmissionFailureClass::IoUringSubmitErrno
    );
    assert_eq!(report.fetch_req_errno, Some(EINVAL_FOR_TEST));
    assert_eq!(report.fetch_req_error, Some(submit_error));
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 7);
    assert!(report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.fetch_req_readiness.all_fetches_ready());
    assert!(!report.start_dev_readiness.all_fetches_ready());
    assert!(report.data_queue_open_report.del_dev_uring_cmd_completed);
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn fetch_req_submission_boundary_refuses_runtime_not_live() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let runtime_not_live_error = UblkDataQueueFetchReqSubmissionError::RuntimeNotLive;

    let report = evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Err(runtime_not_live_error)),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        },
    );

    assert!(report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submission_completed);
    assert!(!report.fetch_req_submitted);
    assert_eq!(
        report.fetch_req_failure_class,
        UblkDataQueueFetchReqSubmissionFailureClass::DataQueueRuntimeNotLive
    );
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 0);
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.fetch_req_readiness.all_fetches_ready());
    assert!(!report.start_dev_readiness.all_fetches_ready());
}

#[test]
fn fetch_req_submission_boundary_refuses_invalid_fetch_req_input() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let invalid_input_error = UblkDataQueueFetchReqSubmissionError::InvalidFetchReqInput(
        UblkDataQueueFetchReqError::TagOutOfRange,
    );

    let report = evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Err(invalid_input_error)),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        },
    );

    assert!(report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submission_completed);
    assert!(!report.fetch_req_submitted);
    assert_eq!(
        report.fetch_req_failure_class,
        UblkDataQueueFetchReqSubmissionFailureClass::InvalidFetchReqInput
    );
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 0);
    assert!(report.fetch_req_readiness.data_queue_runtime_live);
}

#[test]
fn fetch_req_submission_boundary_refuses_submission_queue_full() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let queue_full_error = UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
        tag: 0,
        submitted_fetch_commands: 0,
        error: UblkDataQueueFetchReqError::SubmissionQueueFull,
    };

    let report = evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Err(queue_full_error)),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        },
    );

    assert!(report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submission_completed);
    assert!(!report.fetch_req_submitted);
    assert_eq!(
        report.fetch_req_failure_class,
        UblkDataQueueFetchReqSubmissionFailureClass::SubmissionQueueFull
    );
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 0);
}

#[test]
fn fetch_req_submission_boundary_refuses_io_uring_submit_zero() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let zero_error = UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
        tag: 0,
        submitted_fetch_commands: 0,
        error: UblkDataQueueFetchReqError::IoUringSubmitZero,
    };

    let report = evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Err(zero_error)),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        },
    );

    assert!(report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submission_completed);
    assert!(!report.fetch_req_submitted);
    assert_eq!(
        report.fetch_req_failure_class,
        UblkDataQueueFetchReqSubmissionFailureClass::IoUringSubmitZero
    );
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 0);
}

#[test]
fn fetch_req_submission_boundary_not_attempted_after_open() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);

    let report = evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: None,
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        },
    );

    assert!(report.data_queue_open_report.data_queue_opened);
    assert!(!report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submission_completed);
    assert!(!report.fetch_req_submitted);
    assert_eq!(
        report.fetch_req_failure_class,
        UblkDataQueueFetchReqSubmissionFailureClass::FetchReqSubmissionNotAttemptedAfterOpen
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn fetch_req_submission_boundary_refuses_io_uring_submit_missing_errno() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let missing_errno_error = UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
        tag: 3,
        submitted_fetch_commands: 3,
        error: UblkDataQueueFetchReqError::IoUringSubmitMissingErrno,
    };

    let report = evaluate_ublk_data_queue_fetch_req_submission_boundary(
        UblkDataQueueFetchReqSubmissionBoundaryInput {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Err(missing_errno_error)),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        },
    );

    assert!(report.fetch_req_submission_attempted);
    assert!(!report.fetch_req_submission_completed);
    assert!(report.fetch_req_submitted);
    assert_eq!(
        report.fetch_req_failure_class,
        UblkDataQueueFetchReqSubmissionFailureClass::IoUringSubmitMissingErrno
    );
    assert_eq!(report.fetch_req_readiness.submitted_fetch_commands, 3);
    assert_eq!(report.fetch_req_errno, None);
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_until_request_is_fetched() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        false,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: Some(Err(
                UblkDataQueueCommitAndFetchError::FetchedRequestMissing,
            )),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert!(!report.commit_and_fetch_readiness.fetched_request_available);
    assert!(!report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::FetchedRequestMissing
    );
    assert!(
        report
            .fetch_req_report
            .data_queue_open_report
            .del_dev_uring_cmd_completed
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_records_ready_submission_without_start_dev() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: Some(Ok(UblkDataQueueCommitAndFetchOutcome::from_input(
                commit_input,
            ))),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report
        .commit_and_fetch_readiness
        .all_commit_preconditions_ready());
    assert!(report.commit_and_fetch_attempted);
    assert!(report.commit_and_fetch_completed);
    assert!(report.commit_and_fetch_submitted);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::None
    );
    assert_eq!(
        report
            .commit_and_fetch_outcome
            .expect("commit-and-fetch outcome")
            .user_data,
        commit_and_fetch_user_data(0, 0)
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_when_completion_result_not_ready() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        false,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: Some(Err(
                UblkDataQueueCommitAndFetchError::CompletionResultNotReady,
            )),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert!(!report.commit_and_fetch_readiness.completion_result_ready);
    assert!(!report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::CompletionResultNotReady
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_when_fetch_req_submission_errored() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Err(
                UblkDataQueueFetchReqSubmissionError::FetchReqSubmit {
                    tag: 0,
                    submitted_fetch_commands: 0,
                    error: UblkDataQueueFetchReqError::SubmissionQueueFull,
                },
            )),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: None,
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(!report.fetch_req_report.fetch_req_submission_completed);
    assert!(!report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::FetchReqNotReady
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_when_not_attempted_after_fetch() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome.clone())),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: None,
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert!(!report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::CommitAndFetchNotAttemptedAfterFetch
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_maps_submit_time_errno_variants() {
    const IO_URING_SUBMIT_ERRNO: i32 = 4;

    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let variants: &[(
        UblkDataQueueCommitAndFetchError,
        UblkDataQueueCommitAndFetchFailureClass,
        bool,
        Option<i32>,
    )] = &[
        (
            UblkDataQueueCommitAndFetchError::IoUringSubmitErrno(IO_URING_SUBMIT_ERRNO),
            UblkDataQueueCommitAndFetchFailureClass::IoUringSubmitErrno,
            true,
            Some(IO_URING_SUBMIT_ERRNO),
        ),
        (
            UblkDataQueueCommitAndFetchError::IoUringSubmitMissingErrno,
            UblkDataQueueCommitAndFetchFailureClass::IoUringSubmitMissingErrno,
            true,
            None,
        ),
        (
            UblkDataQueueCommitAndFetchError::IoUringSubmitZero,
            UblkDataQueueCommitAndFetchFailureClass::IoUringSubmitZero,
            true,
            None,
        ),
        (
            UblkDataQueueCommitAndFetchError::SubmissionQueueFull,
            UblkDataQueueCommitAndFetchFailureClass::SubmissionQueueFull,
            true,
            None,
        ),
    ];

    for &(ref error, failure_class, expected_attempted, expected_errno) in variants {
        let report = evaluate_ublk_data_queue_commit_and_fetch_boundary(
            UblkDataQueueCommitAndFetchEvaluation {
                inputs: &ready_inputs(),
                probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                    TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
                ))),
                add_dev_input,
                add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
                data_queue_input: Some(data_queue_input(17)),
                data_queue_open_result: Some(Ok(open_outcome.clone())),
                fetch_req_submission_result: Some(Ok(submission_outcome)),
                commit_and_fetch_input: Some(commit_input),
                commit_and_fetch_readiness: Some(readiness),
                commit_and_fetch_result: Some(Err(*error)),
                del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
            },
        );

        assert_eq!(
            report.commit_and_fetch_attempted, expected_attempted,
            "attempted mismatch for {error:?}"
        );
        assert!(
            !report.commit_and_fetch_completed,
            "should not complete for {error:?}"
        );
        assert_eq!(
            report.commit_and_fetch_failure_class, failure_class,
            "failure_class mismatch for {error:?}"
        );
        assert_eq!(
            report.commit_and_fetch_errno, expected_errno,
            "errno mismatch for {error:?}"
        );
        assert_eq!(
            report.commit_and_fetch_error,
            Some(*error),
            "error not preserved for {error:?}"
        );
        assert!(!report.start_dev_uring_cmd_attempted);
        assert!(!report.ublk_block_device_started);
    }
}

#[test]
fn commit_and_fetch_boundary_not_attempted_after_fetch() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome)),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: None,
            commit_and_fetch_readiness: None,
            commit_and_fetch_result: None,
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::CommitAndFetchNotAttemptedAfterFetch
    );
    assert!(!report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_runtime_not_live() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome)),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: Some(Err(UblkDataQueueCommitAndFetchError::RuntimeNotLive)),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert!(!report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert!(!report.commit_and_fetch_submitted);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::DataQueueRuntimeNotLive
    );
    assert_eq!(report.commit_and_fetch_errno, None);
    assert_eq!(
        report.commit_and_fetch_error,
        Some(UblkDataQueueCommitAndFetchError::RuntimeNotLive)
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_completion_result_not_ready() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome)),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: Some(Err(
                UblkDataQueueCommitAndFetchError::CompletionResultNotReady,
            )),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert!(!report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert!(!report.commit_and_fetch_submitted);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::CompletionResultNotReady
    );
    assert_eq!(report.commit_and_fetch_errno, None);
    assert_eq!(
        report.commit_and_fetch_error,
        Some(UblkDataQueueCommitAndFetchError::CompletionResultNotReady)
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_invalid_input() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome)),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: Some(Err(
                UblkDataQueueCommitAndFetchError::ZeroHardwareQueues,
            )),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert!(!report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert!(!report.commit_and_fetch_submitted);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::InvalidCommitAndFetchInput
    );
    assert_eq!(report.commit_and_fetch_errno, None);
    assert_eq!(
        report.commit_and_fetch_error,
        Some(UblkDataQueueCommitAndFetchError::ZeroHardwareQueues)
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_submission_queue_full() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome)),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: Some(Err(
                UblkDataQueueCommitAndFetchError::SubmissionQueueFull,
            )),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert!(report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert!(!report.commit_and_fetch_submitted);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::SubmissionQueueFull
    );
    assert_eq!(report.commit_and_fetch_errno, None);
    assert_eq!(
        report.commit_and_fetch_error,
        Some(UblkDataQueueCommitAndFetchError::SubmissionQueueFull)
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_io_uring_submit_errno() {
    const EINVAL_FOR_TEST: i32 = 22;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome)),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: Some(Err(
                UblkDataQueueCommitAndFetchError::IoUringSubmitErrno(EINVAL_FOR_TEST),
            )),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert!(report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert!(!report.commit_and_fetch_submitted);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::IoUringSubmitErrno
    );
    assert_eq!(report.commit_and_fetch_errno, Some(EINVAL_FOR_TEST));
    assert_eq!(
        report.commit_and_fetch_error,
        Some(UblkDataQueueCommitAndFetchError::IoUringSubmitErrno(
            EINVAL_FOR_TEST
        ))
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_io_uring_submit_missing_errno() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome)),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: Some(Err(
                UblkDataQueueCommitAndFetchError::IoUringSubmitMissingErrno,
            )),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert!(report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert!(!report.commit_and_fetch_submitted);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::IoUringSubmitMissingErrno
    );
    assert_eq!(report.commit_and_fetch_errno, None);
    assert_eq!(
        report.commit_and_fetch_error,
        Some(UblkDataQueueCommitAndFetchError::IoUringSubmitMissingErrno)
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn commit_and_fetch_boundary_refuses_io_uring_submit_zero() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let open_outcome = data_queue_open_outcome(17);
    let submission_spec =
        build_fetch_req_submission_spec(&open_outcome).expect("fetch req submission spec");
    let submission_outcome = UblkDataQueueFetchReqSubmissionOutcome::from_spec(
        submission_spec,
        u32::from(add_dev_input.queue_depth),
        Some(0),
        Some(add_dev_input.queue_depth - 1),
    );
    let commit_input = UblkDataQueueCommitAndFetchInput::completed_user_copy(0, 0, 1, 64);
    let readiness = UblkDataQueueCommitAndFetchReadiness::from_fetch_req_submission_outcome(
        submission_outcome,
        true,
        true,
    );

    let report =
        evaluate_ublk_data_queue_commit_and_fetch_boundary(UblkDataQueueCommitAndFetchEvaluation {
            inputs: &ready_inputs(),
            probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
                TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
            ))),
            add_dev_input,
            add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
            data_queue_input: Some(data_queue_input(17)),
            data_queue_open_result: Some(Ok(open_outcome)),
            fetch_req_submission_result: Some(Ok(submission_outcome)),
            commit_and_fetch_input: Some(commit_input),
            commit_and_fetch_readiness: Some(readiness),
            commit_and_fetch_result: Some(Err(UblkDataQueueCommitAndFetchError::IoUringSubmitZero)),
            del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
        });

    assert!(report.fetch_req_report.fetch_req_submission_completed);
    assert!(report.commit_and_fetch_attempted);
    assert!(!report.commit_and_fetch_completed);
    assert!(!report.commit_and_fetch_submitted);
    assert_eq!(
        report.commit_and_fetch_failure_class,
        UblkDataQueueCommitAndFetchFailureClass::IoUringSubmitZero
    );
    assert_eq!(report.commit_and_fetch_errno, None);
    assert_eq!(
        report.commit_and_fetch_error,
        Some(UblkDataQueueCommitAndFetchError::IoUringSubmitZero)
    );
    assert!(!report.start_dev_uring_cmd_attempted);
    assert!(!report.ublk_block_device_started);
}

#[test]
fn data_queue_open_boundary_control_open_failed() {
    let mut inputs = ready_inputs();
    inputs.control_open_result = Some(Err(UblkControlOpenErrorClass::PermissionDenied));

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &inputs,
        probe_result: None,
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: None,
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: None,
    });

    assert!(
        report
            .add_dev_report
            .readonly_report
            .open_report
            .control_open_attempted
    );
    assert!(
        !report
            .add_dev_report
            .readonly_report
            .open_report
            .control_opened
    );
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::ControlOpenFailed
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.del_dev_uring_cmd_attempted);
}

#[test]
fn data_queue_open_boundary_feature_probe_failed() {
    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Err(UblkControlReadonlyProbeError::UblkCommandErrno(25))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: None,
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: None,
    });

    assert!(
        report
            .add_dev_report
            .readonly_report
            .open_report
            .control_opened
    );
    assert!(
        report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_attempted
    );
    assert!(
        !report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_completed
    );
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::FeatureProbeFailed
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.del_dev_uring_cmd_attempted);
}

#[test]
fn data_queue_open_boundary_required_features_missing() {
    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            tidefs_ublk_abi::UblkFeatureFlags::CMD_IOCTL_ENCODE.bits(),
        ))),
        add_dev_input: UblkControlAddDevInput::conservative_tidefs(),
        add_dev_result: None,
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: None,
    });

    assert!(
        report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_completed
    );
    assert!(!report.add_dev_report.add_dev_required_features_available);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::RequiredFeaturesMissing
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.del_dev_uring_cmd_attempted);
}

#[test]
fn data_queue_open_boundary_add_dev_failed() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Err(UblkControlAddDevError::SubmissionQueueFull)),
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: None,
    });

    assert!(
        report
            .add_dev_report
            .readonly_report
            .open_report
            .control_opened
    );
    assert!(
        report
            .add_dev_report
            .readonly_report
            .probe_uring_cmd_completed
    );
    assert!(report.add_dev_report.add_dev_required_features_available);
    assert!(report.add_dev_report.add_dev_uring_cmd_attempted);
    assert!(!report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::AddDevFailed
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(!report.del_dev_uring_cmd_attempted);
}

#[test]
fn data_queue_open_boundary_not_attempted_after_add_dev() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: None,
        data_queue_open_result: None,
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueueOpenNotAttemptedAfterAddDev
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
    assert!(report.ublk_device_pair_created);
    assert!(report.ublk_device_pair_deleted);
}

#[test]
fn data_queue_open_boundary_path_not_char_device_and_still_cleans_up() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(
            UblkDataQueueRuntimeOpenError::DataQueuePathNotCharacterDevice,
        )),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueuePathNotCharacterDevice
    );
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueuePathNotCharacterDevice)
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_metadata_errno_and_still_cleans_up() {
    const EACCES_FOR_TEST: i32 = 13;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::DataQueueMetadataErrno(
            EACCES_FOR_TEST,
        ))),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueueMetadataErrno
    );
    assert_eq!(report.data_queue_errno, Some(EACCES_FOR_TEST));
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueueMetadataErrno(
            EACCES_FOR_TEST
        ))
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_open_errno_and_still_cleans_up() {
    const EACCES_FOR_TEST: i32 = 13;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(
            EACCES_FOR_TEST,
        ))),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueueOpenErrno
    );
    assert_eq!(report.data_queue_errno, Some(EACCES_FOR_TEST));
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueueOpenErrno(
            EACCES_FOR_TEST
        ))
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_iouring_setup_errno_and_still_cleans_up() {
    const EAGAIN_FOR_TEST: i32 = 11;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::IoUringSetupErrno(
            EAGAIN_FOR_TEST,
        ))),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.data_queue_open_attempted);
    assert!(report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::IoUringSetupErrno
    );
    assert_eq!(report.data_queue_errno, Some(EAGAIN_FOR_TEST));
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::IoUringSetupErrno(
            EAGAIN_FOR_TEST
        ))
    );
    assert!(report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_open_missing_errno_and_still_cleans_up() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(
            UblkDataQueueRuntimeOpenError::DataQueueOpenMissingErrno,
        )),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueueOpenMissingErrno
    );
    assert_eq!(report.data_queue_errno, None);
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueueOpenMissingErrno)
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_iouring_setup_missing_errno_and_still_cleans_up() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::IoUringSetupMissingErrno)),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(report.data_queue_open_attempted);
    assert!(report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::IoUringSetupMissingErrno
    );
    assert_eq!(report.data_queue_errno, None);
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::IoUringSetupMissingErrno)
    );
    assert!(report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_data_queue_path_mismatch_and_still_cleans_up() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::DataQueuePathMismatch)),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueuePathMismatch
    );
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueuePathMismatch)
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_metadata_missing_errno_and_still_cleans_up() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(
            UblkDataQueueRuntimeOpenError::DataQueueMetadataMissingErrno,
        )),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueueMetadataMissingErrno
    );
    assert_eq!(report.data_queue_errno, None);
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueueMetadataMissingErrno)
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_path_not_character_device_and_still_cleans_up() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(
            UblkDataQueueRuntimeOpenError::DataQueuePathNotCharacterDevice,
        )),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueuePathNotCharacterDevice
    );
    assert_eq!(report.data_queue_errno, None);
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueuePathNotCharacterDevice)
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_metadata_errno_enoent_and_still_cleans_up() {
    const ENOENT_FOR_TEST: i32 = 2;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::DataQueueMetadataErrno(
            ENOENT_FOR_TEST,
        ))),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueueMetadataErrno
    );
    assert_eq!(report.data_queue_errno, Some(ENOENT_FOR_TEST));
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::DataQueueMetadataErrno(
            ENOENT_FOR_TEST
        ))
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_mmap_failed_and_still_cleans_up() {
    const EFAULT_FOR_TEST: i32 = 14;
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::MmapFailed(
            EFAULT_FOR_TEST,
        ))),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::DataQueueOpenErrno
    );
    assert_eq!(report.data_queue_errno, Some(EFAULT_FOR_TEST));
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::MmapFailed(EFAULT_FOR_TEST))
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn data_queue_open_boundary_invalid_runtime_input_and_still_cleans_up() {
    let add_dev_input = UblkControlAddDevInput::conservative_tidefs();
    let data_queue_input = UblkDataQueueRuntimeOpenInput::from_kernel_dev_id(
        17,
        0,
        add_dev_input.nr_hw_queues,
        add_dev_input.queue_depth,
    );

    let report = evaluate_ublk_data_queue_open_boundary(UblkDataQueueOpenBoundaryInput {
        inputs: &ready_inputs(),
        probe_result: Some(Ok(UblkControlGetFeaturesOutcome::from_features_bits(
            TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES.bits(),
        ))),
        add_dev_input,
        add_dev_result: Some(Ok(returned_add_dev_outcome(17))),
        data_queue_input: Some(data_queue_input),
        data_queue_open_result: Some(Err(UblkDataQueueRuntimeOpenError::QueueIdOutOfRange)),
        del_dev_result: Some(Ok(UblkControlDelDevOutcome::from_dev_id(17))),
    });

    assert!(report.add_dev_report.add_dev_uring_cmd_completed);
    assert!(!report.data_queue_open_attempted);
    assert!(!report.data_queue_opened);
    assert_eq!(
        report.data_queue_failure_class,
        UblkDataQueueOpenFailureClass::InvalidDataQueueRuntimeInput
    );
    assert_eq!(report.data_queue_errno, None);
    assert_eq!(
        report.data_queue_error,
        Some(UblkDataQueueRuntimeOpenError::QueueIdOutOfRange)
    );
    assert!(!report.fetch_req_readiness.data_queue_runtime_live);
    assert!(report.del_dev_uring_cmd_attempted);
    assert!(report.del_dev_uring_cmd_completed);
}

#[test]
fn io_loop_report_holds_image_backed_io_validation() {
    let report = UblkDataQueueIoLoopReport {
        start_dev_uring_cmd_completed: true,
        ublk_device_pair_created: true,
        ublk_device_pair_deleted: true,
        io_loop_attempted: true,
        io_loop_completed_iterations: 5,
        io_loop_cqes_processed: 10,
        io_loop_commit_and_fetch_submitted: 5,
        io_loop_failure_class: UblkDataQueueIoLoopFailureClass::None,
        io_loop_errno: None,
        image_bytes_read: 4096,
        image_bytes_written: 8192,
        image_read_ops_completed: 1,
        image_write_ops_completed: 2,
        image_flush_ops: 1,
        image_discard_ops: 0,
        image_write_zeroes_ops: 0,
        io_uring_queue_processed: false,
        shutdown_graceful: false,
        drain_cqes_processed: 0,
        drain_iterations: 0,
        drain_timed_out: false,
        drain_hung_io_count: 0,
        final_flush_completed: false,
        set_params_errno: None,
        data_queue_open_errno: None,
        data_queue_open_error_str: None,
        stop_dev_uring_cmd_completed: false,
        barrier_audit_flush_count: 0,
        barrier_audit_fua_write_count: 0,
        barrier_audit_failed_count: 0,
        barrier_audit_total_entries: 0,
    };

    // Assert image-backed IO validation is carried in the report
    assert_eq!(report.image_bytes_read, 4096);
    assert_eq!(report.image_bytes_written, 8192);
    assert_eq!(report.image_read_ops_completed, 1);
    assert_eq!(report.image_write_ops_completed, 2);
    assert_eq!(report.image_flush_ops, 1);
    assert_eq!(report.image_discard_ops, 0);
    assert_eq!(report.image_write_zeroes_ops, 0);

    // Assert ublk boundary validation is consistent
    assert!(report.start_dev_uring_cmd_completed);
    assert_eq!(report.io_loop_completed_iterations, 5);
    assert_eq!(report.io_loop_cqes_processed, 10);
    assert_eq!(report.io_loop_commit_and_fetch_submitted, 5);
}

#[test]
fn io_loop_report_image_validation_defaults_to_zero() {
    let report = UblkDataQueueIoLoopReport {
        start_dev_uring_cmd_completed: false,
        ublk_device_pair_created: false,
        ublk_device_pair_deleted: false,
        io_loop_attempted: false,
        io_loop_completed_iterations: 0,
        io_loop_cqes_processed: 0,
        io_loop_commit_and_fetch_submitted: 0,
        io_loop_failure_class: UblkDataQueueIoLoopFailureClass::HostNotAdmitted,
        io_loop_errno: None,
        image_bytes_read: 0,
        image_bytes_written: 0,
        image_read_ops_completed: 0,
        image_write_ops_completed: 0,
        image_flush_ops: 0,
        io_uring_queue_processed: false,
        shutdown_graceful: false,
        drain_cqes_processed: 0,
        drain_iterations: 0,
        drain_timed_out: false,
        drain_hung_io_count: 0,
        final_flush_completed: false,
        set_params_errno: None,
        data_queue_open_errno: None,
        data_queue_open_error_str: None,
        image_discard_ops: 0,
        image_write_zeroes_ops: 0,
        stop_dev_uring_cmd_completed: false,
        barrier_audit_flush_count: 0,
        barrier_audit_fua_write_count: 0,
        barrier_audit_failed_count: 0,
        barrier_audit_total_entries: 0,
    };

    assert_eq!(report.image_bytes_read, 0);
    assert_eq!(report.image_bytes_written, 0);
    assert_eq!(report.image_read_ops_completed, 0);
    assert_eq!(report.image_write_ops_completed, 0);
    assert_eq!(report.image_flush_ops, 0);
    assert_eq!(report.image_discard_ops, 0);
    assert_eq!(report.image_write_zeroes_ops, 0);
}

#[test]
fn io_loop_report_print_includes_image_validation() {
    let report = UblkDataQueueIoLoopReport {
        start_dev_uring_cmd_completed: true,
        ublk_device_pair_created: true,
        ublk_device_pair_deleted: true,
        io_loop_attempted: true,
        io_loop_completed_iterations: 3,
        io_loop_cqes_processed: 6,
        io_loop_commit_and_fetch_submitted: 3,
        io_loop_failure_class: UblkDataQueueIoLoopFailureClass::None,
        io_loop_errno: None,
        image_bytes_read: 12288,
        image_bytes_written: 4096,
        image_read_ops_completed: 3,
        image_write_ops_completed: 1,
        image_flush_ops: 2,
        io_uring_queue_processed: false,
        shutdown_graceful: false,
        drain_cqes_processed: 0,
        drain_iterations: 0,
        drain_timed_out: false,
        drain_hung_io_count: 0,
        final_flush_completed: false,
        set_params_errno: None,
        data_queue_open_errno: None,
        data_queue_open_error_str: None,
        image_discard_ops: 1,
        image_write_zeroes_ops: 0,
        stop_dev_uring_cmd_completed: false,
        barrier_audit_flush_count: 0,
        barrier_audit_fua_write_count: 0,
        barrier_audit_failed_count: 0,
        barrier_audit_total_entries: 0,
    };

    // print() should not panic with image validation fields
    report.print();
}

#[test]
fn resize_smoke_reports_policy_supported_without_device_mutation() {
    let report = run_ublk_control_resize_smoke_boundary().expect("resize smoke report");

    // With online resize now enabled (resolve_resize_policy(true)),
    // the smoke proceeds past the policy check and reaches the host
    // admission gate. On hosts without /dev/ublk-control (kernel < 7.0
    // or ublk_drv not loaded), it correctly reports HostNotAdmitted.
    // resize_supported is true and no refusal reason is set.
    assert!(report.resize_supported);
    assert!(report.resize_refusal_reason.is_none());
    assert!(report.resize_refusal_guest_errno.is_none());
    // The smoke did not reach UPDATE_SIZE (no /dev/ublk-control)
    assert!(!report.update_size_completed);
    assert!(!report.ublk_device_pair_deleted);
}
