use super::*;

pub fn run_ublk_control_open_preflight() -> Result<UblkControlOpenReport, AppError> {
    let mut inputs = UblkControlOpenInputs::read_host()?;
    if inputs.should_attempt_control_open() {
        inputs.control_open_result = Some(open_control_device(&inputs.control_path));
    }
    Ok(evaluate_ublk_control_open_preflight(&inputs))
}
pub(crate) fn evaluate_ublk_control_open_preflight(
    inputs: &UblkControlOpenInputs,
) -> UblkControlOpenReport {
    let kernel_class = classify_kernel_release_str(&inputs.kernel_release);
    let degraded_missing_sysfs_mirror =
        !inputs.sys_module_ublk_drv_present || !inputs.sys_class_ublk_char_present;

    let preliminary_refusal = if kernel_class != HostKernelClass::Linux700OrNewer {
        Some(UblkControlOpenRefusalClass::KernelBelowLinux700)
    } else if !inputs.control_path_present {
        Some(UblkControlOpenRefusalClass::MissingUblkControl)
    } else if !inputs.control_path_is_char_device {
        Some(UblkControlOpenRefusalClass::UblkControlNotCharacterDevice)
    } else {
        None
    };

    let (admission_class, refusal_class, control_open_attempted, control_opened, open_error_class) =
        if let Some(refusal_class) = preliminary_refusal {
            (
                UblkControlOpenAdmissionClass::Refused,
                refusal_class,
                false,
                false,
                None,
            )
        } else {
            match inputs.control_open_result {
                Some(Ok(())) => {
                    let admission_class = if degraded_missing_sysfs_mirror {
                        UblkControlOpenAdmissionClass::Degraded
                    } else {
                        UblkControlOpenAdmissionClass::Admitted
                    };
                    (
                        admission_class,
                        UblkControlOpenRefusalClass::None,
                        true,
                        true,
                        None,
                    )
                }
                Some(Err(error_class)) => (
                    UblkControlOpenAdmissionClass::Refused,
                    UblkControlOpenRefusalClass::ControlOpenFailed,
                    true,
                    false,
                    Some(error_class),
                ),
                None => (
                    UblkControlOpenAdmissionClass::Refused,
                    UblkControlOpenRefusalClass::ControlOpenNotAttempted,
                    false,
                    false,
                    None,
                ),
            }
        };

    UblkControlOpenReport {
        kernel_release: inputs.kernel_release.clone(),
        kernel_class,
        observe_baseline_satisfied: kernel_class == HostKernelClass::Linux700OrNewer,
        control_path: inputs.control_path.clone(),
        control_path_present: inputs.control_path_present,
        control_path_is_char_device: inputs.control_path_is_char_device,
        sys_module_ublk_drv_present: inputs.sys_module_ublk_drv_present,
        sys_class_ublk_char_present: inputs.sys_class_ublk_char_present,
        sys_class_block_present: inputs.sys_class_block_present,
        degraded_missing_sysfs_mirror,
        admission_class,
        refusal_class,
        control_open_attempted,
        control_opened,
        control_open_error_class: open_error_class,
        read_only_probe_ioctl_issued: false,
        mutating_ioctl_issued: false,
        ublk_device_created: false,
        host_identity: inputs.host_identity,
    }
}
