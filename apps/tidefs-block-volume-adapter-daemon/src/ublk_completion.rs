use tidefs_ublk_abi::{UblkSrvIoCmd, UBLK_IO_RES_OK};

/// Convert an io_uring completion result into a ublk I/O command result.
///
/// Successful operations map to `UBLK_IO_RES_OK`; dispatcher errors carry the
/// kernel errno as a negative result.
pub fn ublk_result_from_completion(
    completion: &crate::ublk_io_uring::UblkIoCompletionResult,
) -> i32 {
    match completion {
        crate::ublk_io_uring::UblkIoCompletionResult::Read { .. }
        | crate::ublk_io_uring::UblkIoCompletionResult::Write { .. }
        | crate::ublk_io_uring::UblkIoCompletionResult::Flush { .. }
        | crate::ublk_io_uring::UblkIoCompletionResult::Discard { .. }
        | crate::ublk_io_uring::UblkIoCompletionResult::WriteZeroes { .. } => UBLK_IO_RES_OK,
        crate::ublk_io_uring::UblkIoCompletionResult::Error { errno, .. } => -errno,
    }
}

/// Reap all available completions from the dispatcher and convert them to ublk
/// `UblkSrvIoCmd` results for a given queue.
pub fn reap_ublk_completions(
    dispatcher: &mut crate::ublk_io_uring::UblkIoUringDispatcher,
    queue_id: u16,
) -> Vec<UblkSrvIoCmd> {
    dispatcher
        .reap_completions()
        .into_iter()
        .map(|completion| {
            let tag = completion.tag();
            let result = ublk_result_from_completion(&completion);
            UblkSrvIoCmd {
                q_id: queue_id,
                tag: (tag & 0xFFFF) as u16,
                result,
                addr_or_zone_append_lba: 0,
            }
        })
        .collect()
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use tempfile::tempfile;

    fn create_tempfile_with_data(data: &[u8]) -> (std::fs::File, std::os::fd::RawFd) {
        let mut f = tempfile().expect("tempfile");
        f.write_all(data).expect("write data");
        f.flush().expect("flush");
        let fd = f.as_raw_fd();
        (f, fd)
    }

    #[test]
    fn ublk_result_maps_ok_to_zero() {
        use crate::ublk_io_uring::UblkIoCompletionResult;
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::Read { tag: 0, bytes: 512 }),
            UBLK_IO_RES_OK
        );
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::Write {
                tag: 1,
                bytes: 1024
            }),
            UBLK_IO_RES_OK
        );
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::Flush { tag: 2 }),
            UBLK_IO_RES_OK
        );
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::Discard { tag: 3 }),
            UBLK_IO_RES_OK
        );
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::WriteZeroes { tag: 4 }),
            UBLK_IO_RES_OK
        );
    }

    #[test]
    fn ublk_result_maps_error_to_negative_errno() {
        use crate::ublk_io_uring::UblkIoCompletionResult;
        assert_eq!(
            ublk_result_from_completion(&UblkIoCompletionResult::Error { tag: 0, errno: 5 }),
            -5
        );
    }

    #[test]
    fn reap_ublk_completions_integrates_with_dispatcher() {
        use crate::ublk_io_uring::UblkIoUringDispatcher;

        let data = vec![0u8; 8192];
        let (_f, fd) = create_tempfile_with_data(&data);
        let mut dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");

        let payload: Vec<u8> = (0..512u16).map(|i| i as u8).collect();
        dispatcher.write_at(0, &payload).expect("write_at");
        dispatcher.flush().expect("flush");

        let cmds = reap_ublk_completions(&mut dispatcher, 0);
        let _ = cmds;

        let mut read_buf = vec![0u8; 512];
        dispatcher.submit_write(0, &payload).expect("submit_write");
        dispatcher.submit_flush().expect("submit_flush");
        dispatcher
            .submit_read(0, &mut read_buf)
            .expect("submit_read");

        dispatcher.submit_and_wait(3).expect("submit_and_wait");

        let cmds = reap_ublk_completions(&mut dispatcher, 1);
        assert_eq!(cmds.len(), 3, "expected 3 completion cmds, got {cmds:?}");
        for cmd in &cmds {
            assert_eq!(cmd.q_id, 1);
            assert_eq!(cmd.result, UBLK_IO_RES_OK);
        }
        assert_eq!(&read_buf[..], &payload[..]);
    }
}
