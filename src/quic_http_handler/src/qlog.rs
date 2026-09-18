use std::{
    ffi::c_void,
    io::{self, Write},
    sync::Arc,
};

#[derive(Clone, Default)]
pub(super) struct QlogSettings {
    pub(super) state: usize,
    pub(super) callback:
        Option<extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> u8>,
}

pub(super) struct QlogCallbackWriter {
    pub(super) settings: QlogSettings,
    pub(super) connection_id: Arc<[u8]>,
    pub(super) pending: Vec<u8>,
    pub(super) enabled: bool,
}

impl QlogCallbackWriter {
    fn emit_records(&mut self, flush: bool) {
        let mut consumed = 0;
        loop {
            let Some(start) = self.pending[consumed..]
                .iter()
                .position(|byte| *byte == 0x1e)
                .map(|index| consumed + index)
            else {
                if flush {
                    consumed = self.pending.len();
                }
                break;
            };

            let end = self.pending[start + 1..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|index| start + 1 + index);

            let Some(end) = end.or_else(|| flush.then_some(self.pending.len())) else {
                consumed = start;
                break;
            };

            if end > start + 1 {
                if let Some(callback) = self.settings.callback {
                    self.enabled = callback(
                        self.settings.state as *mut c_void,
                        self.connection_id.as_ptr(),
                        self.connection_id.len(),
                        self.pending[start + 1..end].as_ptr(),
                        end - start - 1,
                    ) != 0;
                }
            }
            consumed = end.saturating_add(1).min(self.pending.len());
            if !self.enabled {
                self.pending.clear();
                return;
            }
            if consumed == self.pending.len() {
                break;
            }
        }

        if consumed != 0 {
            self.pending.copy_within(consumed.., 0);
            self.pending.truncate(self.pending.len() - consumed);
        }
    }
}

impl Write for QlogCallbackWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.enabled {
            self.pending.extend_from_slice(buffer);
            self.emit_records(false);
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit_records(true);
        Ok(())
    }
}

impl Drop for QlogCallbackWriter {
    fn drop(&mut self) {
        self.emit_records(true);
    }
}
