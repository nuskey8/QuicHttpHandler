use crate::client::OriginKey;
use crate::qlog::{QlogCallbackWriter, QlogSettings};
use boring::{
    pkey::PKey,
    ssl::{SslAlert, SslContextBuilder, SslMethod, SslVerifyError, SslVerifyMode},
    x509::{store::X509StoreBuilder, X509StoreContext, X509},
};
use std::{
    collections::hash_map::DefaultHasher,
    ffi::c_void,
    hash::{Hash, Hasher},
    io::Write,
    sync::Arc,
};
use tokio_quiche::{quic::ConnectionHook, settings::TlsCertificatePaths};

#[derive(Clone, Default)]
pub(super) struct TlsSettings {
    pub(super) identity: u64,
    pub(super) skip_verification: bool,
    pub(super) custom_verify: bool,
    pub(super) replace_default_roots: bool,
    pub(super) root_certificates: Vec<u8>,
    pub(super) override_server_name: Option<String>,
    pub(super) client_certificates: Vec<u8>,
    pub(super) client_key: Vec<u8>,
    pub(super) verify_state: usize,
    pub(super) verify_callback: Option<
        extern "C" fn(
            *mut c_void,
            *const u8,
            usize,
            *const u8,
            usize,
            *const u8,
            usize,
            u8,
            i32,
            i64,
        ) -> u8,
    >,
}
pub(super) struct TlsHook {
    pub(super) settings: Arc<TlsSettings>,
    pub(super) server_name: String,
    pub(super) qlog: Option<QlogSettings>,
}

pub(super) fn compute_tls_identity(settings: &TlsSettings) -> u64 {
    let mut hash = DefaultHasher::new();
    settings.skip_verification.hash(&mut hash);
    settings.custom_verify.hash(&mut hash);
    settings.replace_default_roots.hash(&mut hash);
    settings.root_certificates.hash(&mut hash);
    settings.override_server_name.hash(&mut hash);
    settings.client_certificates.hash(&mut hash);
    settings.client_key.hash(&mut hash);
    settings.verify_state.hash(&mut hash);
    settings
        .verify_callback
        .map(|callback| callback as usize)
        .hash(&mut hash);
    hash.finish()
}

pub(super) fn origin_key(host: &str, port: u16, tls: &TlsSettings) -> OriginKey {
    OriginKey {
        host: host.to_owned(),
        port,
        server_name: tls
            .override_server_name
            .clone()
            .unwrap_or_else(|| host.to_owned()),
        tls_identity: if tls.identity == 0 {
            compute_tls_identity(tls)
        } else {
            tls.identity
        },
    }
}

impl ConnectionHook for TlsHook {
    fn create_custom_ssl_context_builder(
        &self,
        _: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        let mut builder = SslContextBuilder::new(SslMethod::tls_client()).ok()?;
        let mut roots = X509StoreBuilder::new().ok()?;

        // Use platform roots where available, plus a compiled Mozilla bundle so
        // Unity mobile players don't depend on OpenSSL-style filesystem paths.
        if !self.settings.replace_default_roots {
            let _ = roots.set_default_paths();
            for certificate in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
                if let Ok(certificate) = X509::from_der(certificate.as_ref()) {
                    let _ = roots.add_cert(certificate);
                }
            }
        }

        if !self.settings.root_certificates.is_empty() {
            for certificate in X509::stack_from_pem(&self.settings.root_certificates).ok()? {
                roots.add_cert(certificate).ok()?;
            }
        }
        builder.set_cert_store_builder(roots);

        if !self.settings.client_certificates.is_empty() || !self.settings.client_key.is_empty() {
            let mut certificates = X509::stack_from_pem(&self.settings.client_certificates).ok()?;
            if certificates.is_empty() {
                return None;
            }

            let leaf = certificates.remove(0);
            builder.set_certificate(&leaf).ok()?;
            for certificate in certificates {
                builder.add_extra_chain_cert(certificate).ok()?;
            }

            let key = PKey::private_key_from_pem(&self.settings.client_key).ok()?;
            builder.set_private_key(&key).ok()?;
            builder.check_private_key().ok()?;
        }

        if self.settings.skip_verification {
            builder.set_verify(SslVerifyMode::NONE);
        } else if self.settings.custom_verify {
            let callback = self.settings.verify_callback?;
            let callback_state = self.settings.verify_state;
            let server_name = self.server_name.clone();

            builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                let peer_certificate = ssl.peer_certificate();
                let certificate = peer_certificate
                    .as_ref()
                    .and_then(|value| value.to_der().ok());
                let Some(certificate) = certificate else {
                    return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
                };
                let Some(peer_chain) = ssl.peer_cert_chain() else {
                    return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
                };
                let store = ssl.ssl_context().cert_store();
                let mut standard_error = 0;
                let standard_ok = X509StoreContext::new()
                    .and_then(|mut store_context| {
                        store_context.init(
                            store,
                            peer_certificate.as_ref().unwrap(),
                            peer_chain,
                            |context| {
                                context.verify_param_mut().set_host(&server_name)?;
                                let verified = context.verify_cert()?;
                                if let Err(error) = context.verify_result() {
                                    standard_error = error.as_raw();
                                }
                                Ok(verified)
                            },
                        )
                    })
                    .unwrap_or(false);
                let mut encoded_chain = Vec::new();
                for item in peer_chain {
                    let Ok(der) = item.to_der() else {
                        return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
                    };
                    let Ok(length) = u32::try_from(der.len()) else {
                        return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
                    };
                    encoded_chain.extend_from_slice(&length.to_le_bytes());
                    encoded_chain.extend_from_slice(&der);
                }

                let verification_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |value| {
                        i64::try_from(value.as_millis()).unwrap_or(i64::MAX)
                    });

                if callback(
                    callback_state as *mut c_void,
                    server_name.as_ptr(),
                    server_name.len(),
                    certificate.as_ptr(),
                    certificate.len(),
                    encoded_chain.as_ptr(),
                    encoded_chain.len(),
                    u8::from(standard_ok),
                    standard_error,
                    verification_time,
                ) != 0
                {
                    Ok(())
                } else {
                    Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))
                }
            });
        } else {
            builder.set_verify(SslVerifyMode::PEER);
        }
        Some(builder)
    }

    fn create_qlog_writer(&self, connection_id: &str) -> Option<Box<dyn Write + Send + Sync>> {
        let settings = self.qlog.clone()?;
        Some(Box::new(QlogCallbackWriter {
            settings,
            connection_id: Arc::from(connection_id.as_bytes()),
            pending: Vec::with_capacity(4096),
            enabled: true,
        }))
    }
}
