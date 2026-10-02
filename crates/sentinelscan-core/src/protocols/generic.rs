use std::future::Future;
use std::pin::Pin;

use crate::detection::service::{Detection, ServiceDetector};
use crate::detection::ActiveCtx;

/// Last resort. Never claims a service; records why nothing else matched.
pub struct GenericDetector;

impl ServiceDetector for GenericDetector {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn match_banner(&self, _banner: &[u8], _port: u16) -> Option<Detection> {
        None
    }

    fn probe<'a>(
        &'a self,
        ctx: &'a ActiveCtx,
    ) -> Pin<Box<dyn Future<Output = Option<Detection>> + Send + 'a>> {
        let _ = ctx;
        Box::pin(async move {
            Some(Detection::unknown(
                "no detector matched the banner or probes",
            ))
        })
    }
}
