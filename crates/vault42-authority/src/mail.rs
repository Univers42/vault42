/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   mail.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Delivering a one-time code, and the seam that lets a test read one without a mailbox.
//!
//! Two transports, chosen by configuration. `Smtp` is the production path and talks to Titan.
//! `File` renders exactly the same message and writes it into a directory, so a battery driving
//! a real authority over HTTP can read the code out of process. Both go through `deliver`, so
//! the rendered message cannot drift between what a test reads and what a person receives.
//!
//! There is deliberately no transport that writes a code to stdout or the log. "A code never
//! appears in a log line" is a property worth keeping true, and a logging transport would make
//! it false on purpose. Failures are logged; the code inside them never is.
//!
//! The default is SMTP, so a missing or misspelt `MAIL_TRANSPORT` cannot silently divert real
//! mail into a directory. The authority also refuses to start with second factors enabled and
//! no usable transport, because an authority that accepts a code request it cannot deliver looks
//! healthy while locking every account out.

use crate::config::{MailConfig, MailTransport};
use crate::error::{Error, Result};

/// One rendered message, ready for whichever transport carries it.
pub struct Message {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Render the message that carries `code` to `to`.
///
/// The code is in the body and nowhere else — not the subject, which mail clients show in
/// notifications and previews on a locked screen.
pub fn code_message(to: &str, code: &str, ttl_secs: i64) -> Message {
    let minutes = (ttl_secs / 60).max(1);
    Message {
        to: to.to_string(),
        subject: "Your vault42 sign-in code".to_string(),
        body: format!(
            "Your vault42 sign-in code is {code}\n\n\
             It is valid for {minutes} minutes and can be used once.\n\
             If you did not try to sign in, you can ignore this message.\n"
        ),
    }
}

/// Hand `message` to the configured transport.
pub fn deliver(mail: &MailConfig, message: &Message) -> Result<()> {
    match &mail.transport {
        MailTransport::File(dir) => write_to_outbox(dir, mail, message),
        MailTransport::Smtp => send_over_smtp(mail, message),
    }
}

/// Write the rendered message into the outbox directory as one file.
///
/// The filename carries the recipient and a monotonic-enough timestamp so a test can find the
/// newest message for an address, and so two codes in the same second do not overwrite one
/// another. `RFC 822`-ish headers keep it readable by a person and trivially parseable by a test.
fn write_to_outbox(dir: &str, mail: &MailConfig, message: &Message) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| Error::Internal(e.into()))?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let path = std::path::Path::new(dir).join(format!("{}-{stamp}.eml", safe_name(&message.to)));
    let rendered = format!(
        "From: {}\nTo: {}\nSubject: {}\n\n{}",
        mail.from, message.to, message.subject, message.body
    );
    std::fs::write(path, rendered).map_err(|e| Error::Internal(e.into()))
}

/// Reduce an address to characters that are safe in a filename on any platform.
fn safe_name(address: &str) -> String {
    address
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Send over implicit TLS to the configured SMTP host.
///
/// Port 465 is implicit TLS from the first byte, so `relay` is built with a TLS wrapper rather
/// than STARTTLS: an upgrade a network attacker can strip is not a transport for a login code.
/// The password is read from the configuration and never logged, and a failure reports only that
/// delivery failed — an SMTP rejection can echo the recipient back, and that would make an error
/// body an address oracle.
fn send_over_smtp(mail: &MailConfig, message: &Message) -> Result<()> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message as Email, SmtpTransport, Transport};

    let password = mail
        .password
        .clone()
        .ok_or_else(|| Error::Internal(anyhow::anyhow!("no mail credential configured")))?;
    let email = Email::builder()
        .from(
            mail.from
                .parse()
                .map_err(|_| Error::Internal(anyhow::anyhow!("MAIL_FROM is not an address")))?,
        )
        .to(message
            .to
            .parse()
            .map_err(|_| Error::BadRequest("not a deliverable address".into()))?)
        .subject(&message.subject)
        .body(message.body.clone())
        .map_err(|e| Error::Internal(e.into()))?;
    let relay = SmtpTransport::relay(&mail.host)
        .map_err(|e| Error::Internal(e.into()))?
        .port(mail.port)
        .credentials(Credentials::new(mail.from.clone(), password))
        .build();
    relay.send(&email).map(|_| ()).map_err(|error| {
        tracing::warn!(host = %mail.host, "one-time code delivery failed");
        Error::Internal(anyhow::anyhow!(
            "code delivery failed: {}",
            error.is_transient()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The code is in the body and never in the subject, which is what a locked screen shows.
    #[test]
    fn the_subject_never_carries_the_code() {
        let message = code_message("dev@archicode.codes", "123456", 300);
        assert!(!message.subject.contains("123456"));
        assert!(message.body.contains("123456"));
        assert!(message.body.contains("5 minutes"));
    }

    /// A very short window still reads as at least one minute rather than "0 minutes".
    #[test]
    fn the_stated_window_is_never_zero() {
        assert!(code_message("a@b.co", "1", 30).body.contains("1 minutes"));
    }

    /// The file transport writes a readable message whose body carries the code, so a battery
    /// can take a code out of process without a mailbox.
    #[test]
    fn the_file_transport_writes_a_message_a_test_can_read() {
        let dir = std::env::temp_dir().join(format!("vault42-outbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mail = MailConfig {
            transport: MailTransport::File(dir.display().to_string()),
            from: "devfast@archicode.codes".into(),
            host: String::new(),
            port: 0,
            password: None,
        };
        deliver(&mail, &code_message("dev@archicode.codes", "424242", 300)).expect("deliver");
        let written: Vec<_> = std::fs::read_dir(&dir)
            .expect("outbox")
            .filter_map(|entry| entry.ok())
            .map(|entry| std::fs::read_to_string(entry.path()).expect("read"))
            .collect();
        assert_eq!(written.len(), 1, "one file per delivery");
        assert!(written[0].contains("424242"), "the code is readable");
        assert!(written[0].contains("To: dev@archicode.codes"));
        assert!(written[0].contains("From: devfast@archicode.codes"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A path-hostile address cannot escape the outbox directory it was given.
    #[test]
    fn an_address_cannot_steer_the_written_path() {
        assert_eq!(safe_name("../../etc/passwd"), "______etc_passwd");
        assert_eq!(safe_name("dev@archicode.codes"), "dev_archicode_codes");
        assert!(!safe_name("a/b").contains('/'));
    }
}
