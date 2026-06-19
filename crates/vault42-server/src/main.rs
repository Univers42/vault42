/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   main.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! vault42-server — the public gRPC/HTTPS edge (tonic). A STATELESS orchestrator:
//! it authenticates the caller, authorizes via grobase, stores/serves opaque
//! envelopes, and audits — it never holds plaintext or an unwrapped DEK. P0 is a
//! healthcheck stub; the tonic `Vault` service is wired in P5.

use std::process::ExitCode;

/// Entry point. Recognizes the container `--healthcheck` probe and otherwise
/// reports that the server runtime is not yet implemented.
fn main() -> ExitCode {
    if std::env::args().any(|arg| arg == "--healthcheck") {
        return ExitCode::SUCCESS;
    }
    eprintln!(
        "vault42-server {}: gRPC runtime lands in P5",
        vault42_core::VERSION
    );
    ExitCode::SUCCESS
}
