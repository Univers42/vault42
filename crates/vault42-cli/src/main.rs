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

//! vault42 — the zero-knowledge CLI (the primary surface). ALL plaintext crypto
//! happens here, on the client; only ciphertext ever leaves the machine. P0 is a
//! stub; the verb surface (init / set / get / share / rotate / ...) is wired from
//! P6 onward over gRPC.

use std::process::ExitCode;

/// Entry point for the `vault42` binary. P0 prints the version; the clap-driven
/// verb surface arrives in P6.
fn main() -> ExitCode {
    println!("vault42 {} — CLI verbs land in P6", vault42_core::VERSION);
    ExitCode::SUCCESS
}
