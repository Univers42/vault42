/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   lib.rs                                               :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! vault42-ssh — the hardened SSH edge (russh). It authenticates a registered SSH
//! public key as a login identity and forwards to the same gRPC core
//! (`ForceCommand`-jailed to vault ops). Auth is TRANSPORT-ONLY: the client
//! keystore unlock still happens locally, so plaintext reveal never occurs
//! server-side even if the SSH host is fully compromised. Wired in P8.

/// The plane label this crate registers as (placeholder until P8).
pub const PLANE: &str = "ssh-edge";
