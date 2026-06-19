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

//! Generated protobuf wire types for vault42 — the typed gRPC spine. `vault.v1` is
//! the user/operator surface; `authz.v1` is the policy surface. The Rust is emitted
//! at build time by `build.rs` (tonic + prost) and included here. Clippy is held
//! lenient on generated code; the hand-written crates carry the strict lints.

/// The vault user/operator service (Push/Get/Fetch/Ls/Share/Rm/Rotate/…).
pub mod vault {
    pub mod v1 {
        #![allow(clippy::all, clippy::pedantic, clippy::nursery)]
        tonic::include_proto!("vault.v1");
    }
}

/// The authorization service (`Check` → grobase PDP, `Grant` with a TTL lease).
pub mod authz {
    pub mod v1 {
        #![allow(clippy::all, clippy::pedantic, clippy::nursery)]
        tonic::include_proto!("authz.v1");
    }
}
