/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   build.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Build script: compile the protobuf contracts into Rust (tonic client + server)
//! using a vendored `protoc`, so no system protoc is required (Docker-first).

/// Compile `contracts/{vault,authz}/v1/*.proto` into client + server stubs.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(
            &["vault/v1/vault.proto", "authz/v1/authz.proto"],
            &["../../contracts"],
        )?;
    println!("cargo:rerun-if-changed=../../contracts");
    Ok(())
}
