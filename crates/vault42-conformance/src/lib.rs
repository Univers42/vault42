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

//! vault42-conformance — the security conformance battery. This library is
//! intentionally minimal; the proptest suites and cargo-fuzz targets live under
//! `tests/` and `fuzz/` and land with P2 (roundtrip, tamper→auth-failure,
//! non-recipient-cannot-unwrap, signature-forgery-rejected, recovery-opt-in gate,
//! and the no-plaintext-in-logs check).
