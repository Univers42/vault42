/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   smoke.rs                                             :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Smoke test proving the workspace and test harness compile and run. The real
//! property/fuzz battery (roundtrip, tamper→auth-failure, zero-knowledge) lands
//! with P2 — this only establishes that the conformance crate links the core.

#[test]
fn core_version_present() {
    assert!(!vault42_core::VERSION.is_empty());
}
