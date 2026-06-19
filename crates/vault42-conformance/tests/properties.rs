/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   properties.rs                                        :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! Property battery for the zero-knowledge envelope (the v01/v02 gate properties at
//! the `proptest` level): for ALL plaintexts the roundtrip holds; ANY single-bit
//! tamper of the ciphertext fails the open; and a non-recipient can NEVER open.
//! Cheap key generation per case keeps the suite fast; 64 cases is enough signal.

use proptest::prelude::*;
use vault42_core::{open, seal, Identity, Metadata, ReadScope, Recipients};

fn metadata(rev: u64) -> Metadata {
    Metadata {
        version: 1,
        secret_id: "secret".into(),
        tenant: "tenant".into(),
        owner: "api-key:abc".into(),
        rev,
        content_type: "env".into(),
        recovery_optin: false,
    }
}

fn scope() -> ReadScope<'static> {
    ReadScope {
        secret_id: "secret",
        min_rev: 0,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn roundtrip_recovers_any_plaintext(plaintext in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let alice = Identity::generate();
        let author = Identity::generate();
        let users = [alice.encryption_public()];
        let recipients = Recipients { users: &users, recovery: None };
        let env = seal(&plaintext, metadata(1), &recipients, author.signing_key()).expect("seal");
        let pt = open(&env, alice.encryption_secret(), &author.author_public(), &scope()).expect("open");
        prop_assert_eq!(&pt[..], &plaintext[..]);
    }

    #[test]
    fn any_ciphertext_bitflip_fails(
        plaintext in proptest::collection::vec(any::<u8>(), 1..1024),
        bit in 0u32..8,
    ) {
        let alice = Identity::generate();
        let author = Identity::generate();
        let users = [alice.encryption_public()];
        let recipients = Recipients { users: &users, recovery: None };
        let mut env = seal(&plaintext, metadata(1), &recipients, author.signing_key()).expect("seal");
        let index = (bit as usize) % env.ciphertext.len();
        env.ciphertext[index] ^= 1 << (bit % 8);
        prop_assert!(open(&env, alice.encryption_secret(), &author.author_public(), &scope()).is_err());
    }

    #[test]
    fn non_recipient_never_opens(plaintext in proptest::collection::vec(any::<u8>(), 0..512)) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let author = Identity::generate();
        let users = [alice.encryption_public()];
        let recipients = Recipients { users: &users, recovery: None };
        let env = seal(&plaintext, metadata(1), &recipients, author.signing_key()).expect("seal");
        prop_assert!(open(&env, bob.encryption_secret(), &author.author_public(), &scope()).is_err());
    }
}
