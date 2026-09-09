/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   framing.rs                                           :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The canonical length-framing primitive.
//!
//! One definition, used by every canonical message this crate defines. Framing exists so a
//! signed message is INJECTIVE: with each field's length written before its bytes, no choice
//! of values can shift bytes across a field boundary, so two distinct field tuples can never
//! produce the same message.
//!
//! It lives here rather than beside its callers because a second copy is the failure mode.
//! Two copies of a framing rule stay internally consistent while silently ceasing to agree
//! with each other, and the symptom is signatures that verify on one side and not the other.

/// Append one length-prefixed field: `<decimal len> ':' <value> '\n'`.
pub(crate) fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
    out.push(b'\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_is_injective_across_field_boundaries() {
        let mut ab = Vec::new();
        frame(&mut ab, b"a");
        frame(&mut ab, b"bc");
        let mut abc = Vec::new();
        frame(&mut abc, b"ab");
        frame(&mut abc, b"c");
        assert_ne!(ab, abc, "a bare concatenation would make these equal");
    }

    #[test]
    fn an_empty_field_is_still_framed() {
        let mut out = Vec::new();
        frame(&mut out, b"");
        assert_eq!(out, b"0:\n");
    }
}
