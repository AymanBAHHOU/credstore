//! Validation for secret names, descriptions and values.

/// Longest secret name accepted.
pub const MAX_NAME_LEN: usize = 128;
/// Longest description accepted.
pub const MAX_DESCRIPTION_LEN: usize = 300;
/// Largest secret value accepted.
pub const MAX_VALUE_LEN: usize = 64 * 1024;

/// Invalid user input. Messages never repeat the input, which might be a secret typed in
/// the wrong place.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    #[error("secret names must match ^[A-Z_][A-Z0-9_]*$ (for example STRIPE_KEY)")]
    BadName,
    #[error("secret names are at most {MAX_NAME_LEN} characters")]
    NameTooLong,
    #[error("descriptions are at most {MAX_DESCRIPTION_LEN} characters")]
    DescriptionTooLong,
    #[error("descriptions cannot contain control characters (they are shown in a terminal)")]
    DescriptionControlChars,
    #[error("the secret value is empty")]
    EmptyValue,
    #[error("secret values are at most {MAX_VALUE_LEN} bytes")]
    ValueTooLong,
    #[error("secret values cannot contain NUL bytes")]
    ValueHasNul,
}

/// `^[A-Z_][A-Z0-9_]*$`, at most [`MAX_NAME_LEN`] characters.
pub fn validate_name(name: &str) -> Result<(), InputError> {
    let mut chars = name.chars();
    let first_ok = matches!(chars.next(), Some('A'..='Z' | '_'));
    if !first_ok || !chars.all(|c| matches!(c, 'A'..='Z' | '0'..='9' | '_')) {
        return Err(InputError::BadName);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(InputError::NameTooLong);
    }
    Ok(())
}

/// Plain text without control characters, at most [`MAX_DESCRIPTION_LEN`] characters.
/// Control characters are refused because descriptions are shown in the approval TUI,
/// where escape sequences could disguise a request.
pub fn validate_description(description: &str) -> Result<(), InputError> {
    if description.chars().count() > MAX_DESCRIPTION_LEN {
        return Err(InputError::DescriptionTooLong);
    }
    if description.chars().any(char::is_control) {
        return Err(InputError::DescriptionControlChars);
    }
    Ok(())
}

/// Non-empty, no NUL (cannot be passed in an environment variable), bounded size.
pub fn validate_value(value: &str) -> Result<(), InputError> {
    if value.is_empty() {
        return Err(InputError::EmptyValue);
    }
    if value.len() > MAX_VALUE_LEN {
        return Err(InputError::ValueTooLong);
    }
    if value.contains('\0') {
        return Err(InputError::ValueHasNul);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["A", "_", "STRIPE_KEY", "_X1", "K9_9", "ABC_DEF_123"] {
            assert_eq!(validate_name(ok), Ok(()), "{ok}");
        }
        for bad in [
            "", "1A", "a", "Stripe", "A-B", "A B", "A.B", "É", "A\n", "A\0", "$A", "A=B",
        ] {
            assert_eq!(validate_name(bad), Err(InputError::BadName), "{bad:?}");
        }
        assert_eq!(validate_name(&"A".repeat(128)), Ok(()));
        assert_eq!(
            validate_name(&"A".repeat(129)),
            Err(InputError::NameTooLong)
        );
    }

    #[test]
    fn descriptions() {
        assert_eq!(validate_description(""), Ok(()));
        assert_eq!(validate_description("Stripe test key, billing API"), Ok(()));
        assert_eq!(validate_description(&"é".repeat(300)), Ok(()));
        assert_eq!(
            validate_description(&"x".repeat(301)),
            Err(InputError::DescriptionTooLong)
        );
        for bad in ["a\nb", "\x1b[2Jfake", "tab\there", "bell\x07", "\u{9b}31m"] {
            assert_eq!(
                validate_description(bad),
                Err(InputError::DescriptionControlChars),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn values() {
        assert_eq!(validate_value("FAKE-SECRET-VALUE-12345"), Ok(()));
        assert_eq!(validate_value("multi\nline"), Ok(()));
        assert_eq!(validate_value(""), Err(InputError::EmptyValue));
        assert_eq!(validate_value("a\0b"), Err(InputError::ValueHasNul));
        assert_eq!(
            validate_value(&"x".repeat(MAX_VALUE_LEN + 1)),
            Err(InputError::ValueTooLong)
        );
    }

    #[test]
    fn errors_do_not_echo_input() {
        let err = validate_name("FAKE-SECRET-VALUE-12345").unwrap_err();
        assert!(!err.to_string().contains("FAKE"));
    }
}
