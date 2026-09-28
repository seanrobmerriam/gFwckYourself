#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(env!("CARGO_PKG_NAME"), "gfwck");
    }
}
