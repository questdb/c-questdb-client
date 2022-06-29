use crate::F64Serializer;

fn f2s(n: f64) -> String {
    F64Serializer::new(n).to_str().to_owned()
}

#[test]
fn test_f2s_0_0() {
    assert_eq!(f2s(0.0), "0.0");
}

#[test]
fn test_f2s_neg_0_0() {
    assert_eq!(f2s(-0.0), "-0.0");
}

#[test]
fn test_f2s_1_0() {
    assert_eq!(f2s(1.0), "1.0");
}

#[test]
fn test_f2s_neg_1_0() {
    assert_eq!(f2s(-1.0), "-1.0");
}

#[test]
fn test_f2s_10_0() {
    assert_eq!(f2s(10.0), "10.0");
}

#[test]
fn test_f2s_0_1() {
    assert_eq!(f2s(0.1), "0.1");
}

#[test]
fn test_f2s_0_01() {
    assert_eq!(f2s(0.01), "0.01");
}

#[test]
fn test_f2s_0_000001() {
    assert_eq!(f2s(0.000001), "1e-6");
}

#[test]
fn test_f2s_neg_0_000001() {
    assert_eq!(f2s(-0.000001), "-1e-6");
}

#[test]
fn test_f2s_100_0() {
    assert_eq!(f2s(100.0), "100.0");
}

#[test]
fn test_f2s_1_2() {
    assert_eq!(f2s(1.2), "1.2");
}

#[test]
fn test_f2s_1234_5678() {
    assert_eq!(f2s(1234.5678), "1234.5678");
}

#[test]
fn test_f2s_neg_1234_5678() {
    assert_eq!(f2s(-1234.5678), "-1234.5678");
}

#[test]
fn test_f2s_1_2345678901234567() {
    assert_eq!(f2s(1.2345678901234567), "1.2345678901234567");
}

#[test]
fn test_f2s_1000000000000000000000000_0() {
    assert_eq!(f2s(1000000000000000000000000.0), "1e24");
}

#[test]
fn test_f2s_neg_1000000000000000000000000_0() {
    assert_eq!(f2s(-1000000000000000000000000.0), "-1e24");
}

#[test]
fn test_f2s_nan() {
    assert_eq!(f2s(f64::NAN), "NaN");
}

#[test]
fn test_f2s_infinity() {
    assert_eq!(f2s(f64::INFINITY), "Infinity");
}

#[test]
fn test_f2s_neg_infinity() {
    assert_eq!(f2s(f64::NEG_INFINITY), "-Infinity");
}

#[test]
fn test_f2s_min_positive() {
    assert_eq!(f2s(f64::MIN_POSITIVE), "2.2250738585072014e-308");
}

#[test]
fn test_f2s_neg_min_positive() {
    assert_eq!(f2s(-f64::MIN_POSITIVE), "-2.2250738585072014e-308");
}

#[test]
fn test_f2s_min() {
    assert_eq!(f2s(f64::MIN), "-1.7976931348623157e308");
}

#[test]
fn test_f2s_max() {
    assert_eq!(f2s(f64::MAX), "1.7976931348623157e308");
}
