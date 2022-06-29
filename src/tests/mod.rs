mod f64_serializer;
mod sender;
mod json_tests;
mod mock;

pub type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;